// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use bytes::Bytes;
use futures::FutureExt;
use futures_util::stream::FuturesUnordered;
use quiche::doq;
use quiche::doq::DoqError;
use tokio::select;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use super::DoqCommand;
use super::DoqEvent;
use super::DoqResponder;
use super::ResponderMessage;
use crate::buf_factory::BufFactory;
use crate::metrics::Metrics;
use crate::quic::HandshakeInfo;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

// A per-query responder channel with capacity 16 works out to 16 * 64KB =
// 1MB of max buffered response data, matching `H3Driver`'s `STREAM_CAPACITY`
// rationale. In tests it's set to 1 to stress the flush/backpressure paths.
#[cfg(not(any(test, debug_assertions)))]
const RESPONDER_CAPACITY: usize = 16;
#[cfg(any(test, debug_assertions))]
const RESPONDER_CAPACITY: usize = 1;

// Extra `EVENT_CAPACITY` headroom for `DoqEvent::HandshakeConfirmed`, which
// can be pending in the channel at the same time as a full burst of
// `Query` events (reads are processed before writes each iteration, and
// `HandshakeConfirmed` is only sent from `process_writes`). See
// `DoqServerDriver::new` for the rest of the sizing rationale.
const EVENT_CAPACITY_MARGIN: u64 = 1;

/// Per-query tracking, keyed by `stream_id` in
/// [`DoqServerDriver::streams`]: the sole source of truth for whether a
/// query is still live, mirroring `H3Driver::stream_map`/`StreamCtx`.
struct QueryState {
    /// `Some`: the receiver is parked here. It's not currently awaited by
    /// anything; it's looked up by `stream_id` when its stream is reported
    /// writable.
    ///
    /// `None`: the receiver is checked out. Either it's inside a
    /// [`WaitForResponder`] living in [`DoqServerDriver::waiting`], awaiting
    /// the consumer's next message, or it's momentarily held on the stack
    /// while a `send_response`/`flush_response` call is in progress for it.
    rx: Option<mpsc::Receiver<ResponderMessage>>,
    /// Whether the response last written (or about to be written, once
    /// pulled) for this stream carries `fin = true`. Only meaningful while
    /// `rx` is `Some`, i.e. while parked awaiting `Connection`'s buffered
    /// remainder to drain.
    pending_fin: bool,
}

/// A thin [`ApplicationOverQuic`] pump over [`quiche::doq::Connection`],
/// speaking the DoQ transport in the server role.
///
/// See the [module docs](super) for the driver/controller split. All
/// per-stream framing, reassembly, and the protocol-error matrix live in
/// [`quiche::doq::Connection`]; this driver only pumps events out to the
/// paired [`DoqController`] and drains per-query [`DoqResponder`] channels
/// back into the connection.
pub struct DoqServerDriver {
    /// The underlying DoQ transport connection. Initialized in
    /// `ApplicationOverQuic::on_conn_established`.
    conn: Option<doq::Connection>,

    /// Sends [`DoqEvent`]s to the paired [`DoqController`]. Bounded (see
    /// [`DoqServerDriver::new`]) so a stalled consumer can't pin unbounded
    /// memory.
    event_sender: mpsc::Sender<DoqEvent>,
    /// Receives [`DoqCommand`]s from the paired [`DoqController`].
    cmd_recv: mpsc::UnboundedReceiver<DoqCommand>,

    /// Sole source of truth for live query streams; see [`QueryState`].
    streams: HashMap<u64, QueryState>,
    /// Futures awaiting the next message on a query's responder channel.
    /// Only ever holds an entry for a `stream_id` whose `streams[id].rx` is
    /// currently `None` because it was checked out into this set.
    waiting: FuturesUnordered<WaitForResponder>,

    /// The buffer used to interact with the underlying `IoWorker`.
    io_worker_buf: Vec<u8>,

    /// Set once `DoqEvent::HandshakeConfirmed` has been sent, on the first
    /// `process_writes` call. The connection FSM only invokes
    /// `process_writes` once the handshake is actually confirmed, so this
    /// is a reliable signal without inspecting `qconn` directly.
    handshake_confirmed: bool,
    /// Tracks whether the event receiver has been dropped, to avoid
    /// busy-looping on `event_sender.closed()`.
    event_receiver_dropped: bool,
}

impl DoqServerDriver {
    /// Builds a new [`DoqServerDriver`] and its paired [`DoqController`].
    ///
    /// The driver should then be passed to
    /// [`InitialQuicConnection`](crate::quic::InitialQuicConnection)'s
    /// `start` method. Unlike [`H3Driver`](crate::http3::driver::H3Driver),
    /// this takes no general settings: DoQ's other connection-level knob
    /// (`max_idle_timeout`) is an existing
    /// [`QuicSettings`](crate::settings::QuicSettings) field, set before
    /// this driver is created.
    ///
    /// `initial_max_streams_bidi` must be the same value configured on the
    /// [`QuicSettings`](crate::settings::QuicSettings)/[`quiche::Config`]
    /// used for this connection. It sizes the bounded `DoqEvent` channel:
    /// a `DoqEvent::Query` is emitted once per stream, exactly when that
    /// stream's query is fully received, and quiche only credits back a
    /// stream-limit slot once the stream is fully complete in both
    /// directions (`Stream::is_complete()`, `quiche/src/stream/mod.rs`) —
    /// i.e. once the driver has fully sent its response. So the number of
    /// streams that have produced a `Query` event but not yet finished
    /// responding can never exceed `initial_max_streams_bidi`, and sizing
    /// the channel to that (plus `EVENT_CAPACITY_MARGIN` for
    /// `HandshakeConfirmed`) means it only ever fills up because the
    /// consumer has stopped draining it, not because of a legitimate
    /// concurrent-query burst. RFC 9250, Section 5.5.1 recommends clients
    /// send all their queries concurrently.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-5.5.1
    ///
    /// This bound relies on quiche's specific policy of only replenishing
    /// the stream limit as streams complete
    /// (`quiche/src/stream/mod.rs`'s `collect()`). RFC 9000, Section 4.6
    /// leaves that replenishment policy up to the implementation, so this is a
    /// quiche-implementation guarantee, not a protocol one; revisit if
    /// that policy ever changes.
    /// https://datatracker.ietf.org/doc/html/rfc9000#section-4.6
    pub fn new(initial_max_streams_bidi: u64) -> (Self, DoqController) {
        let event_capacity = initial_max_streams_bidi
            .saturating_add(EVENT_CAPACITY_MARGIN)
            as usize;
        let (event_sender, event_recv) = mpsc::channel(event_capacity);
        let (cmd_sender, cmd_recv) = mpsc::unbounded_channel();

        (
            DoqServerDriver {
                conn: None,
                event_sender,
                cmd_recv,
                streams: HashMap::new(),
                waiting: FuturesUnordered::new(),
                io_worker_buf: vec![0u8; BufFactory::MAX_BUF_SIZE],
                handshake_confirmed: false,
                event_receiver_dropped: false,
            },
            DoqController {
                cmd_sender,
                event_recv: Some(event_recv),
            },
        )
    }

    /// Returns the underlying transport connection.
    ///
    /// Returns an error if called before `on_conn_established`; in practice
    /// this never happens, since `should_act` gates every other
    /// `ApplicationOverQuic` method that could reach this on
    /// `self.conn.is_some()`.
    fn conn_mut(&mut self) -> QuicResult<&mut doq::Connection> {
        self.conn.as_mut().ok_or_else(|| {
            "DoqServerDriver's transport connection has not been \
             established yet"
                .into()
        })
    }

    /// Checks `rx` out into a fresh [`WaitForResponder`] in `self.waiting`,
    /// to await the consumer's next message on it.
    ///
    /// Ensures `stream_id` has a `streams` entry marked as checked out
    /// (`rx: None`), creating one if this is the query's first message.
    fn check_out_into_waiting(
        &mut self, stream_id: u64, rx: mpsc::Receiver<ResponderMessage>,
    ) {
        let state = self.streams.entry(stream_id).or_insert(QueryState {
            rx: None,
            pending_fin: false,
        });
        state.rx = None;
        state.pending_fin = false;

        self.waiting.push(WaitForResponder::new(stream_id, rx));
    }

    /// Processes a single [`quiche::doq::Event`] returned by
    /// [`doq::Connection::poll`].
    fn process_read_event(
        &mut self, stream_id: u64, event: doq::Event,
    ) -> QuicResult<()> {
        match event {
            doq::Event::Query { data, is_0rtt } => {
                let (tx, rx) = mpsc::channel(RESPONDER_CAPACITY);

                match self.event_sender.try_send(DoqEvent::Query {
                    data: Bytes::from(data),
                    is_0rtt,
                    responder: DoqResponder::new(tx),
                }) {
                    Ok(()) => {
                        self.check_out_into_waiting(stream_id, rx);
                        Ok(())
                    },

                    // The consumer isn't draining events fast enough.
                    // Rather than grow this channel without bound, fail
                    // the connection so a stalled consumer can't pin
                    // unbounded memory.
                    Err(mpsc::error::TrySendError::Full(_)) =>
                        Err("DoQ event channel is full; consumer too slow".into()),

                    // A dropped event receiver is handled by the
                    // `event_sender.closed()` arm in `wait_for_data`,
                    // which closes the connection; this is just the send
                    // that lost the race.
                    Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
                }
            },

            // Handle peer RESET_STREAM as required by RFC 9250, Section 4.3.1.
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
            //
            // Two cases:
            // 1. The client gave up before finishing the query. We never made a
            //    responder for this stream, so there's nothing to clean up.
            // 2. The client finished the query (so we made a responder), but then
            //    still sent RESET_STREAM. This is legal even after STREAM FIN. We
            //    need to clean up that responder now.
            //
            // `cancel_responder` handles both: it's a no-op for case 1,
            // and resolves `DoqResponder::closed()` for case 2.
            doq::Event::Reset(_wire_error) => {
                self.cancel_responder(stream_id);
                Ok(())
            },

            // `Connection`'s server role never emits these; they're
            // client-role-only (see `quiche::doq::Event`'s docs). Guarded
            // here instead of matched away so a future change to that
            // invariant fails loudly instead of silently dropping events.
            doq::Event::Response { .. } | doq::Event::Finished => unreachable!(
                "a server-role quiche::doq::Connection only emits Query \
                     and Reset events"
            ),
        }
    }

    /// Stops tracking `stream_id`'s query, if any, so its responder's
    /// `closed()` future resolves for the consumer.
    ///
    /// Used for peer cancellation (`Event::Reset`) per RFC 9250, Section 4.3.1.
    /// A `StreamStopped` write error is handled inline in
    /// `handle_write_error` instead, since that path already owns `rx` and
    /// doesn't need the `waiting` scan below.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    fn cancel_responder(&mut self, stream_id: u64) {
        let Some(state) = self.streams.get(&stream_id) else {
            return;
        };

        if state.rx.is_some() {
            // Parked: we own the receiver outright here. Removing (and
            // dropping) it closes the channel, resolving the consumer's
            // `DoqResponder::closed()`.
            self.streams.remove(&stream_id);
            return;
        }

        // Checked out into `waiting`: we don't own the receiver right now,
        // so we can't remove the `streams` entry without orphaning the
        // in-flight `WaitForResponder` (`FuturesUnordered` has no keyed
        // removal API). Close the channel instead. `responder_ready`'s
        // `message: None` branch removes the entry once any
        // already-buffered message drains and the channel reports closed.
        // This mirrors `H3Driver::cleanup_stream`'s identical `iter_mut()`
        // plus `chan.close()` pattern, used there for the same reason.
        for pending in self.waiting.iter_mut() {
            if pending.stream_id == stream_id {
                if let Some(rx) = pending.rx.as_mut() {
                    rx.close();
                }
            }
        }
    }

    /// Resets `stream_id` with `error` per RFC 9250, Section 4.3.2, stopping
    /// the driver from sending any more of the response.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.2
    ///
    /// Two errors are treated as benign no-ops rather than fatal:
    /// `UnknownStream` is a stale race with the peer, and
    /// `InvalidStreamState` means quiche already collected the stream,
    /// matching the `H3Driver` write-path precedent
    /// (`http3/driver/mod.rs`'s `InvalidStreamState` handling).
    fn reset_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64, error: DoqError,
    ) -> QuicResult<()> {
        match self
            .conn_mut()?
            .reset_stream(qconn, stream_id, error.to_wire())
        {
            Ok(()) | Err(doq::Error::UnknownStream) => Ok(()),
            Err(doq::Error::TransportError(
                quiche::Error::InvalidStreamState(_),
            )) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Handles the next message pulled from a query's [`DoqResponder`]
    /// channel, or its closure.
    fn responder_ready(
        &mut self, qconn: &mut QuicheConnection, ready: ResponderReady,
    ) -> QuicResult<()> {
        let ResponderReady {
            stream_id,
            rx,
            message,
        } = ready;

        let Some(message) = message else {
            // The consumer dropped its `DoqResponder` without a final
            // `send`/`reset` call. `rx` is already gone (channel closed).
            // Drop our tracking too and abandon the transaction rather than
            // leaving the QUIC stream open indefinitely: it would never
            // reach FIN, so its `MAX_STREAMS_BIDI` credit would never be
            // replenished.
            self.streams.remove(&stream_id);
            self.reset_stream(qconn, stream_id, DoqError::InternalError)?;
            return Ok(());
        };

        match message {
            ResponderMessage::Response { data, fin } =>
                self.send_response(qconn, stream_id, rx, &data, fin),

            ResponderMessage::Reset { error } => {
                drop(rx);
                self.streams.remove(&stream_id);
                self.reset_stream(qconn, stream_id, error)
            },
        }
    }

    /// Frames and writes one response message via
    /// [`doq::Connection::send_response`], then routes the result to
    /// [`update_stream_state`](Self::update_stream_state) or
    /// [`handle_write_error`](Self::handle_write_error).
    fn send_response(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        rx: mpsc::Receiver<ResponderMessage>, data: &[u8], fin: bool,
    ) -> QuicResult<()> {
        match self.conn_mut()?.send_response(qconn, stream_id, data, fin) {
            Ok(()) => self.update_stream_state(stream_id, rx, fin),
            Err(err) => self.handle_write_error(qconn, stream_id, rx, err),
        }
    }

    /// Drains a stream's buffered response remainder via
    /// [`doq::Connection::flush_response`], then routes the result the same
    /// way [`send_response`](Self::send_response) does.
    fn flush_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        rx: mpsc::Receiver<ResponderMessage>, fin: bool,
    ) -> QuicResult<()> {
        match self.conn_mut()?.flush_response(qconn, stream_id) {
            Ok(()) => self.update_stream_state(stream_id, rx, fin),
            Err(err) => self.handle_write_error(qconn, stream_id, rx, err),
        }
    }

    /// After a successful write (`send_response` or `flush_response`),
    /// decides whether to park the receiver until the buffered remainder
    /// drains, pull the next response, or stop tracking the stream
    /// entirely once `fin` is fully delivered.
    ///
    /// The `streams` entry for `stream_id` is guaranteed to still exist
    /// here. Nothing removes it while `rx` is checked out for processing,
    /// except this very call's `fin`-complete branch below. Every other
    /// removal path either owns `rx` outright, which this call does, or
    /// only closes the channel without removing the entry (see
    /// `cancel_responder`'s checked-out branch).
    fn update_stream_state(
        &mut self, stream_id: u64, rx: mpsc::Receiver<ResponderMessage>,
        fin: bool,
    ) -> QuicResult<()> {
        if self.conn_mut()?.response_pending(stream_id) {
            let state = self.streams.get_mut(&stream_id).expect(
                "a stream just written to must still be tracked in `streams`",
            );
            state.rx = Some(rx);
            state.pending_fin = fin;
        } else if fin {
            // The whole response, including FIN, was written. Dropping `rx`
            // resolves the responder's `closed()` for the consumer.
            self.streams.remove(&stream_id);
        } else {
            // Fully drained, but more responses may follow (zone transfer).
            // Keep polling this query's channel for the next one.
            self.check_out_into_waiting(stream_id, rx);
        }

        Ok(())
    }

    /// Handles an error from a write attempt (`send_response` or
    /// `flush_response`) on `stream_id`.
    ///
    /// The arms below are per-stream: peer-triggered or benign local races,
    /// not treated as connection-fatal.
    fn handle_write_error(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        rx: mpsc::Receiver<ResponderMessage>, error: doq::Error,
    ) -> QuicResult<()> {
        match error {
            // A stale race: the stream already completed or was cancelled.
            doq::Error::UnknownStream => {
                drop(rx);
                self.streams.remove(&stream_id);
                Ok(())
            },

            // Stop sending when requested by the peer.
            // See RFC 9250, Section 4.3.1.
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
            // Per-stream, not fatal.
            doq::Error::TransportError(quiche::Error::StreamStopped(_)) => {
                drop(rx);
                self.streams.remove(&stream_id);
                Ok(())
            },

            // Benign local race: quiche already collected the stream,
            // matching the `H3Driver` write-path precedent
            // (`http3/driver/mod.rs`'s `InvalidStreamState` handling).
            doq::Error::TransportError(quiche::Error::InvalidStreamState(_)) => {
                drop(rx);
                self.streams.remove(&stream_id);
                Ok(())
            },

            // Only `send_response` produces this (a `data` too large to
            // frame); `flush_response` never does, since it only drains
            // already-framed bytes. Not peer-triggered: abandon just this
            // one transaction.
            doq::Error::MessageTooLarge => {
                drop(rx);
                self.streams.remove(&stream_id);
                self.reset_stream(qconn, stream_id, DoqError::InternalError)
            },

            err => Err(err.into()),
        }
    }

    /// Executes a [`DoqCommand`] received from the [`DoqController`].
    fn handle_command(
        &mut self, qconn: &mut QuicheConnection, cmd: DoqCommand,
    ) -> QuicResult<()> {
        match cmd {
            DoqCommand::CloseConnection { error, reason } => {
                let _ = qconn.close(true, error.to_wire(), &reason);
                Ok(())
            },
        }
    }
}

/// The consumer-side handle paired with a [`DoqServerDriver`].
///
/// Receives [`DoqEvent`]s from the driver and sends connection-level
/// [`DoqCommand`]s to it. Per-query operations (sending responses,
/// resetting a transaction, observing peer cancellation) go through the
/// [`DoqResponder`] attached to each [`DoqEvent::Query`] instead.
pub struct DoqController {
    /// Sends [`DoqCommand`]s to the paired [`DoqServerDriver`].
    cmd_sender: mpsc::UnboundedSender<DoqCommand>,
    /// Receives [`DoqEvent`]s from the paired [`DoqServerDriver`]. Can be
    /// extracted and used independently of the [`DoqController`].
    event_recv: Option<mpsc::Receiver<DoqEvent>>,
}

impl DoqController {
    /// Gets a mutable reference to the [`DoqEvent`] receiver for the
    /// paired [`DoqServerDriver`], or `None` if it has already been taken
    /// via [`take_event_receiver`](Self::take_event_receiver).
    pub fn event_receiver_mut(
        &mut self,
    ) -> Option<&mut mpsc::Receiver<DoqEvent>> {
        self.event_recv.as_mut()
    }

    /// Takes the [`DoqEvent`] receiver for the paired [`DoqServerDriver`],
    /// or `None` if it has already been taken.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<DoqEvent>> {
        self.event_recv.take()
    }

    /// Closes the whole connection. See [`DoqCommand::CloseConnection`].
    pub fn close_connection(&self, error: DoqError, reason: Vec<u8>) {
        let _ = self
            .cmd_sender
            .send(DoqCommand::CloseConnection { error, reason });
    }
}

impl ApplicationOverQuic for DoqServerDriver {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.conn = Some(doq::Connection::with_transport(qconn)?);
        Ok(())
    }

    #[inline]
    fn should_act(&self) -> bool {
        self.conn.is_some()
    }

    #[inline]
    fn buffer(&mut self) -> &mut [u8] {
        &mut self.io_worker_buf
    }

    /// Polls the underlying [`doq::Connection`] for events, translating each
    /// into the corresponding [`DoqEvent`] via
    /// [`process_read_event`](Self::process_read_event).
    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        loop {
            match self.conn_mut()?.poll(qconn) {
                Ok((stream_id, event)) =>
                    self.process_read_event(stream_id, event)?,

                Err(doq::Error::Done) => break,

                // Close the connection for these violations.
                // See RFC 9250, Section 4.3.3.
                // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
                // Covers a unidirectional or server-initiated stream, a
                // truncated FIN, or a second query framed on the same
                // stream.
                Err(doq::Error::ProtocolError) => {
                    let _ = qconn.close(
                        true,
                        DoqError::ProtocolError.to_wire(),
                        b"DoQ protocol error",
                    );
                    return Ok(());
                },

                // `poll()` never returns `MessageTooLarge` or
                // `UnknownStream`; those come only from `send_response` or
                // `reset_stream`. Any other `TransportError` is
                // connection-fatal by default, per RFC 9000, Section 11.
                // https://datatracker.ietf.org/doc/html/rfc9000#section-11
                // transport-level errors are connection-scoped, and only
                // application-level errors can be isolated to one stream.
                Err(err) => return Err(err.into()),
            }
        }

        Ok(())
    }

    /// Emits `DoqEvent::HandshakeConfirmed` on the first call. The
    /// connection FSM only invokes `process_writes` once the handshake is
    /// confirmed, so this is a reliable signal. Drains buffered response
    /// remainders on every stream reported writable, then optimistically
    /// pulls any responder messages that are already available.
    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if !self.handshake_confirmed {
            self.handshake_confirmed = true;
            let _ = self.event_sender.try_send(DoqEvent::HandshakeConfirmed);
        }

        while let Some(stream_id) = qconn.stream_writable_next() {
            let Some(state) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            let Some(rx) = state.rx.take() else { continue };
            let fin = state.pending_fin;

            self.flush_stream(qconn, stream_id, rx, fin)?;
        }

        while let Some(Some(ready)) = self.waiting.next().now_or_never() {
            self.responder_ready(qconn, ready)?;
        }

        Ok(())
    }

    fn on_conn_close<M: Metrics>(
        &mut self, _qconn: &mut QuicheConnection, _metrics: &M,
        _connection_result: &QuicResult<()>,
    ) {
        let _ = self.event_sender.try_send(DoqEvent::ConnectionClosed);
    }

    /// Waits for the next responder message, connection-level command, or
    /// controller-drop signal.
    ///
    /// The trailing `else` branch keeps this panic-safe. Two things can
    /// permanently disable a `select!` branch: the controller dropping (so
    /// `cmd_recv.recv()` returns `None` forever), and the event receiver
    /// having already dropped once (so `event_sender.closed()`'s `if`
    /// guard is now false). If both happen, every branch is disabled at
    /// once. Per tokio's documented `select!` semantics, that panics
    /// ("all branches are disabled and there is no provided else branch")
    /// unless an `else` branch is present to block forever instead.
    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        select! {
            biased;
            Some(ready) = self.waiting.next() => self.responder_ready(qconn, ready),
            Some(cmd) = self.cmd_recv.recv() => self.handle_command(qconn, cmd),
            // `closed()`'s output is `()`; `_` discards it since only the
            // fact that it resolved matters. The `if` guard turns this
            // branch off after it fires once, so a later call to
            // `wait_for_data` doesn't try to close the connection again.
            _ = self.event_sender.closed(), if !self.event_receiver_dropped => {
                self.event_receiver_dropped = true;
                // Unlike `H3Driver::close_if_idle`, DoQ has no
                // per-connection idle/dangling-stream tracking to make a
                // conditional close meaningful here. Close unconditionally.
                let _ = qconn.close(true, DoqError::NoError.to_wire(), b"");
                Ok(())
            },
            // `std::future::pending()` never resolves. This branch only
            // runs once every other branch is permanently disabled: the
            // controller dropped (`cmd_recv.recv()` returns `None`
            // forever) and the `if` guard above is already false.
            // Without this, `select!` would panic instead of blocking
            // forever in that case.
            else => std::future::pending().await,
        }?;

        // Make sure the controller isn't starved, but also not prioritized
        // in the biased select. Poll it last, and also perform a
        // `try_recv` each iteration (mirrors `H3Driver::wait_for_data`).
        if let Ok(cmd) = self.cmd_recv.try_recv() {
            self.handle_command(qconn, cmd)?;
        }

        Ok(())
    }
}

/// A [`Future`] that resolves with the next [`ResponderMessage`] pulled from
/// a query's [`DoqResponder`] channel (or `None` once it closes).
struct WaitForResponder {
    stream_id: u64,
    rx: Option<mpsc::Receiver<ResponderMessage>>,
}

impl WaitForResponder {
    fn new(stream_id: u64, rx: mpsc::Receiver<ResponderMessage>) -> Self {
        WaitForResponder {
            stream_id,
            rx: Some(rx),
        }
    }
}

struct ResponderReady {
    stream_id: u64,
    rx: mpsc::Receiver<ResponderMessage>,
    message: Option<ResponderMessage>,
}

impl Future for WaitForResponder {
    type Output = ResponderReady;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        // Expect is OK: `rx` is only `None` after the first `Poll::Ready`,
        // which is fine to panic for a non-fused future (same contract as
        // `WaitForDownstreamData` in `http3/driver/streams.rs`).
        self.rx
            .as_mut()
            .expect("WaitForResponder polled after completion")
            .poll_recv(cx)
            .map(|message| ResponderReady {
                stream_id: self.stream_id,
                rx: self
                    .rx
                    .take()
                    .expect("WaitForResponder polled after completion"),
                message,
            })
    }
}
