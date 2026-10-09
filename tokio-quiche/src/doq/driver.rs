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
use std::error::Error;
use std::fmt;
use std::future::poll_fn;
use std::future::Future;
use std::io;
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
use crate::metrics::Metrics;
use crate::quic::HandshakeInfo;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

/// Driver failures from [`DoqServerDriver`].
///
/// These errors are boxed at the [`ApplicationOverQuic`] [`QuicResult`]
/// boundary. The controller does not retain the worker's terminal error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DoqConnectionError {
    /// The transport connection has not been established yet.
    ConnectionNotEstablished,

    /// The driver no longer tracks the stream: it was closed, cancelled, or
    /// never opened.
    UnknownStream,
}

impl Error for DoqConnectionError {}

impl fmt::Display for DoqConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::ConnectionNotEstablished =>
                "DoQ transport connection has not been established yet",
            Self::UnknownStream => "unknown stream",
        };

        write!(f, "{s}")
    }
}

// A per-query responder channel with capacity 16 works out to 16 * 64KB =
// 1MB of max buffered response data, matching `H3Driver`'s `STREAM_CAPACITY`
// rationale. In tests it's set to 1 to stress the flush/backpressure paths.
#[cfg(not(any(test, debug_assertions)))]
const RESPONDER_CAPACITY: usize = 16;
#[cfg(any(test, debug_assertions))]
const RESPONDER_CAPACITY: usize = 1;

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

/// Work selected by `wait_for_data` for the driver to process.
///
/// The `work` future returns this value with a reserved event queue slot.
enum ReadyWork {
    /// A result from reading a DoQ event.
    Read(doq::Result<(u64, doq::Event)>),
    /// A stream with buffered response bytes ready to send.
    Flush(u64),
    /// A responder message or channel closure ready to process.
    Response(ResponderReady),
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
    /// Pass the driver to
    /// [`InitialQuicConnection::start`](crate::InitialQuicConnection::start).
    /// Configure the transport before listener creation with
    /// [`QuicSettings`](crate::settings::QuicSettings): advertise
    /// [`DOQ_ALPN`](super::DOQ_ALPN) through `alpn`, set connection and stream
    /// flow-control limits, and choose `max_idle_timeout` and
    /// `enable_early_data`. Supply server TLS credentials through
    /// [`ConnectionParams::new_server`](crate::settings::ConnectionParams::new_server).
    /// These settings belong to the transport; this constructor only chooses
    /// event-channel capacity.
    ///
    /// `event_capacity` is the maximum number of events in the queue at once.
    /// The caller chooses this limit. For example, a capacity of 10 allows
    /// up to 10 queued events. Each event read frees a slot for another event,
    /// so the connection can process more than 10 queries over its lifetime.
    /// All event types share the slots. The driver reserves one slot before
    /// consuming a query, reset, response message, or writable notification.
    ///
    /// When the queue is full, the driver pauses query reads and response
    /// writes until a slot is available. Pending query bytes and responses
    /// stay buffered.
    /// Keep reading events while response tasks run. If event reads stop,
    /// a full queue can prevent response sends from completing.
    /// `HandshakeConfirmed` and `ConnectionClosed` can be dropped when the
    /// queue is full. Connection cleanup runs even if `ConnectionClosed`
    /// cannot be queued.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`io::Error`] with [`io::ErrorKind::InvalidInput`] if
    /// `event_capacity` is zero or exceeds
    /// [`tokio::sync::Semaphore::MAX_PERMITS`].
    pub fn new(event_capacity: usize) -> QuicResult<(Self, DoqController)> {
        if event_capacity == 0 ||
            event_capacity > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DoQ event capacity: {event_capacity}"),
            )
            .into());
        }
        let (event_sender, event_recv) = mpsc::channel(event_capacity);
        let (cmd_sender, cmd_recv) = mpsc::unbounded_channel();

        Ok((
            DoqServerDriver {
                conn: None,
                event_sender,
                cmd_recv,
                streams: HashMap::new(),
                waiting: FuturesUnordered::new(),
                handshake_confirmed: false,
                event_receiver_dropped: false,
            },
            DoqController {
                cmd_sender,
                event_recv: Some(event_recv),
            },
        ))
    }

    /// Returns the underlying transport connection.
    ///
    /// Returns an error if called before `on_conn_established`; in practice
    /// this never happens, since `should_act` gates every other
    /// `ApplicationOverQuic` method that could reach this on
    /// `self.conn.is_some()`.
    fn conn_mut(&mut self) -> QuicResult<&mut doq::Connection> {
        self.conn
            .as_mut()
            .ok_or_else(|| DoqConnectionError::ConnectionNotEstablished.into())
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
        permit: mpsc::OwnedPermit<DoqEvent>,
    ) -> QuicResult<()> {
        match event {
            doq::Event::Query { data, is_0rtt } => {
                let (tx, rx) = mpsc::channel(RESPONDER_CAPACITY);

                permit.send(DoqEvent::Query {
                    data: Bytes::from(data),
                    is_0rtt,
                    responder: DoqResponder::new(stream_id, tx),
                });
                self.check_out_into_waiting(stream_id, rx);
                Ok(())
            },

            // Only resets exposed by the transport reach this path. A reset
            // after the complete query and FIN have been read can be suppressed.
            // Close any tracked receiver before queuing the peer code.
            doq::Event::Reset(code) => {
                self.cancel_responder(stream_id);
                permit.send(DoqEvent::PeerReset { stream_id, code });
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

    /// Reserves event space without waiting. Receiver drop is handled by
    /// `wait_for_data`; either unavailable condition pauses application work.
    fn try_reserve_event(&self) -> Option<mpsc::OwnedPermit<DoqEvent>> {
        self.event_sender.clone().try_reserve_owned().ok()
    }

    /// Stops tracking `stream_id`'s query, if any, so its responder's
    /// `closed()` future resolves for the consumer.
    ///
    /// Used only for resets exposed by the transport. Such a reset can arrive
    /// without a query event, in which case there is no responder to close.
    /// Resets after a complete query and FIN have been read can be suppressed.
    /// A `StreamStopped` write error already owns its receiver and closes it
    /// in `handle_write_error`.
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

    /// Resets `stream_id` with `error` per [RFC 9250, Section 4.3.2], stopping
    /// the driver from sending any more of the response.
    ///
    /// Two errors are treated as benign no-ops rather than fatal:
    /// `UnknownStream` is a stale race with the peer, and
    /// `InvalidStreamState` means quiche already collected the stream,
    /// matching the `H3Driver` write-path precedent
    /// (`http3/driver/mod.rs`'s `InvalidStreamState` handling).
    ///
    /// [RFC 9250, Section 4.3.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.2
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
        permit: mpsc::OwnedPermit<DoqEvent>,
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
                self.send_response(qconn, stream_id, rx, &data, fin, permit),

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
        permit: mpsc::OwnedPermit<DoqEvent>,
    ) -> QuicResult<()> {
        match self.conn_mut()?.send_response(qconn, stream_id, data, fin) {
            Ok(()) => {
                drop(permit);
                self.update_stream_state(stream_id, rx, fin)
            },
            Err(err) =>
                self.handle_write_error(qconn, stream_id, rx, err, permit),
        }
    }

    /// Drains a stream's buffered response remainder via
    /// [`doq::Connection::flush_response`], then routes the result the same
    /// way [`send_response`](Self::send_response) does.
    fn flush_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        rx: mpsc::Receiver<ResponderMessage>, fin: bool,
        permit: mpsc::OwnedPermit<DoqEvent>,
    ) -> QuicResult<()> {
        match self.conn_mut()?.flush_response(qconn, stream_id) {
            Ok(()) => {
                drop(permit);
                self.update_stream_state(stream_id, rx, fin)
            },
            Err(err) =>
                self.handle_write_error(qconn, stream_id, rx, err, permit),
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
            let Some(state) = self.streams.get_mut(&stream_id) else {
                return Err(DoqConnectionError::UnknownStream.into());
            };
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
    /// Peer stops and benign local races close only this query. A reserved
    /// event slot carries the observed stop code.
    fn handle_write_error(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        rx: mpsc::Receiver<ResponderMessage>, error: doq::Error,
        permit: mpsc::OwnedPermit<DoqEvent>,
    ) -> QuicResult<()> {
        match error {
            // A stale race: the stream already completed or was cancelled.
            doq::Error::UnknownStream => {
                drop(rx);
                self.streams.remove(&stream_id);
                Ok(())
            },

            // Stop sending when requested by the peer.
            // See [RFC 9250, Section 4.3.1].
            // Close the query before attempting the cancellation enqueue.
            //
            // [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
            doq::Error::TransportError(quiche::Error::StreamStopped(code)) => {
                drop(rx);
                self.streams.remove(&stream_id);
                permit.send(DoqEvent::PeerStopped { stream_id, code });
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

    /// Closes the connection when the event consumer drops its receiver.
    ///
    /// The flag disables the receiver-drop branch to prevent repeated closes.
    fn handle_event_receiver_drop(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.event_receiver_dropped = true;
        let _ = qconn.close(true, DoqError::NoError.to_wire(), b"");
        Ok(())
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
/// resetting a transaction) go through the [`DoqResponder`] attached to each
/// [`DoqEvent::Query`]. Peer cancellation codes arrive as [`DoqEvent`]s.
///
/// The controller initially owns the event receiver. Use
/// [`take_event_receiver`](Self::take_event_receiver) to move it to another
/// task while retaining connection commands here. Dropping the controller
/// also drops the receiver if it is still held here. Dropping the receiver
/// makes the driver initiate connection close with [`DoqError::NoError`].
/// Keep the receiver alive and drain it while serving the connection.
///
/// After receiver extraction, dropping the controller only closes its command
/// channel. The driver can continue serving the extracted receiver.
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
    ///
    /// The caller owns the returned receiver and must keep draining it while
    /// query tasks run. Dropping it initiates connection close with
    /// [`DoqError::NoError`], even if this controller remains alive.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<DoqEvent>> {
        self.event_recv.take()
    }

    /// Queues a request to close the whole connection. See
    /// [`DoqCommand::CloseConnection`]. This method does not wait for transport
    /// close or report whether the worker accepted the command.
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

    /// Polls the underlying [`doq::Connection`] for events, translating each
    /// into the corresponding [`DoqEvent`].
    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.conn_mut()?;
        loop {
            let Some(permit) = self.try_reserve_event() else {
                return Ok(());
            };
            match self.conn_mut()?.poll(qconn) {
                Ok((stream_id, event)) =>
                    self.process_read_event(stream_id, event, permit)?,

                Err(doq::Error::Done) => break,

                // `Connection::poll()` already initiated the protocol-error
                // close. Keep the worker loop alive so it can send it.
                Err(doq::Error::ProtocolError) => return Ok(()),

                // `poll()` never returns `MessageTooLarge` or
                // `UnknownStream`; those come only from `send_response` or
                // `reset_stream`. Any other `TransportError` is
                // connection-fatal by default, per [RFC 9000, Section 11].
                // transport-level errors are connection-scoped, and only
                // application-level errors can be isolated to one stream.
                //
                // [RFC 9000, Section 11]: https://datatracker.ietf.org/doc/html/rfc9000#section-11
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

        loop {
            let Some(permit) = self.try_reserve_event() else {
                return Ok(());
            };
            let Some(stream_id) = qconn.stream_writable_next() else {
                break;
            };
            let Some(state) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            let Some(rx) = state.rx.take() else { continue };
            let fin = state.pending_fin;

            self.flush_stream(qconn, stream_id, rx, fin, permit)?;
        }

        loop {
            let Some(permit) = self.try_reserve_event() else {
                return Ok(());
            };
            let Some(Some(ready)) = self.waiting.next().now_or_never() else {
                break;
            };
            self.responder_ready(qconn, ready, permit)?;
        }

        Ok(())
    }

    fn on_conn_close<M: Metrics>(
        &mut self, _qconn: &mut QuicheConnection, _metrics: &M,
        _connection_result: &QuicResult<()>,
    ) {
        self.streams.clear();
        self.waiting.clear();
        let _ = self.event_sender.try_send(DoqEvent::ConnectionClosed);
    }

    /// Waits for application work, a command, or event receiver drop.
    ///
    /// Reads and writes share one event slot reservation. Reserve before
    /// consuming a writable notification, responder message, or DoQ event.
    /// Writes need a slot because they can expose a peer cancellation. The
    /// handler sends that event through the permit or releases the unused
    /// permit after a successful write. A full queue leaves queries, response
    /// messages, and buffered writes in their current storage.
    ///
    /// Once a slot is available, check work in this order:
    ///
    /// 1. Flush a parked response after connection establishment.
    /// 2. Take one ready responder message or channel closure.
    /// 3. Poll DoQ for a query, reset, or error.
    ///
    /// Only the flush check requires an established connection. Reads can
    /// process early data before the handshake completes. Checking reads here
    /// resumes buffered queries after capacity returns without another packet.
    /// Normal worker reads run after packet reception.
    ///
    /// Two waits return Pending. With a full queue, the reservation registers
    /// a capacity wake-up. With capacity but no work, release the permit and
    /// return Pending without a self-wake. Responder polling registers a data
    /// wake-up. The outer worker select handles incoming packets and timers.
    /// Do not retain an event slot while idle, even when capacity is one.
    ///
    /// The outer worker can cancel this wait when a packet or timer wins its
    /// select. Cancellation drops a pending reservation without taking work.
    /// Once work is consumed, return its ReadyWork and permit together. The
    /// selected branch dispatches them without another await, so a consumed
    /// event or response is not held across a cancellation point.
    ///
    /// The biased select checks commands, event receiver drop, then work.
    /// Control input does not require event capacity. Receiver drop initiates
    /// connection close once and disables the receiver-drop and work branches.
    /// A closed command channel disables its Some pattern. If all branches
    /// are disabled, remain pending so the outer worker can handle packets and
    /// timers. After dispatch, also handle one command that arrived meanwhile.
    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let sender = self.event_sender.clone();
        let conn = self
            .conn
            .as_mut()
            .ok_or(DoqConnectionError::ConnectionNotEstablished)?;
        let streams = &self.streams;
        let waiting = &mut self.waiting;
        // Create a future that reserves an event slot when polled.
        let mut reservation = std::pin::pin!(sender.clone().reserve_owned());
        // Create a future for the work branch of select.
        // Each poll calls this closure with the task context, cx.
        // The closure reserves an event slot, then selects one operation.
        // It returns Pending, or Ready with the operation and permit.
        let work = poll_fn(|cx| {
            // A full queue returns Pending and registers the task's waker.
            // Freeing a slot wakes this task.
            let result = match reservation.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            };
            // A completed reservation must not be polled again. Install a
            // fresh pinned future for the next poll if this poll finds no work.
            reservation.set(sender.clone().reserve_owned());
            let permit = match result {
                Ok(permit) => permit,
                // The receiver-drop branch handles a closed event channel.
                Err(_) => return Poll::Pending,
            };

            // Flush buffered response bytes first. This write path requires
            // establishment; responder and read checks remain available below.
            if qconn.is_established() {
                while let Some(stream_id) = qconn.stream_writable_next() {
                    if streams
                        .get(&stream_id)
                        .is_some_and(|state| state.rx.is_some())
                    {
                        // Select this stream for flushing. Keep its receiver
                        // in streams; the select handler takes it and flushes
                        // the buffered bytes without another await.
                        return Poll::Ready((
                            permit,
                            ReadyWork::Flush(stream_id),
                        ));
                    }
                }
            }
            // Take a response only after parked writes have been checked.
            // A pending responder poll registers a wake for data or closure.
            if let Poll::Ready(Some(ready)) =
                futures_util::StreamExt::poll_next_unpin(waiting, cx)
            {
                return Poll::Ready((permit, ReadyWork::Response(ready)));
            }
            // Check reads last, including early data before establishment.
            // Capacity recovery must resume buffered queries without a packet.
            match conn.poll(qconn) {
                Err(doq::Error::Done) => {
                    // Release idle capacity. Leave the fresh reservation
                    // unpolled until a data wake or an outer worker wake.
                    drop(permit);
                    Poll::Pending
                },
                result => Poll::Ready((permit, ReadyWork::Read(result))),
            }
        });
        select! {
            biased; // Check commands and receiver drop before consuming work.

            // Receive a connection command from DoqController.
            // handle_command applies it to the QUIC connection.
            // A closed and empty command channel returns None.
            // None fails the Some pattern and disables this branch.
            Some(cmd) = self.cmd_recv.recv() => {
                self.handle_command(qconn, cmd)
            },

            // Handle event receiver drop once.
            _ = self.event_sender.closed(), if !self.event_receiver_dropped => {
                self.handle_event_receiver_drop(qconn)
            },

            // Stop processing queries and responses after event receiver drop.
            // Pass the reserved event slot to the handler.
            // Handle the result immediately. An async wait here could allow
            // cancellation before the event or response is processed.
            (permit, ready) = work, if !self.event_receiver_dropped => {
                match ready {
                    ReadyWork::Read(Ok((stream_id, event))) =>
                        self.process_read_event(stream_id, event, permit),
                    // DoQ already initiated close. Let the worker send it.
                    ReadyWork::Read(Err(doq::Error::ProtocolError)) => Ok(()),
                    // Propagate other read failures to the worker.
                    ReadyWork::Read(Err(error)) => Err(error.into()),
                    // Take the responder receiver for the selected flush.
                    // Use its saved FIN flag with the buffered response bytes.
                    ReadyWork::Flush(stream_id) => {
                        let state = self.streams.get_mut(&stream_id)
                            .ok_or(DoqConnectionError::UnknownStream)?;
                        let rx = state.rx.take()
                            .ok_or(DoqConnectionError::UnknownStream)?;
                        let fin = state.pending_fin;
                        self.flush_stream(qconn, stream_id, rx, fin, permit)
                    },
                    // The handler owns the consumed message and receiver, and
                    // uses the permit if the write reports a peer stop.
                    ReadyWork::Response(ready) =>
                        self.responder_ready(qconn, ready, permit),
                }
            },

            // A closed command channel fails the Some pattern. After receiver
            // drop disables the other branches, keep this future pending so
            // the outer worker select can continue without a select! panic.
            else => std::future::pending().await,
        }?;

        // A command can arrive after select polls its branch.
        // Handle one without waiting after dispatching application work.
        // Limit this check to one command so this call can return.
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

/// A query's response, reset, or channel closure, ready for the driver.
///
/// [`WaitForResponder`] returns this value with ownership of the receiver.
struct ResponderReady {
    /// Identifies the query stream.
    stream_id: u64,
    /// Receiver transferred from the completed wait.
    rx: mpsc::Receiver<ResponderMessage>,
    /// The next message, or `None` when the channel is closed and drained.
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

#[cfg(test)]
mod tests {

    use futures::FutureExt;

    use super::*;
    use crate::doq::test_utils::default_quiche_config;
    use crate::doq::test_utils::DoqDriverTestHelper;
    use crate::doq::test_utils::Pipe;
    use crate::metrics::DefaultMetrics;

    fn fill_events(driver: &DoqServerDriver) {
        while driver.event_sender.capacity() > 0 {
            driver
                .event_sender
                .try_send(DoqEvent::HandshakeConfirmed)
                .unwrap();
        }
    }

    #[tokio::test]
    async fn event_capacity_and_retained_errors() {
        // Check that the queue uses the exact capacity requested by the caller.
        for capacity in [1, 2, 302] {
            let (_, mut controller) = DoqServerDriver::new(capacity).unwrap();
            assert_eq!(
                controller.event_receiver_mut().unwrap().max_capacity(),
                capacity
            );
        }
        let mut helper = DoqDriverTestHelper::new().unwrap();
        // Read before initialization and check that the boxed error preserves
        // the ConnectionNotEstablished enum variant.
        let (mut uninitialized, _) = DoqServerDriver::new(1).unwrap();
        let err = uninitialized
            .process_reads(&mut helper.pipe.server)
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<DoqConnectionError>(),
            Some(&DoqConnectionError::ConnectionNotEstablished)
        );
        let id = helper.peer_send_query(b"q").unwrap();
        helper.advance_and_run_loop().unwrap();
        // Use a response large enough to leave bytes pending after the send.
        helper
            .driver
            .conn_mut()
            .unwrap()
            .send_response(&mut helper.pipe.server, id, &vec![b'x'; 20_000], true)
            .unwrap();
        assert!(helper.driver.conn_mut().unwrap().response_pending(id));
        // Remove driver tracking while the core still has buffered bytes.
        // Updating this stream must return the boxed UnknownStream variant.
        helper.driver.streams.remove(&id);
        let (tx, rx) = mpsc::channel(1);
        let err = helper.driver.update_stream_state(id, rx, true).unwrap_err();
        assert_eq!(
            err.downcast_ref::<DoqConnectionError>(),
            Some(&DoqConnectionError::UnknownStream)
        );
        // The failed update drops the supplied receiver and closes its sender.
        assert!(tx.is_closed());
    }

    #[tokio::test]
    async fn event_capacity_rejects_invalid_capacities() {
        let largest = tokio::sync::Semaphore::MAX_PERMITS;
        let (_, mut controller) = DoqServerDriver::new(largest).unwrap();
        assert_eq!(
            controller.event_receiver_mut().unwrap().max_capacity(),
            largest
        );
        for capacity in [0, largest + 1, usize::MAX] {
            let err = DoqServerDriver::new(capacity).err().unwrap();
            let err = err.downcast_ref::<io::Error>().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                err.to_string(),
                format!("invalid DoQ event capacity: {capacity}")
            );
        }
    }

    #[tokio::test]
    async fn query_and_reset_resume_after_event_capacity_returns() {
        // Test a complete query and a reset after a partial stream write.
        for reset in [false, true] {
            let mut helper = DoqDriverTestHelper::new().unwrap();
            // Keep one query active to check that queue saturation
            // preserves it.
            helper.peer_send_query(b"active").unwrap();
            helper.advance_and_run_loop().unwrap();
            let (_, _, active) = helper.expect_query_event();
            // Fill the queue with test events before sending the next input.
            fill_events(&helper.driver);
            let stream_id = 4;
            if reset {
                helper
                    .pipe
                    .client
                    .stream_send(stream_id, b"partial", false)
                    .unwrap();
                helper
                    .pipe
                    .client
                    .stream_shutdown(stream_id, quiche::Shutdown::Write, 0x1234)
                    .unwrap();
            } else {
                helper.peer_send_query(b"q").unwrap();
            }
            // Deliver the next query or reset while the event queue is full.
            helper.pipe.advance().unwrap();
            helper
                .driver
                .process_reads(&mut helper.pipe.server)
                .unwrap();
            // Reading must pause without dropping the active query or closing
            // the connection. Only the first query is tracked and waiting.
            assert_eq!(helper.driver.streams.len(), 1);
            assert_eq!(helper.driver.waiting.len(), 1);
            assert!(active.closed().now_or_never().is_none());
            assert!(helper.pipe.server.local_error().is_none());
            // Free one slot, then process data already received. No new packet
            // is delivered between freeing capacity and waiting for work.
            helper.try_recv_event().unwrap();
            helper
                .driver
                .wait_for_data(&mut helper.pipe.server)
                .await
                .unwrap();
            let mut delivered = false;
            // Skip the remaining test events and check the delayed query or
            // reset, including its stream ID and original peer error code.
            while let Ok(event) = helper.try_recv_event() {
                match event {
                    DoqEvent::HandshakeConfirmed => (),
                    DoqEvent::PeerReset {
                        stream_id: id,
                        code,
                    } if reset => {
                        assert_eq!(id, stream_id);
                        assert_eq!(code, 0x1234);
                        delivered = true;
                        break;
                    },
                    DoqEvent::Query {
                        data, responder, ..
                    } if !reset => {
                        assert_eq!(data, Bytes::from_static(b"q"));
                        assert_eq!(responder.stream_id(), stream_id);
                        delivered = true;
                        break;
                    },
                    other => panic!("unexpected event: {other:?}"),
                }
            }
            assert!(delivered);
            // Delivering the delayed event must leave the first query open.
            assert!(active.closed().now_or_never().is_none());
        }
    }

    #[tokio::test]
    async fn stop_waits_for_event_capacity_without_closing_connection() {
        let mut helper = DoqDriverTestHelper::new().unwrap();
        let id = helper.peer_send_query(b"q").unwrap();
        helper.advance_and_run_loop().unwrap();
        let (_, _, responder) = helper.expect_query_event();
        // Fill the event queue before the peer sends STOP_SENDING.
        fill_events(&helper.driver);
        helper
            .pipe
            .client
            .stream_shutdown(id, quiche::Shutdown::Read, 0x1234)
            .unwrap();
        helper.pipe.advance().unwrap();
        // Queue response data so a write can detect the peer stop.
        responder
            .send(Bytes::from_static(b"resp"), true)
            .await
            .unwrap();
        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .unwrap();
        // Without space for the stop event, keep the response and query alive.
        assert!(responder.closed().now_or_never().is_none());
        assert_eq!(helper.driver.streams.len(), 1);
        // Free one slot and retry the write without receiving another packet.
        helper.try_recv_event().unwrap();
        helper
            .driver
            .wait_for_data(&mut helper.pipe.server)
            .await
            .unwrap();
        // The stop closes only this query, leaving the connection open.
        assert!(responder.closed().now_or_never().is_some());
        assert!(helper.driver.streams.is_empty());
        assert!(helper.pipe.server.local_error().is_none());
        let mut stopped = false;
        // Skip test events and check the stream ID and raw peer stop code.
        while let Ok(event) = helper.try_recv_event() {
            if let DoqEvent::PeerStopped { stream_id, code } = event {
                assert_eq!(stream_id, id);
                assert_eq!(code, 0x1234);
                stopped = true;
            }
        }
        assert!(stopped);
    }

    #[tokio::test]
    async fn handshake_overflow_is_nonfatal() {
        let mut helper = DoqDriverTestHelper::new().unwrap();
        fill_events(&helper.driver);
        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .unwrap();
        assert!(helper.driver.handshake_confirmed);
        assert!(helper.pipe.server.local_error().is_none());
    }

    /// Creates two active queries with receivers in different driver storage.
    /// The first receiver waits for application data in `driver.waiting`.
    /// The second receiver is stored in `driver.streams` while the core DoQ
    /// connection holds response bytes that cannot yet be sent.
    /// Returns the helper, the waiting responder, and the buffered responder.
    async fn waiting_and_parked_queries(
    ) -> (DoqDriverTestHelper, DoqResponder, DoqResponder) {
        let mut config = default_quiche_config();
        // Use a 20-byte receive window so the 200-byte final response
        // cannot be sent in full. The remaining bytes must stay in the core
        // DoQ buffer.
        config.set_initial_max_stream_data_bidi_local(20);
        let mut helper = DoqDriverTestHelper::with_pipe(
            Pipe::with_config_and_buf(&mut config).unwrap(),
        )
        .unwrap();
        helper.peer_send_query(b"waiting").unwrap();
        helper.peer_send_query(b"parked").unwrap();
        helper.advance_and_run_loop().unwrap();
        let (_, _, waiting) = helper.expect_query_event();
        let (_, _, parked) = helper.expect_query_event();
        // Send nothing through the first responder. Its receiver stays in
        // driver.waiting. Send a final response through the second responder
        // so it fills the receive window and leaves buffered response bytes.
        parked
            .send(Bytes::from(vec![b'x'; 200]), true)
            .await
            .unwrap();
        // Process the response without advancing packets or letting the client
        // read it. The second receiver moves to driver.streams because the
        // response cannot finish until the client grants more stream credit.
        helper.work_loop_iter().unwrap();
        // Check both receiver locations: stored in a stream entry, and waiting
        // for application data. Neither responder may be closed yet.
        assert!(helper
            .driver
            .streams
            .values()
            .any(|state| state.rx.is_some()));
        assert!(!helper.driver.waiting.is_empty());
        assert!(waiting.closed().now_or_never().is_none());
        assert!(parked.closed().now_or_never().is_none());
        (helper, waiting, parked)
    }

    #[tokio::test]
    async fn full_close_event_queue_does_not_delay_query_cleanup() {
        // Keep one query waiting for application data and another with buffered
        // response bytes. Their receivers occupy waiting and streams.
        let (mut helper, waiting, parked) = waiting_and_parked_queries().await;
        // Fill every event slot with test events. Record the queue length so
        // the test can check that ConnectionClosed could not be added.
        fill_events(&helper.driver);
        let len = helper.controller.event_receiver_mut().unwrap().len();
        // Initiate QUIC close, then invoke the driver's close hook directly.
        // This tests query cleanup without exchanging connection-close packets.
        helper.pipe.server.close(true, 0, b"").unwrap();
        helper.driver.on_conn_close(
            &mut helper.pipe.server,
            &DefaultMetrics,
            &Ok(()),
        );
        // No events have been read to free capacity. now_or_never checks that
        // both responder channels are already closed, without awaiting cleanup.
        assert!(waiting.closed().now_or_never().is_some());
        assert!(parked.closed().now_or_never().is_some());
        // Neither receiver location may retain query state after close.
        assert!(helper.driver.streams.is_empty());
        assert!(helper.driver.waiting.is_empty());
        // The queue is still full and its length is unchanged. Query cleanup
        // succeeds even though the ConnectionClosed event could not be queued.
        assert_eq!(helper.controller.event_receiver_mut().unwrap().len(), len);
    }

    #[tokio::test]
    async fn buffered_flush_resumes_after_event_capacity_returns() {
        let (mut helper, waiting, parked) = waiting_and_parked_queries().await;
        let id = parked.stream_id();
        // The response is already buffered. Fill the queue before the peer
        // stops reading, so detecting its stop must wait for event space.
        fill_events(&helper.driver);
        helper
            .pipe
            .client
            .stream_shutdown(id, quiche::Shutdown::Read, 42)
            .unwrap();
        helper.pipe.advance().unwrap();
        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .unwrap();
        // Keep the buffered bytes and responder until a stop event can be sent.
        assert!(parked.closed().now_or_never().is_none());
        assert!(helper.driver.conn_mut().unwrap().response_pending(id));
        // Free one slot so the flush can detect and report the peer stop.
        helper.try_recv_event().unwrap();
        helper
            .driver
            .wait_for_data(&mut helper.pipe.server)
            .await
            .unwrap();
        // Close the stopped query while keeping the unrelated query open.
        assert!(parked.closed().now_or_never().is_some());
        assert!(waiting.closed().now_or_never().is_none());
        let mut delivered = false;
        while let Ok(event) = helper.try_recv_event() {
            if let DoqEvent::PeerStopped { stream_id, code } = event {
                assert_eq!(stream_id, id);
                assert_eq!(code, 42);
                delivered = true;
            }
        }
        assert!(delivered);
        assert!(helper.pipe.server.local_error().is_none());
    }

    #[tokio::test]
    async fn response_bytes_survive_full_event_queue() {
        let mut helper = DoqDriverTestHelper::new().unwrap();
        let id = helper.peer_send_query(b"q").unwrap();
        helper.advance_and_run_loop().unwrap();
        let (_, _, responder) = helper.expect_query_event();
        fill_events(&helper.driver);
        // Submit a final response while event capacity blocks driver writes.
        responder
            .send(Bytes::from_static(b"response"), true)
            .await
            .unwrap();
        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .unwrap();
        assert!(responder.closed().now_or_never().is_none());
        // Free one slot so the driver can take and send the queued response.
        helper.try_recv_event().unwrap();
        helper
            .driver
            .wait_for_data(&mut helper.pipe.server)
            .await
            .unwrap();
        // Deliver the response and check its exact bytes and final
        // stream state.
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer.poll(&mut helper.pipe.client),
            Ok((id, doq::Event::Response {
                data: b"response".to_vec()
            }))
        );
        assert_eq!(
            helper.peer.poll(&mut helper.pipe.client),
            Ok((id, doq::Event::Finished))
        );
        assert!(responder.closed().now_or_never().is_some());
        assert!(helper.pipe.server.local_error().is_none());
    }

    #[tokio::test]
    async fn idle_wait_releases_capacity_and_cancelled_wait_preserves_query() {
        let mut helper = DoqDriverTestHelper::new().unwrap();
        // Use one slot so an idle reservation would block all later events.
        let (mut driver, controller) = DoqServerDriver::new(1).unwrap();
        driver
            .on_conn_established(
                &mut helper.pipe.server,
                &HandshakeInfo::new(std::time::Instant::now(), None),
            )
            .unwrap();
        helper.driver = driver;
        helper.controller = controller;
        // now_or_never polls once and drops a wait that returns Pending.
        // Each idle wait must leave the only event slot available.
        for _ in 0..3 {
            assert!(helper
                .driver
                .wait_for_data(&mut helper.pipe.server)
                .now_or_never()
                .is_none());
            assert_eq!(helper.driver.event_sender.capacity(), 1);
        }
        fill_events(&helper.driver);
        let id = helper.peer_send_query(b"q").unwrap();
        helper.pipe.advance().unwrap();
        // Cancel waits while the query is received but the event queue is full.
        // They must leave the query available for a later wait.
        for _ in 0..3 {
            assert!(helper
                .driver
                .wait_for_data(&mut helper.pipe.server)
                .now_or_never()
                .is_none());
        }
        // Free the slot and check that the query survived the cancelled waits.
        helper.try_recv_event().unwrap();
        helper
            .driver
            .wait_for_data(&mut helper.pipe.server)
            .await
            .unwrap();
        let (_, _, responder) = helper.expect_query_event();
        assert_eq!(responder.stream_id(), id);
        assert!(helper
            .driver
            .wait_for_data(&mut helper.pipe.server)
            .now_or_never()
            .is_none());
        assert_eq!(helper.driver.event_sender.capacity(), 1);
        // Connection commands must remain usable while application work waits
        // for event capacity.
        fill_events(&helper.driver);
        helper
            .controller
            .close_connection(DoqError::NoError, Vec::new());
        helper
            .driver
            .wait_for_data(&mut helper.pipe.server)
            .await
            .unwrap();
        assert!(helper.pipe.server.local_error().is_some());
    }

    #[tokio::test]
    async fn flow_blocked_flush_releases_idle_reservation() {
        let (mut helper, waiting, parked) = waiting_and_parked_queries().await;
        let waiting_id = waiting.stream_id();
        let parked_id = parked.stream_id();
        let capacity = helper.driver.event_sender.capacity();
        // QUIC flow control blocks the buffered response.
        // now_or_never polls each wait once and drops it if it is pending.
        // Repeat without receiving more stream credit.
        for _ in 0..3 {
            assert!(helper
                .driver
                .wait_for_data(&mut helper.pipe.server)
                .now_or_never()
                .is_none());
        }
        // Dropping pending waits must leave event capacity unchanged.
        assert_eq!(helper.driver.event_sender.capacity(), capacity);
        assert!(waiting.closed().now_or_never().is_none());
        assert!(parked.closed().now_or_never().is_none());
        // Complete the short response while the other stream remains blocked.
        waiting.send(Bytes::from_static(b"ok"), true).await.unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            helper.peer.poll(&mut helper.pipe.client),
            Ok((waiting_id, doq::Event::Response {
                data: b"ok".to_vec()
            }))
        );
        assert_eq!(
            helper.peer.poll(&mut helper.pipe.client),
            Ok((waiting_id, doq::Event::Finished))
        );
        assert!(helper
            .driver
            .conn_mut()
            .unwrap()
            .response_pending(parked_id));
        assert!(parked.closed().now_or_never().is_none());
    }

    #[tokio::test]
    async fn receiver_drop_while_full_remains_independent_of_capacity() {
        let (helper, waiting, parked) = waiting_and_parked_queries().await;
        fill_events(&helper.driver);
        let DoqDriverTestHelper {
            mut driver,
            mut pipe,
            controller,
            ..
        } = helper;
        // The controller still owns the event receiver. Dropping it must
        // initiate close without waiting for space in the full event queue.
        drop(controller);
        driver.wait_for_data(&mut pipe.server).await.unwrap();
        assert!(pipe.server.local_error().is_some());
        // Connection cleanup closes both waiting and buffered responders.
        driver.on_conn_close(&mut pipe.server, &DefaultMetrics, &Ok(()));
        assert!(waiting.closed().now_or_never().is_some());
        assert!(parked.closed().now_or_never().is_some());
        // A later wait must remain pending after receiver drop.
        assert!(driver
            .wait_for_data(&mut pipe.server)
            .now_or_never()
            .is_none());
    }

    #[tokio::test]
    async fn early_query_resumes_before_handshake_when_capacity_returns() {
        let mut config = default_quiche_config();
        config.enable_early_data();
        // Complete one connection to obtain a TLS session for 0-RTT resumption.
        let mut ticket_pipe = Pipe::with_config_and_buf(&mut config).unwrap();
        ticket_pipe.handshake().unwrap();
        let session = ticket_pipe.client.session().unwrap().to_vec();
        // Deliver only the resumed client's flight, leaving the new handshake
        // incomplete while the server can receive early application data.
        let mut pipe = Pipe::with_config_and_buf(&mut config).unwrap();
        pipe.client.set_session(&session).unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
        let mut helper =
            DoqDriverTestHelper::with_initialized_pipe(pipe).unwrap();
        // Receive the early query while the event queue blocks query delivery.
        fill_events(&helper.driver);
        helper.peer_send_query(b"early").unwrap();
        helper.advance_client_to_server().unwrap();
        helper
            .driver
            .process_reads(&mut helper.pipe.server)
            .unwrap();
        // Release one slot and resume reads without advancing the handshake.
        helper.try_recv_event().unwrap();
        helper
            .driver
            .wait_for_data(&mut helper.pipe.server)
            .await
            .unwrap();
        assert!(!helper.pipe.server.is_established());
        let mut delivered = false;
        // The delayed query must retain its bytes and early-data flag.
        while let Ok(event) = helper.try_recv_event() {
            if let DoqEvent::Query { data, is_0rtt, .. } = event {
                assert_eq!(data, Bytes::from_static(b"early"));
                assert!(is_0rtt);
                delivered = true;
            }
        }
        assert!(delivered);
    }

    #[tokio::test]
    async fn driver_drop_releases_waiting_and_parked_queries() {
        let (helper, waiting, parked) = waiting_and_parked_queries().await;
        // Dropping the driver releases receivers from both waiting and streams,
        // even without an explicit connection-close callback.
        drop(helper.driver);
        assert!(waiting.closed().now_or_never().is_some());
        assert!(parked.closed().now_or_never().is_some());
    }
}
