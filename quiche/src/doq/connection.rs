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

//! A synchronous, IO-less DoQ transport protocol object.
//!
//! [`Connection`] mirrors [`crate::h3::Connection`]'s shape and lifecycle: it
//! is driven by repeatedly calling [`Connection::poll`] on top of a
//! `&mut quiche::Connection`, and owns everything needed to turn QUIC stream
//! bytes into framed DNS messages (and back) without parsing DNS content
//! itself. It is shared by the blocking-mio DoQ examples and the async
//! `tokio-quiche` drivers so the per-stream reassembly and the protocol-error
//! matrix in RFC 9250, Section 4.3.3 are implemented exactly once.
//! https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;

use crate::buffers::BufFactory;
use crate::stream::is_bidi;
use crate::stream::is_local;

use super::read_dns_message;
use super::write_dns_message;
use super::DnsWireError;
use super::DoqError;

/// A specialized [`Result`] type for [`Connection`] operations.
pub type Result<T> = std::result::Result<T, Error>;

/// An error while driving a [`Connection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// There is no more work to do right now.
    Done,

    /// A fatal DoQ protocol violation was detected.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    ProtocolError,

    /// DNS message is larger than the 65535 bytes the 2-octet length prefix
    /// can represent.
    MessageTooLarge,

    /// Client specific functions were called on a server-role connection.
    ClientOnly,

    /// There are no more client-initiated bidirectional stream IDs.
    StreamIdExhausted,

    /// Unknown stream was used which `Connection` doesn't know about
    UnknownStream,

    /// Error originated from the transport layer.
    TransportError(crate::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Done => write!(f, "no more work to do"),
            Error::ProtocolError => write!(f, "DoQ protocol error"),
            Error::MessageTooLarge => write!(f, "DNS message is too large"),
            Error::ClientOnly => {
                write!(f, "operation requires a client connection")
            },
            Error::StreamIdExhausted => write!(f, "client stream IDs exhausted"),
            Error::UnknownStream => write!(f, "unknown or already-closed stream"),
            Error::TransportError(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::Done => Error::Done,
            e => Error::TransportError(e),
        }
    }
}

impl From<DnsWireError> for Error {
    fn from(e: DnsWireError) -> Self {
        match e {
            DnsWireError::DnsMessageTooLarge => Error::MessageTooLarge,

            // The remaining variants describe a malformed message rather than
            // an oversized one. The read path inspects them directly, because
            // a truncated message is only an error once the peer sends fin.
            DnsWireError::LenDataIncomplete |
            DnsWireError::DnsMessageIncomplete |
            DnsWireError::IoError(_) => Error::ProtocolError,
        }
    }
}

/// A DoQ transport event, returned by [`Connection::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete DNS query was received on a client-initiated
    /// bidirectional stream (server-role `Connection` only). Emitted once
    /// per stream, after STREAM FIN, so a truncated message or a second
    /// query on the same stream can be rejected as a protocol error instead
    /// of surfaced.
    Query {
        /// The raw DNS message bytes, with the 2-octet length prefix
        /// already stripped. Not parsed or validated in any way — DNS
        /// content is the consumer's responsibility, not the transport's.
        data: Vec<u8>,

        /// Whether these bytes arrived while the QUIC connection was still
        /// in early data (0-RTT). RFC 9250, Section 4.5 restricts which
        /// operations may proceed before handshake confirmation, which
        /// restricts which DNS opcodes may be safely acted on before
        /// the handshake is confirmed; that policy decision belongs to the
        /// consumer, not the transport.
        /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
        is_0rtt: bool,
    },

    /// A complete DNS response message was received on a stream the local,
    /// client-role `Connection` initiated. Emitted once per completed
    /// message: a zone-transfer stream carrying multiple responses emits
    /// this event once per message, followed by a single [`Event::Finished`]
    /// once STREAM FIN arrives.
    Response {
        /// The raw DNS message bytes, with the 2-octet length prefix
        /// already stripped.
        data: Vec<u8>,
    },

    /// The server finished sending responses on this stream.
    Finished,

    /// The peer reset the stream (`RESET_STREAM`). The raw wire error code is
    /// passed through unmapped; a caller that needs the unknown-code mapping
    /// in RFC 9250, Section 4.3.4 must do it itself. A client receiving
    /// `STOP_SENDING` instead gets [`Error::ProtocolError`] because RFC 9250,
    /// Section 4.3.3 makes that fatal.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.4
    Reset(u64),
}

/// Per-stream reassembly state owned by [`Connection`].
#[derive(Default)]
struct StreamState {
    /// Bytes received so far that have not yet been consumed by a complete
    /// framed DNS message.
    recv_buf: Vec<u8>,

    /// Whether STREAM FIN has been observed on the receive side.
    fin_received: bool,

    /// Whether the QUIC connection was in early data when the first byte on
    /// this stream arrived (captures `is_0rtt`, per RFC 9250, Section 4.5).
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
    is_0rtt: bool,

    /// Whether this `Connection` opened the stream itself, as opposed to
    /// discovering it by reading peer-initiated bytes. Only
    /// [`Connection::send_query`] sets this, so it is never true on a server.
    /// [`Connection::flush_query`] and [`Connection::query_pending`] use it to
    /// recognize locally opened query streams.
    is_local: bool,

    /// Whether at least one DNS message event has been surfaced on this
    /// stream: [`Event::Query`] on a server, [`Event::Response`] on a client.
    /// This latches, and is never cleared once set: a zone-transfer stream
    /// sets it on its first response and keeps it set across the rest.
    ///
    /// Server role reads it as a latch. Buffered bytes arriving after the
    /// query was surfaced are a second query on the same stream, a protocol
    /// error under RFC 9250, Section 4.3.3.
    ///
    /// Client role reads it at STREAM FIN. A FIN with no response surfaced is
    /// a protocol error under RFC 9250, Sections 4.2 and 4.3.3.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    event_triggered: bool,

    /// Framed outgoing query or response bytes that QUIC has not yet accepted.
    /// A partial write drains accepted bytes from the front, retaining the
    /// remaining suffix until the stream is writable again.
    send_buf: Vec<u8>,

    /// Whether the queued outgoing message must carry STREAM FIN once all its
    /// bytes are accepted. Client queries always set this; server responses
    /// set it only for their final message.
    send_fin: bool,
}

impl StreamState {
    fn new(is_0rtt: bool) -> Self {
        StreamState {
            is_0rtt,
            ..Default::default()
        }
    }
}

/// A synchronous, IO-less DoQ transport connection.
///
/// `Connection` sits directly on top of a `quiche::Connection` (like
/// [`crate::h3::Connection`] does for HTTP/3): it owns per-stream byte
/// reassembly, DoQ's 2-octet length-prefix framing, stream-role
/// classification, and the parts of the RFC 9250, Section 4.3.3 protocol-error
/// matrix that are detectable from QUIC-stream usage and
/// framing alone. It does **not** parse DNS message content.
/// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
pub struct Connection {
    is_server: bool,
    next_query_stream_id: u64,
    streams: HashMap<u64, StreamState>,
    pending: VecDeque<(u64, Event)>,
}

impl Connection {
    /// Creates a `Connection` on top of the given `quiche::Connection`.
    ///
    /// The role (client vs. server) is taken from `conn`; DoQ has no
    /// control streams or settings exchange, so there is no handshake work
    /// to do on either role before this returns.
    pub fn with_transport<F: BufFactory>(
        conn: &crate::Connection<F>,
    ) -> Result<Connection> {
        Ok(Connection {
            is_server: conn.is_server(),
            next_query_stream_id: 0,
            streams: HashMap::new(),
            pending: VecDeque::new(),
        })
    }

    /// Processes any readable streams and returns the next DoQ event.
    ///
    /// Returns `Err(Error::Done)` when there is currently no event to
    /// report. A returned [`Error::ProtocolError`] has already initiated a
    /// connection close with `DoqError::ProtocolError`.
    pub fn poll<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<(u64, Event)> {
        // A prior protocol error already initiated closure. Do not continue
        // processing application streams while that close is pending.
        if conn.local_error().is_some() {
            return Err(Error::Done);
        }

        if let Some(ev) = self.pending.pop_front() {
            return Ok(ev);
        }

        for stream_id in conn.readable() {
            if !self.is_server && self.streams.contains_key(&stream_id) {
                self.probe_query_stream(conn, stream_id)?;
            }

            match self.process_readable_stream(conn, stream_id) {
                Ok(events) if events.is_empty() => continue,

                Ok(mut events) => {
                    // `events` is never empty here; the first event is
                    // returned immediately and the rest queued so the next
                    // `poll()` call returns them without needing `stream_id`
                    // to be readable again (its bytes have already been
                    // drained from the QUIC layer into our own buffer).
                    let first = events.remove(0);
                    for ev in events {
                        self.pending.push_back((stream_id, ev));
                    }
                    return Ok((stream_id, first));
                },

                Err(Error::ProtocolError) =>
                    return self.fail_protocol_error(conn),

                Err(e) => return Err(e),
            }
        }

        Err(Error::Done)
    }

    /// Opens a client-initiated bidirectional stream and queues one framed DNS
    /// query on it.
    ///
    /// RFC 9250, Section 4.2: "The client MUST send the DNS query over the
    /// selected stream and MUST indicate through the STREAM FIN mechanism
    /// that no further data will be sent on that stream."
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
    ///
    /// Call [`flush_query`](Self::flush_query) for every writable notification
    /// on a tracked query stream, including when
    /// [`query_pending`](Self::query_pending) returns `false`.
    pub fn send_query<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, data: &[u8],
    ) -> Result<u64> {
        if self.is_server {
            return Err(Error::ClientOnly);
        }

        let stream_id = self.next_query_stream_id;

        let mut send_buf = Vec::new();
        write_dns_message(&mut send_buf, data)?;

        self.streams.insert(stream_id, StreamState {
            is_local: true,
            send_buf,
            send_fin: true,
            ..Default::default()
        });

        // Force transport stream creation after registering DoQ state, like
        // H3 request creation. Roll back the registration if it fails.
        match conn.stream_send(stream_id, b"", false) {
            Ok(_) => (),
            Err(crate::Error::StreamStopped(_)) => {
                self.streams.remove(&stream_id);
                return self.fail_protocol_error(conn);
            },
            Err(e) => {
                self.streams.remove(&stream_id);
                return Err(e.into());
            },
        }

        if let Err(e) = self.flush_query(conn, stream_id) {
            // `stream_send` reports accepted bytes only through `Ok(sent)`.
            // Every error path above returns before accepting query bytes;
            // `ProtocolError` additionally attempts to close the connection.
            self.streams.remove(&stream_id);
            return Err(e);
        }

        self.next_query_stream_id = self
            .next_query_stream_id
            .checked_add(4)
            .ok_or(Error::StreamIdExhausted)?;

        Ok(stream_id)
    }

    /// Flushes framed query bytes queued by [`send_query`](Self::send_query).
    ///
    /// This probes the QUIC send side even after the query bytes have drained.
    pub fn flush_query<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<()> {
        if self.is_server {
            return Err(Error::ClientOnly);
        }

        let Some(state) = self.streams.get(&stream_id) else {
            return Err(Error::UnknownStream);
        };

        if !state.is_local {
            return Err(Error::UnknownStream);
        }

        self.probe_query_stream(conn, stream_id)?;

        let Some(state) = self.streams.get_mut(&stream_id) else {
            return Err(Error::UnknownStream);
        };

        if state.send_buf.is_empty() {
            return Ok(());
        }

        match conn.stream_send(stream_id, &state.send_buf, true) {
            // A write can be partial. quiche suppresses the fin unless the
            // whole buffer fits, so the fin lands with the last byte.
            Ok(sent) => {
                state.send_buf.drain(..sent);
                Ok(())
            },

            // The stream had no send capacity, so no byte moved. The queued
            // bytes stay in `send_buf`, where `query_pending` reports them
            // until a later call drains them. Catch this before the arm
            // below, which would surface backpressure as `Error::Done`.
            Err(crate::Error::Done) => Ok(()),

            // RFC 9250, Section 4.3.3 lists "a client receives a STOP_SENDING
            // request" among the fatal error conditions.
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
            // The server role stays per-stream. RFC 9250, Section 4.3.1:
            // "Servers SHOULD NOT continue processing a DNS transaction if
            // they receive a STOP_SENDING."
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
            Err(crate::Error::StreamStopped(_)) => self.fail_protocol_error(conn),

            Err(e) => Err(e.into()),
        }
    }

    /// Returns whether a query still has bytes waiting for QUIC send capacity.
    pub fn query_pending(&self, stream_id: u64) -> bool {
        self.streams
            .get(&stream_id)
            .is_some_and(|s| s.is_local && !s.send_buf.is_empty())
    }

    /// Cancels the outstanding query on `stream_id`.
    ///
    /// RFC 9250, Section 4.3.1: "If a DoQ client wishes to cancel an
    /// outstanding request, it MUST issue a QUIC STOP_SENDING, and it SHOULD
    /// use the error code DOQ_REQUEST_CANCELLED.  It MAY use a more specific
    /// error code registered according to Section 8.4."
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    /// Pass [`DoqError::RequestCancelled`] as `error` unless a more specific
    /// code applies.
    ///
    /// RFC 9250, Section 4.3.1: "The STOP_SENDING request may be sent at any
    /// time but will have no effect if the server response has already been
    /// sent, in which case the client will simply discard the incoming
    /// response.  The corresponding DNS transaction MUST be abandoned."
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    /// The stream state is dropped, so a response already in flight is
    /// discarded instead of being surfaced as an [`Event`].
    ///
    /// Returns `Err(Error::UnknownStream)` if `stream_id` is not a query
    /// stream this `Connection` opened, which includes an already-completed
    /// or already-cancelled one.
    pub fn cancel_query<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64, error: u64,
    ) -> Result<()> {
        if self.is_server {
            return Err(Error::ClientOnly);
        }

        let Some(state) = self.streams.get(&stream_id) else {
            return Err(Error::UnknownStream);
        };

        if !state.is_local {
            return Err(Error::UnknownStream);
        }

        // Queued bytes mean the fin never reached the peer: `flush_query`
        // asks for it with the last byte of the query, and quiche suppresses
        // it on a partial write. Read this before dropping the state.
        let query_unsent = !state.send_buf.is_empty();

        self.streams.remove(&stream_id);

        // Shut the read side down first, so the stream stops being readable
        // even if the send side below reports an error.
        match conn.stream_shutdown(stream_id, crate::Shutdown::Read, error) {
            Ok(()) | Err(crate::Error::Done) => (),
            Err(e) => return Err(e.into()),
        }

        if query_unsent {
            // RFC 9250, Section 4.3.1: "Servers MUST NOT continue processing
            // a DNS transaction if they receive a RESET_STREAM request from
            // the client before the client indicates the STREAM FIN."
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
            // A half-sent query would otherwise leave the server waiting on
            // a fin that never arrives.
            match conn.stream_shutdown(stream_id, crate::Shutdown::Write, error) {
                Ok(()) | Err(crate::Error::Done) => (),
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    /// Queues a DNS response message on `stream_id`, framed with the 2-octet
    /// length prefix, and writes as much of it as the stream's current send
    /// capacity allows.
    ///
    /// `data` is sent verbatim: no padding or other mutation. `fin` marks
    /// this as the last response for the transaction; a zone-transfer stream
    /// sends one or more calls with `fin = false` followed by a final call
    /// with `fin = true`.
    ///
    /// A framed message that doesn't fit in the stream's current capacity is
    /// written partially and the remainder is buffered; the caller should
    /// invoke [`flush_response`](Self::flush_response) once the stream is
    /// reported writable again to send more. Splitting a single framed
    /// message across several QUIC stream writes is transparent to the peer,
    /// which reassembles the length prefix and body from the ordered byte
    /// stream exactly as DNS over TCP does (RFC 9250, Section 4.2; RFC 1035,
    /// Section 4.2.2).
    /// Use [`response_pending`](Self::response_pending) to tell whether queued
    /// bytes remain.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
    /// https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
    ///
    /// Returns `Err(Error::UnknownStream)` if `stream_id` was never seen as a
    /// query stream, has already been completed (its final response was
    /// queued with `fin = true`), or has been reset — a normal race with the
    /// peer, not a bug, to be treated as a no-op. Returns
    /// `Err(Error::MessageTooLarge)` if `data` is larger than the 65535 bytes
    /// the 2-octet length prefix can represent.
    pub fn send_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64, data: &[u8],
        fin: bool,
    ) -> Result<()> {
        let state = match self.streams.get_mut(&stream_id) {
            // A stream whose final response is already queued is treated as
            // completed and no longer accepts responses.
            Some(s) if !s.send_fin => s,
            _ => return Err(Error::UnknownStream),
        };

        // `write_dns_message` checks the 65535-byte limit before writing, so
        // it never leaves a partial frame in `send_buf` on error. The new
        // message is appended after any not-yet-written remainder already
        // queued on this stream.
        write_dns_message(&mut state.send_buf, data)?;
        state.send_fin = fin;

        self.flush_response(conn, stream_id)
    }

    /// Writes as many queued response bytes for `stream_id` as the stream's
    /// current send capacity allows, delivering the STREAM FIN only once the
    /// final queued byte is written.
    ///
    /// Call this when the stream is reported writable to drain a response
    /// that [`send_response`](Self::send_response) couldn't write in one go.
    /// quiche clears the FIN flag on any capacity-truncated write, so passing
    /// the whole remaining buffer on each call delivers the FIN exactly when
    /// the last byte is accepted.
    ///
    /// Returns `Ok(())` whether or not any bytes were written (a stream with
    /// no capacity is a normal, retryable condition); use
    /// [`response_pending`](Self::response_pending) to tell whether data
    /// remains queued. Returns `Err(Error::UnknownStream)` if the stream
    /// isn't tracked, or a [`Error::TransportError`] if the peer stopped the
    /// stream (`STOP_SENDING`) as described by RFC 9250, Section 4.3.1.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    pub fn flush_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<()> {
        let state = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Err(Error::UnknownStream),
        };

        if state.send_buf.is_empty() && !state.send_fin {
            return Ok(());
        }

        match conn.stream_send(stream_id, &state.send_buf, state.send_fin) {
            Ok(sent) => {
                // Drop the bytes quiche accepted; `send_buf` keeps only the
                // not-yet-written remainder.
                state.send_buf.drain(..sent);

                if state.send_buf.is_empty() {
                    // The whole queued buffer has been written. Because
                    // quiche only keeps the FIN flag on a write it accepts in
                    // full, an empty buffer means the FIN (if any) was
                    // delivered on this call and the transaction is complete.
                    if state.send_fin {
                        self.streams.remove(&stream_id);
                    }
                }

                Ok(())
            },

            // No capacity right now; retry when the stream is writable again.
            Err(crate::Error::Done) => Ok(()),

            Err(e) => Err(e.into()),
        }
    }

    /// Returns `true` if `stream_id` has queued response bytes not yet
    /// accepted by the QUIC layer.
    ///
    /// A driver uses this to decide whether to wait for the stream to become
    /// writable before pulling the next response from the application, so the
    /// per-stream buffer stays bounded to roughly one in-flight message.
    pub fn response_pending(&self, stream_id: u64) -> bool {
        self.streams
            .get(&stream_id)
            .is_some_and(|s| !s.send_buf.is_empty())
    }

    /// Abandons the transaction on `stream_id`, sending `RESET_STREAM` with
    /// the given DoQ error code and dropping the stream's state as described
    /// by RFC 9250, Section 4.3.2.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.2
    ///
    /// Returns `Err(Error::UnknownStream)` if `stream_id` was never seen or
    /// has already been completed or reset.
    pub fn reset_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64, error: u64,
    ) -> Result<()> {
        if self.streams.remove(&stream_id).is_none() {
            return Err(Error::UnknownStream);
        }

        match conn.stream_shutdown(stream_id, crate::Shutdown::Write, error) {
            Ok(()) | Err(crate::Error::Done) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Classifies `stream_id` per the DoQ stream-usage rules and, if it's a
    /// stream this `Connection` is responsible for, reads and reassembles
    /// any newly available bytes and returns the resulting events (possibly
    /// more than one, for a client-role multi-response stream; possibly
    /// none, if no complete message is ready yet).
    fn process_readable_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<Vec<Event>> {
        let peer_initiated = !is_local(stream_id, self.is_server);

        if self.is_server {
            // DoQ servers never open streams of their own; a readable
            // locally-initiated stream can't happen in practice and isn't
            // ours to process.
            if !peer_initiated {
                return Ok(Vec::new());
            }

            // Clients MUST send queries on a bidirectional stream per RFC
            // 9250, Section 4.3.3.
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
            if !is_bidi(stream_id) {
                return Err(Error::ProtocolError);
            }
        } else {
            // A client-role `Connection` only ever reads on the
            // bidirectional streams it opened itself to send queries;
            // servers never initiate streams in DoQ per RFC 9250, Sections
            // 3.4 and 4.3.3.
            // https://datatracker.ietf.org/doc/html/rfc9250#section-3.4
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
            if peer_initiated {
                return Err(Error::ProtocolError);
            }

            if !is_bidi(stream_id) {
                return Ok(Vec::new());
            }
        }

        if let Some(error) = self.read_stream(conn, stream_id)? {
            return Ok(vec![Event::Reset(error)]);
        }

        if self.is_server {
            self.drain_server_stream(stream_id)
        } else {
            self.drain_client_stream(stream_id)
        }
    }

    /// Drains all currently-available bytes for `stream_id` from the QUIC
    /// layer into the stream's reassembly buffer.
    ///
    /// Returns `Ok(Some(error))` if the peer reset the stream with the given
    /// wire error code, dropping the stream's state and not draining any
    /// further; the caller should surface this as `Event::Reset(error)`. If
    /// the server's own reset below fails instead, this returns that error.
    /// RFC 9250, Section 4.3.1 requires the following behavior:
    /// "Servers MUST NOT continue processing a DNS transaction if they
    /// receive a RESET_STREAM request from the client before the client
    /// indicates the STREAM FIN. The server MUST issue a RESET_STREAM to
    /// indicate that the transaction is abandoned unless: it has already
    /// done so for another reason or it has already both sent the
    /// response and indicated the STREAM FIN."
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    fn read_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<Option<u64>> {
        let mut buf = [0; 4096];

        loop {
            // Sampled before `stream_recv` so a handshake that completes
            // between data arrival and this call doesn't make 0-RTT data
            // look like it arrived after the handshake was confirmed. Only
            // matters for the first read on a stream (`or_insert_with`
            // below), but that's exactly the read that sets the flag.
            let is_0rtt = conn.is_in_early_data();

            match conn.stream_recv(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    let state = self
                        .streams
                        .entry(stream_id)
                        .or_insert_with(|| StreamState::new(is_0rtt));

                    state.recv_buf.extend_from_slice(&buf[..len]);

                    if self.is_server &&
                        state.recv_buf.len() > super::MAX_DOQ_MESSAGE_LEN
                    {
                        self.streams.remove(&stream_id);
                        return Err(Error::ProtocolError);
                    }

                    if fin {
                        // Once FIN is delivered, quiche may immediately
                        // collect the stream if the local send side is also
                        // already complete (e.g. we already sent our query
                        // with `fin = true`, or our response with
                        // `fin = true`). Calling `stream_recv` again after
                        // that returns `InvalidStreamState`, so stop here
                        // rather than looping once more.
                        state.fin_received = true;
                        break;
                    }

                    if len == 0 {
                        break;
                    }
                },

                Err(crate::Error::Done) => break,

                Err(crate::Error::StreamReset(error)) => {
                    // If the client had already sent FIN, this branch
                    // isn't entered at all: a RESET_STREAM matching the
                    // already-known final size doesn't resurface as
                    // `StreamReset` from `stream_recv` (it keeps
                    // returning `Done`), so there is nothing to check for
                    // that case here.
                    //
                    // We don't check whether this stream was already
                    // reset (e.g. via `reset_stream`) because calling
                    // `stream_shutdown` again below is a no-op.
                    //
                    // We only check whether the server already sent the
                    // response with FIN. `self.streams` no longer has an
                    // entry for it in that case (`flush_response` removes
                    // it once fully drained), so we ask `conn` directly
                    // instead: the RESET_STREAM being handled here always
                    // finishes the receive side, so for this
                    // bidirectional stream `stream_closed` (both
                    // directions finished) is true here exactly when the
                    // send side had already finished too.
                    let fin_sent = conn.stream_closed(stream_id);

                    self.streams.remove(&stream_id);

                    if self.is_server && !fin_sent {
                        match conn.stream_shutdown(
                            stream_id,
                            crate::Shutdown::Write,
                            error,
                        ) {
                            Ok(()) | Err(crate::Error::Done) => (),
                            Err(e) => return Err(e.into()),
                        }
                    }

                    return Ok(Some(error));
                },

                Err(e) => return Err(e.into()),
            }
        }

        Ok(None)
    }

    /// Server-role reassembly: at most one `Event::Query` per stream, held
    /// back until STREAM FIN arrives (see the module docs) so a truncated
    /// message or a second query on the same stream is rejected as a
    /// protocol error instead of surfaced.
    fn drain_server_stream(&mut self, stream_id: u64) -> Result<Vec<Event>> {
        let state = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        if state.event_triggered {
            if !state.recv_buf.is_empty() {
                return Err(Error::ProtocolError);
            }

            return Ok(Vec::new());
        }

        match read_dns_message(&state.recv_buf) {
            Ok((data, consumed)) => {
                // Bytes beyond the first complete message are a second
                // query framed on the same stream per RFC 9250, Section
                // 4.3.3, regardless of whether FIN has arrived yet.
                // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
                if consumed < state.recv_buf.len() {
                    return Err(Error::ProtocolError);
                }

                if !state.fin_received {
                    return Ok(Vec::new());
                }

                let data = data.to_vec();
                let is_0rtt = state.is_0rtt;
                state.event_triggered = true;
                state.recv_buf.clear();

                Ok(vec![Event::Query { data, is_0rtt }])
            },

            Err(DnsWireError::LenDataIncomplete) |
            Err(DnsWireError::DnsMessageIncomplete) => {
                // STREAM FIN before a full message arrived is a truncated
                // message per RFC 9250, Section 4.3.3.
                // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
                if state.fin_received {
                    return Err(Error::ProtocolError);
                }

                Ok(Vec::new())
            },

            // Neither variant is currently reachable from
            // `read_dns_message` on this path, but match them explicitly
            // rather than falling through a catch-all: a future
            // `DnsWireError` variant added there must be treated as a real
            // error here, not silently as "no events yet".
            Err(DnsWireError::DnsMessageTooLarge) |
            Err(DnsWireError::IoError(_)) => Err(Error::ProtocolError),
        }
    }

    /// Client-role reassembly: extracts every currently-complete response
    /// message (a zone-transfer stream may have several buffered at once),
    /// followed by `Event::Finished` once STREAM FIN arrives with no
    /// trailing partial message left in the buffer.
    fn drain_client_stream(&mut self, stream_id: u64) -> Result<Vec<Event>> {
        let state = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let mut events = Vec::new();

        loop {
            match read_dns_message(&state.recv_buf) {
                Ok((data, consumed)) => {
                    events.push(Event::Response {
                        data: data.to_vec(),
                    });
                    state.event_triggered = true;
                    state.recv_buf.drain(..consumed);
                },

                Err(DnsWireError::LenDataIncomplete) |
                Err(DnsWireError::DnsMessageIncomplete) => break,

                Err(_) => break,
            }
        }

        if state.fin_received {
            // RFC 9250, Section 4.2 requires a server response before FIN.
            // Section 4.3.3 makes a FIN before a response a protocol error.
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
            if !state.event_triggered || !state.recv_buf.is_empty() {
                return Err(Error::ProtocolError);
            }

            events.push(Event::Finished);
            self.streams.remove(&stream_id);
        }

        Ok(events)
    }

    /// Checks the send-side status of a locally opened query stream.
    fn probe_query_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<()> {
        match conn.stream_capacity(stream_id) {
            Ok(_) => Ok(()),

            // Fatal for the client role, as in `flush_query`. RFC 9250,
            // Section 4.3.3 lists "a client receives a STOP_SENDING request"
            // among the fatal error conditions.
            // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
            Err(crate::Error::StreamStopped(_)) => self.fail_protocol_error(conn),

            Err(e) => Err(e.into()),
        }
    }

    /// Closes the connection with `DOQ_PROTOCOL_ERROR` and returns
    /// [`Error::ProtocolError`].
    fn fail_protocol_error<T, F: BufFactory>(
        &self, conn: &mut crate::Connection<F>,
    ) -> Result<T> {
        conn.close(
            true,
            DoqError::ProtocolError.to_wire(),
            b"DoQ protocol error",
        )?;
        Err(Error::ProtocolError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::Pipe;
    use crate::ConnectionError;

    fn doq_config() -> crate::Config {
        let mut config = Pipe::default_config("cubic").unwrap();
        config
            .set_application_protos(&[super::super::DOQ_ALPN])
            .unwrap();
        // `Pipe::default_config`'s 15-byte per-stream window is too small for
        // the multi-response (zone-transfer) test below to arrive in a
        // single `Pipe::advance()` call.
        config.set_initial_max_stream_data_bidi_local(10_000);
        config.set_initial_max_stream_data_bidi_remote(10_000);
        config
    }

    fn framed(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_dns_message(&mut out, data).unwrap();
        out
    }

    fn assert_protocol_close(conn: &crate::Connection) {
        assert_eq!(
            conn.local_error(),
            Some(&ConnectionError {
                is_app: true,
                error_code: DoqError::ProtocolError.to_wire(),
                reason: b"DoQ protocol error".to_vec(),
            })
        );
    }

    #[test]
    fn send_query_allocates_and_frames_client_streams() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();

        assert_eq!(client.send_query(&mut pipe.client, b"zero"), Ok(0));
        assert_eq!(client.send_query(&mut pipe.client, b"four"), Ok(4));
        assert_eq!(client.send_query(&mut pipe.client, b"eight"), Ok(8));
        assert!(!client.query_pending(0));
        assert!(!client.query_pending(4));
        assert!(!client.query_pending(8));

        pipe.advance().unwrap();

        for (stream_id, data) in [
            (0, b"zero".as_slice()),
            (4, b"four".as_slice()),
            (8, b"eight".as_slice()),
        ] {
            let mut buf = [0; 16];
            assert_eq!(
                pipe.server.stream_recv(stream_id, &mut buf),
                Ok((data.len() + 2, true))
            );
            assert_eq!(&buf[..data.len() + 2], framed(data));
        }

        pipe.server.stream_send(8, &framed(b"eight"), true).unwrap();
        pipe.server.stream_send(0, &framed(b"zero"), true).unwrap();
        pipe.server.stream_send(4, &framed(b"four"), true).unwrap();
        pipe.advance().unwrap();

        let mut responses = Vec::new();
        for _ in 0..6 {
            match client.poll(&mut pipe.client).unwrap() {
                (stream_id, Event::Response { data }) => {
                    responses.push((stream_id, data));
                },
                (_, Event::Finished) => (),
                (_, event) => panic!("unexpected event: {event:?}"),
            }
        }
        responses.sort_unstable_by_key(|(stream_id, _)| *stream_id);
        assert_eq!(responses, vec![
            (0, b"zero".to_vec()),
            (4, b"four".to_vec()),
            (8, b"eight".to_vec()),
        ]);
    }

    #[test]
    fn send_query_rejects_server_role_and_oversize_without_consuming_id() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        assert_eq!(
            server.send_query(&mut pipe.server, b"query"),
            Err(Error::ClientOnly)
        );

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(
            client.send_query(&mut pipe.client, &[0; 65_536]),
            Err(Error::MessageTooLarge)
        );
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
    }

    #[test]
    fn send_query_partial_write_delivers_fin_with_final_bytes() {
        let mut config = doq_config();
        config.set_initial_max_stream_data_bidi_remote(20);
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let query = vec![0xAB; 200];
        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, &query), Ok(0));
        assert!(client.query_pending(0));

        let mut received = Vec::new();
        let mut fin = false;
        for _ in 0..50 {
            pipe.advance().unwrap();

            let mut buf = [0; 256];
            loop {
                match pipe.server.stream_recv(0, &mut buf) {
                    Ok((len, stream_fin)) => {
                        received.extend_from_slice(&buf[..len]);
                        fin |= stream_fin;
                    },
                    Err(crate::Error::Done) => break,
                    Err(error) => panic!("unexpected receive error: {error:?}"),
                }
            }

            if !client.query_pending(0) {
                break;
            }

            client.flush_query(&mut pipe.client, 0).unwrap();
        }

        pipe.advance().unwrap();
        let mut buf = [0; 256];
        loop {
            match pipe.server.stream_recv(0, &mut buf) {
                Ok((len, stream_fin)) => {
                    received.extend_from_slice(&buf[..len]);
                    fin |= stream_fin;
                },
                Err(crate::Error::Done) => break,
                Err(error) => panic!("unexpected receive error: {error:?}"),
            }
        }

        assert!(!client.query_pending(0));
        assert!(fin);
        assert_eq!(received, framed(&query));
    }

    #[test]
    fn cancel_query_sends_stop_sending() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        pipe.advance().unwrap();

        assert_eq!(
            client.cancel_query(
                &mut pipe.client,
                0,
                DoqError::RequestCancelled.to_wire()
            ),
            Ok(())
        );
        pipe.advance().unwrap();

        // The server observes the cancellation as `StreamStopped` carrying
        // the DoQ error code the client asked for.
        assert_eq!(
            pipe.server.stream_send(0, &framed(b"response"), true),
            Err(crate::Error::StreamStopped(
                DoqError::RequestCancelled.to_wire()
            ))
        );
    }

    #[test]
    fn cancel_query_stops_response_events() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        pipe.advance().unwrap();

        // The response is already on the wire when the cancellation is
        // issued, so it arrives at a stream the client no longer tracks.
        pipe.server
            .stream_send(0, &framed(b"response"), true)
            .unwrap();
        assert_eq!(
            client.cancel_query(
                &mut pipe.client,
                0,
                DoqError::RequestCancelled.to_wire()
            ),
            Ok(())
        );
        pipe.advance().unwrap();

        // `Shutdown::Read` drops the stream from the readable set, so the
        // discarded response never reaches `poll`.
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
        assert!(pipe.client.local_error().is_none());
    }

    #[test]
    fn cancel_query_partial_query_resets_send_side() {
        let mut config = doq_config();
        // Too small for the framed query, so the fin is never sent.
        config.set_initial_max_stream_data_bidi_remote(20);
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, &[b'q'; 64]), Ok(0));
        assert!(client.query_pending(0));
        pipe.advance().unwrap();

        assert_eq!(
            client.cancel_query(
                &mut pipe.client,
                0,
                DoqError::RequestCancelled.to_wire()
            ),
            Ok(())
        );
        pipe.advance().unwrap();

        // The half-sent query is reset, so the server stops waiting for a
        // fin that will never arrive.
        let mut buf = [0; 64];
        assert_eq!(
            pipe.server.stream_recv(0, &mut buf),
            Err(crate::Error::StreamReset(
                DoqError::RequestCancelled.to_wire()
            ))
        );
    }

    #[test]
    fn cancel_query_unknown_stream_is_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        let error = DoqError::RequestCancelled.to_wire();

        assert_eq!(
            client.cancel_query(&mut pipe.client, 0, error),
            Err(Error::UnknownStream)
        );

        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        assert_eq!(client.cancel_query(&mut pipe.client, 0, error), Ok(()));

        // The state is gone, so cancelling twice is not idempotent.
        assert_eq!(
            client.cancel_query(&mut pipe.client, 0, error),
            Err(Error::UnknownStream)
        );
    }

    #[test]
    fn cancel_query_on_server_is_client_only() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        assert_eq!(
            server.cancel_query(
                &mut pipe.server,
                0,
                DoqError::RequestCancelled.to_wire()
            ),
            Err(Error::ClientOnly)
        );
    }

    #[test]
    fn client_stop_sending_closes_with_protocol_error_during_query_send() {
        let mut config = doq_config();
        config.set_initial_max_stream_data_bidi_remote(20);
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, &[0; 200]), Ok(0));
        assert!(client.query_pending(0));

        pipe.advance().unwrap();

        pipe.server
            .stream_shutdown(0, crate::Shutdown::Read, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            client.flush_query(&mut pipe.client, 0),
            Err(Error::ProtocolError)
        );
        assert_protocol_close(&pipe.client);
    }

    #[test]
    fn client_stop_sending_closes_after_query_bytes_drain() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        assert!(!client.query_pending(0));
        pipe.advance().unwrap();

        let mut buf = [0; 65_535];
        let frames = [crate::frame::Frame::StopSending {
            stream_id: 0,
            error_code: 42,
        }];
        let len = crate::test_utils::encode_pkt(
            &mut pipe.server,
            crate::packet::Type::Short,
            &frames,
            &mut buf,
        )
        .unwrap();
        crate::test_utils::recv_send(&mut pipe.client, &mut buf, len).unwrap();

        assert_eq!(
            client.flush_query(&mut pipe.client, 0),
            Err(Error::ProtocolError)
        );
        assert_protocol_close(&pipe.client);
    }

    #[test]
    fn client_stop_sending_wins_over_a_simultaneous_response() {
        let mut config = doq_config();
        config.set_initial_max_stream_data_bidi_remote(20);
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, &[0; 200]), Ok(0));
        pipe.advance().unwrap();

        pipe.server
            .stream_send(0, &framed(b"response"), false)
            .unwrap();
        pipe.server
            .stream_shutdown(0, crate::Shutdown::Read, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Err(Error::ProtocolError));
        assert_protocol_close(&pipe.client);
    }

    #[test]
    fn query_probe_propagates_non_protocol_errors() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        client.streams.insert(0, StreamState {
            is_local: true,
            ..Default::default()
        });

        assert_eq!(
            client.probe_query_stream(&mut pipe.client, 0),
            Err(Error::TransportError(crate::Error::InvalidStreamState(0)))
        );
    }

    #[test]
    fn server_reset_on_opened_query_surfaces_as_event() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        pipe.advance().unwrap();

        pipe.server
            .stream_shutdown(0, crate::Shutdown::Write, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Reset(42))));
    }

    #[test]
    fn send_query_stream_limit_preserves_id() {
        let mut config = doq_config();
        config.set_initial_max_streams_bidi(0);
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(
            client.send_query(&mut pipe.client, b"query"),
            Err(Error::TransportError(crate::Error::StreamLimit))
        );
        assert_eq!(client.next_query_stream_id, 0);
        assert!(!client.query_pending(0));
    }

    #[test]
    fn send_query_works_in_early_data() {
        let mut config = doq_config();
        config.enable_early_data();

        let mut ticket_pipe = Pipe::with_config(&mut config).unwrap();
        ticket_pipe.handshake().unwrap();
        let session = ticket_pipe.client.session().unwrap().to_vec();

        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.client.set_session(&session).unwrap();
        let flight = crate::test_utils::emit_flight(&mut pipe.client).unwrap();
        crate::test_utils::process_flight(&mut pipe.server, flight).unwrap();
        assert!(pipe.client.is_in_early_data());

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"early"), Ok(0));
        assert!(!client.query_pending(0));
    }

    #[test]
    fn server_response_stop_sending_is_a_transport_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        pipe.client.stream_send(0, &framed(b"query"), true).unwrap();
        pipe.advance().unwrap();
        assert!(matches!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query { .. }))
        ));

        pipe.client
            .stream_shutdown(0, crate::Shutdown::Read, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.send_response(&mut pipe.server, 0, b"response", true),
            Err(Error::TransportError(crate::Error::StreamStopped(42)))
        );
        assert_eq!(pipe.server.local_error(), None);
    }

    #[test]
    fn query_split_length_prefix_across_reads() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        let wire = framed(b"hello");

        // First send only the first byte of the 2-octet length prefix.
        pipe.client.stream_send(0, &wire[..1], false).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Err(Error::Done),
            "no complete message yet"
        );

        // Now send the rest, with FIN.
        pipe.client.stream_send(0, &wire[1..], true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"hello".to_vec(),
                is_0rtt: false,
            }))
        );

        assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));
    }

    #[test]
    fn query_truncated_fin_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        let wire = framed(b"hello");

        // Send everything but the last byte, with FIN.
        pipe.client
            .stream_send(0, &wire[..wire.len() - 1], true)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::ProtocolError));
        assert_protocol_close(&pipe.server);
        assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));
    }

    #[test]
    fn query_second_message_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        let mut wire = framed(b"hello");
        wire.extend_from_slice(&framed(b"world"));

        pipe.client.stream_send(0, &wire, true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::ProtocolError));
    }

    #[test]
    fn query_second_message_before_fin_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        let mut wire = framed(b"hello");
        wire.extend_from_slice(&framed(b"world"));

        // No FIN yet -- the second query's bytes are already a protocol
        // error on their own, without needing to wait for FIN.
        pipe.client.stream_send(0, &wire, false).unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::ProtocolError));
    }

    #[test]
    fn client_initiated_unidirectional_stream_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // Stream 2 is client-initiated unidirectional.
        pipe.client.stream_send(2, &framed(b"hello"), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::ProtocolError));
    }

    #[test]
    fn server_initiated_stream_rejected_by_client_role() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();

        // Stream 1 is server-initiated bidirectional.
        pipe.server.stream_send(1, &framed(b"hello"), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Err(Error::ProtocolError));
        assert_protocol_close(&pipe.client);
    }

    #[test]
    fn client_fin_before_response_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        pipe.advance().unwrap();

        pipe.server.stream_send(0, b"", true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Err(Error::ProtocolError));
        assert_protocol_close(&pipe.client);
    }

    #[test]
    fn multi_response_zone_transfer() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();

        assert_eq!(client.send_query(&mut pipe.client, b"axfr query"), Ok(0));
        pipe.advance().unwrap();

        let mut wire = framed(b"answer 1");
        wire.extend_from_slice(&framed(b"answer 2"));
        wire.extend_from_slice(&framed(b"answer 3"));

        pipe.server.stream_send(0, &wire, true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            client.poll(&mut pipe.client),
            Ok((0, Event::Response {
                data: b"answer 1".to_vec()
            }))
        );
        assert_eq!(
            client.poll(&mut pipe.client),
            Ok((0, Event::Response {
                data: b"answer 2".to_vec()
            }))
        );
        assert_eq!(
            client.poll(&mut pipe.client),
            Ok((0, Event::Response {
                data: b"answer 3".to_vec()
            }))
        );
        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Finished)));
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
    }

    #[test]
    fn client_reset_stream_surfaces_as_event() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // Start a query but don't finish it, then abandon it with
        // RESET_STREAM instead of STREAM FIN.
        pipe.client
            .stream_send(0, &framed(b"hello")[..3], false)
            .unwrap();
        pipe.client
            .stream_shutdown(0, crate::Shutdown::Write, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Ok((0, Event::Reset(42))));

        // The stream is no longer tracked: a later attempt to respond to it
        // (e.g. because the consumer's response was already in flight when
        // the reset arrived) is a no-op error, not a panic.
        assert_eq!(
            server.send_response(&mut pipe.server, 0, b"too late", true),
            Err(Error::UnknownStream)
        );

        // Server replies with RESET_STREAM.
        let transport = pipe.server.stats();
        assert_eq!(
            transport.reset_stream_count_remote, 1,
            "server should count the remote reset"
        );
        assert_eq!(
            transport.reset_stream_count_local, 1,
            "server should reset its own send side before query FIN"
        );
    }

    #[test]
    fn server_echoed_reset_reaches_client() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        let mut client = Connection::with_transport(&pipe.client).unwrap();

        // The client abandons a query before sending STREAM FIN.
        pipe.client
            .stream_send(0, &framed(b"hello")[..3], false)
            .unwrap();
        pipe.client
            .stream_shutdown(0, crate::Shutdown::Write, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Ok((0, Event::Reset(42))));

        // Round-trip the server's echoed RESET_STREAM back to the client to
        // confirm it was actually sent on the wire, not just requested
        // locally.
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Reset(42))));
    }

    #[test]
    fn already_reset_stream_is_not_echoed_again() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // Client sends a partial query, no FIN yet.
        pipe.client
            .stream_send(0, &framed(b"hello")[..3], false)
            .unwrap();
        pipe.advance().unwrap();
        assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));

        // The driver abandons the transaction for a reason unrelated to a
        // client-initiated reset (e.g. an internal error), resetting the
        // server's own send side before the client's own RESET_STREAM
        // below is processed.
        server.reset_stream(&mut pipe.server, 0, 7).unwrap();

        // The client independently resets its send side before indicating
        // STREAM FIN, racing with the server's reset above.
        pipe.client
            .stream_shutdown(0, crate::Shutdown::Write, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Ok((0, Event::Reset(42))));

        // RFC 9250, Section 4.3.1 forbids a second RESET_STREAM because the
        // server already reset the stream for another reason.
        // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
        let transport = pipe.server.stats();
        assert_eq!(
            transport.reset_stream_count_local, 1,
            "server should not echo a reset for a stream it already reset"
        );
    }

    #[test]
    fn reset_after_query_fin_is_not_echoed() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // Send a complete framed query with FIN.
        pipe.client.stream_send(0, &framed(b"hello"), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"hello".to_vec(),
                is_0rtt: false,
            }))
        );

        // The client resets the stream after its FIN was already sent.
        // quiche accepts a matching-final-size reset here but does not
        // resurface it as `StreamReset` from `stream_recv` (see
        // `RecvBuf::reset`), so the DoQ layer never sees this as a
        // reset to echo.
        pipe.client
            .stream_shutdown(0, crate::Shutdown::Write, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));

        let transport = pipe.server.stats();
        assert_eq!(
            transport.reset_stream_count_remote, 1,
            "server should still count the remote reset"
        );
        assert_eq!(
            transport.reset_stream_count_local, 0,
            "server should NOT echo a reset that arrives after query FIN"
        );
    }

    #[test]
    fn is_0rtt_captured_correctly() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        pipe.client.stream_send(0, &framed(b"hello"), true).unwrap();
        pipe.advance().unwrap();

        match server.poll(&mut pipe.server) {
            Ok((0, Event::Query { is_0rtt, .. })) => {
                assert!(!is_0rtt, "post-handshake query is not 0-RTT");
            },
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn send_response_unknown_stream_is_a_no_op_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        assert_eq!(
            server.send_response(&mut pipe.server, 0, b"hello", true),
            Err(Error::UnknownStream)
        );
    }

    #[test]
    fn send_response_roundtrip() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        let mut client = Connection::with_transport(&pipe.client).unwrap();

        pipe.client.stream_send(0, &framed(b"hello"), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"hello".to_vec(),
                is_0rtt: false,
            }))
        );

        server
            .send_response(&mut pipe.server, 0, b"world", true)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            client.poll(&mut pipe.client),
            Ok((0, Event::Response {
                data: b"world".to_vec()
            }))
        );
        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Finished)));

        // The transaction is complete; a second response is now unknown.
        assert_eq!(
            server.send_response(&mut pipe.server, 0, b"again", true),
            Err(Error::UnknownStream)
        );
    }

    /// A `Config` whose server-facing send window on stream 0 is small
    /// enough to force `send_response` into a partial write, while leaving
    /// the client's own send path and the connection-level flow control
    /// unconstrained.
    fn small_window_config() -> crate::Config {
        let mut config = Pipe::default_config("cubic").unwrap();
        config
            .set_application_protos(&[super::super::DOQ_ALPN])
            .unwrap();
        config.set_initial_max_data(10_000);
        // Deliberately small: the server's send window on the
        // client-initiated stream 0 is governed by the client's advertised
        // `bidi_local` limit, so this forces `send_response` to only write
        // part of a large response in one go.
        config.set_initial_max_stream_data_bidi_local(20);
        // Large: keeps the client's own query stream unconstrained, so only
        // the server's response path is under test.
        config.set_initial_max_stream_data_bidi_remote(10_000);
        config
    }

    /// Drains `server`'s buffered response on `stream_id` across as many
    /// `flush_response`/`Pipe::advance` round trips as it takes for the
    /// small window in [`small_window_config`] to grow enough, polling
    /// `client` after each round trip and collecting every event it
    /// produces along the way. Bounded so a regression that never drains
    /// fails the test instead of hanging it.
    fn drain_response(
        pipe: &mut Pipe, server: &mut Connection, client: &mut Connection,
        stream_id: u64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        let mut iterations = 0;

        loop {
            pipe.advance().unwrap();

            loop {
                match client.poll(&mut pipe.client) {
                    Ok((_, ev)) => events.push(ev),
                    Err(Error::Done) => break,
                    Err(e) => panic!("unexpected client poll error: {e:?}"),
                }
            }

            pipe.advance().unwrap();

            if !server.response_pending(stream_id) {
                break;
            }

            server.flush_response(&mut pipe.server, stream_id).unwrap();

            iterations += 1;
            assert!(iterations < 50, "drain loop did not terminate");
        }

        events
    }

    #[test]
    fn send_response_partial_write_drains_across_flushes() {
        let mut config = small_window_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        let mut client = Connection::with_transport(&pipe.client).unwrap();

        pipe.client.stream_send(0, &framed(b"query"), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"query".to_vec(),
                is_0rtt: false,
            }))
        );

        let body = vec![0xAB; 200];

        assert_eq!(
            server.send_response(&mut pipe.server, 0, &body, true),
            Ok(())
        );
        assert!(
            server.response_pending(0),
            "200 bytes shouldn't fit in the 20-byte window in one write"
        );

        let events = drain_response(&mut pipe, &mut server, &mut client, 0);

        assert!(!server.response_pending(0));
        assert_eq!(events, vec![
            Event::Response { data: body },
            Event::Finished,
        ]);
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
    }

    #[test]
    fn fin_not_delivered_until_response_fully_drained() {
        let mut config = small_window_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        let mut client = Connection::with_transport(&pipe.client).unwrap();

        pipe.client.stream_send(0, &framed(b"query"), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"query".to_vec(),
                is_0rtt: false,
            }))
        );

        let body = vec![0xAB; 200];

        server
            .send_response(&mut pipe.server, 0, &body, true)
            .unwrap();
        assert!(
            server.response_pending(0),
            "200 bytes shouldn't fit in the 20-byte window in one write"
        );

        // Only the first partial write has reached the client so far, so
        // the framed message is still incomplete: even though quiche
        // cleared the QUIC-level FIN flag on the truncated write, the
        // client must not report `Finished` yet.
        pipe.advance().unwrap();
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));

        let events = drain_response(&mut pipe, &mut server, &mut client, 0);

        assert!(!server.response_pending(0));
        assert_eq!(events, vec![
            Event::Response { data: body },
            Event::Finished,
        ]);
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
    }

    #[test]
    fn send_response_after_partial_final_is_unknown_stream() {
        let mut config = small_window_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        pipe.client.stream_send(0, &framed(b"query"), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"query".to_vec(),
                is_0rtt: false,
            }))
        );

        let body = vec![0xAB; 200];

        server
            .send_response(&mut pipe.server, 0, &body, true)
            .unwrap();
        assert!(
            server.response_pending(0),
            "200 bytes shouldn't fit in the 20-byte window in one write"
        );

        // `send_fin` is already set even though bytes are still buffered,
        // so a second response on the same stream is rejected up front.
        assert_eq!(
            server.send_response(&mut pipe.server, 0, b"too late", true),
            Err(Error::UnknownStream)
        );
    }

    #[test]
    fn multi_response_partial_writes() {
        let mut config = small_window_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        let mut client = Connection::with_transport(&pipe.client).unwrap();

        pipe.client
            .stream_send(0, &framed(b"axfr query"), true)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"axfr query".to_vec(),
                is_0rtt: false,
            }))
        );

        let body1 = vec![0x11; 150];
        let body2 = vec![0x22; 150];
        let body3 = vec![0x33; 150];

        server
            .send_response(&mut pipe.server, 0, &body1, false)
            .unwrap();
        server
            .send_response(&mut pipe.server, 0, &body2, false)
            .unwrap();
        server
            .send_response(&mut pipe.server, 0, &body3, true)
            .unwrap();
        assert!(server.response_pending(0));

        let events = drain_response(&mut pipe, &mut server, &mut client, 0);

        assert!(!server.response_pending(0));
        assert_eq!(events, vec![
            Event::Response { data: body1 },
            Event::Response { data: body2 },
            Event::Response { data: body3 },
            Event::Finished,
        ]);
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
    }
}
