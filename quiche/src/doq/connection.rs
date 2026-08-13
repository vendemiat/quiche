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

/// A specialized [`Result`] type for [`Connection`] operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Maximum unconsumed bytes a server-role stream may buffer while waiting
/// for STREAM FIN: a DoQ message plus its 2-octet length prefix, per RFC 9250,
/// Section 4.2. A server-role stream carries at most one query (see
/// [`Connection::drain_server_stream`]), so legitimate traffic never needs
/// more; a peer that keeps streaming bytes past this without completing or
/// finishing its query is exceeding its budget rather than making progress.
/// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
///
/// Not applied to the client role: a zone-transfer stream may legitimately
/// have several complete responses buffered at once before
/// [`Connection::drain_client_stream`] runs.
const MAX_SERVER_RECV_BUF_LEN: usize = 65535 + 2;

/// An error while driving a [`Connection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// There is no more work to do right now.
    Done,

    /// A QUIC-stream-usage or DoQ-framing rule was violated in a way that is
    /// fatal to the connection, per RFC 9250, Section 4.3.3.
    /// These include a client-initiated unidirectional stream, a
    /// server-initiated stream seen by a client-role `Connection`, STREAM
    /// FIN before a full message arrived, or a second message framed on a
    /// stream that already carried one. The caller should close the QUIC
    /// connection with `DoqError::ProtocolError`.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    ProtocolError,

    /// A DNS message passed to [`Connection::send_response`] is larger than
    /// the 65535 bytes the 2-octet length prefix can represent.
    MessageTooLarge,

    /// [`Connection::send_response`] or [`Connection::reset_stream`] was
    /// called for a stream `Connection` doesn't know about: never seen,
    /// already completed, or already reset. Callers should treat this as a
    /// no-op race with the peer, not a bug.
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

    /// STREAM FIN was observed on a stream after all currently-complete
    /// messages have already been surfaced. For a client-role `Connection`
    /// this is the signal that no further [`Event::Response`]s will follow
    /// on that stream.
    Finished,

    /// The peer reset the stream (`RESET_STREAM`) or asked the local side to
    /// stop sending (`STOP_SENDING`). The raw wire error code is passed
    /// through unmapped; a caller that needs the unknown-code mapping in RFC
    /// 9250, Section 4.3.4 must do it itself.
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

    /// Server role only: set once the query on this stream has been
    /// surfaced via `Event::Query`. The entry is kept (rather than removed)
    /// so `send_response`/`reset_stream` can still find the stream, and so
    /// any further bytes on it are recognized as a protocol-error second
    /// query rather than silently ignored.
    query_emitted: bool,

    /// Framed response bytes queued for sending but not yet accepted by the
    /// QUIC send buffer. Holds only the not-yet-written remainder: each
    /// partial write drains the bytes it accepted off the front. A single
    /// framed message may only partially fit in the stream's current
    /// capacity, so its tail lives here until the stream is writable again.
    send_buf: Vec<u8>,

    /// Set once the final response has been queued (via `send_response` with
    /// `fin = true`); the STREAM FIN is delivered once `send_buf` fully
    /// drains. Once set, no further responses are accepted on this stream.
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
            streams: HashMap::new(),
            pending: VecDeque::new(),
        })
    }

    /// Processes any readable streams and returns the next DoQ event.
    ///
    /// Returns `Err(Error::Done)` when there is currently no event to
    /// report. Returns `Err(Error::ProtocolError)` when a fatal protocol
    /// violation per RFC 9250, Section 4.3.3 is detected; the caller should
    /// close the connection with `DoqError::ProtocolError`.
    /// https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    pub fn poll<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<(u64, Event)> {
        if let Some(ev) = self.pending.pop_front() {
            return Ok(ev);
        }

        for stream_id in conn.readable() {
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

                Err(e) => return Err(e),
            }
        }

        Err(Error::Done)
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
        write_dns_message(&mut state.send_buf, data)
            .map_err(|_| Error::MessageTooLarge)?;
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
    /// stream (`STOP_SENDING`) — see
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1>.
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
    /// the given DoQ error code (see
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.2>) and
    /// dropping the stream's state.
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

            // Clients MUST send queries on a bidirectional stream, see
            // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>.
            if !is_bidi(stream_id) {
                return Err(Error::ProtocolError);
            }
        } else {
            // A client-role `Connection` only ever reads on the
            // bidirectional streams it opened itself to send queries;
            // servers never initiate streams in DoQ, see
            // <https://datatracker.ietf.org/doc/html/rfc9250#section-3.4>
            // and
            // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>.
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
    /// Per RFC 9250, Section 4.3.1:
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1>,
    /// "Servers MUST NOT continue processing a DNS transaction if they
    /// receive a RESET_STREAM request from the client before the client
    /// indicates the STREAM FIN. The server MUST issue a RESET_STREAM to
    /// indicate that the transaction is abandoned unless: it has already
    /// done so for another reason or it has already both sent the
    /// response and indicated the STREAM FIN."
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
                        state.recv_buf.len() > MAX_SERVER_RECV_BUF_LEN
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

        if state.query_emitted {
            if !state.recv_buf.is_empty() {
                return Err(Error::ProtocolError);
            }

            return Ok(Vec::new());
        }

        match read_dns_message(&state.recv_buf) {
            Ok((data, consumed)) => {
                // Bytes beyond the first complete message are a second
                // query framed on the same stream, see
                // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>,
                // regardless of whether FIN has arrived yet.
                if consumed < state.recv_buf.len() {
                    return Err(Error::ProtocolError);
                }

                if !state.fin_received {
                    return Ok(Vec::new());
                }

                let data = data.to_vec();
                let is_0rtt = state.is_0rtt;
                state.query_emitted = true;
                state.recv_buf.clear();

                Ok(vec![Event::Query { data, is_0rtt }])
            },

            Err(DnsWireError::LenDataIncomplete) |
            Err(DnsWireError::DnsMessageIncomplete) => {
                // STREAM FIN before a full message arrived is a truncated
                // message, see
                // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>.
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
                    state.recv_buf.drain(..consumed);
                },

                Err(DnsWireError::LenDataIncomplete) |
                Err(DnsWireError::DnsMessageIncomplete) => break,

                Err(_) => break,
            }
        }

        if state.fin_received {
            // A non-empty leftover here is a partial message that will
            // never be completed, see
            // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>.
            if !state.recv_buf.is_empty() {
                return Err(Error::ProtocolError);
            }

            events.push(Event::Finished);
            self.streams.remove(&stream_id);
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::Pipe;

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
    }

    #[test]
    fn multi_response_zone_transfer() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();

        // The client opens the query stream itself.
        pipe.client
            .stream_send(0, &framed(b"axfr query"), true)
            .unwrap();
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

        // Per RFC 9250, Section 4.3.1:
        // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1>,
        // the server must not issue a second RESET_STREAM: it has already
        // reset the stream for another reason.
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
