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
//! matrix in
//! <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3> are
//! implemented exactly once.

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

/// An error while driving a [`Connection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// There is no more work to do right now.
    Done,

    /// A QUIC-stream-usage or DoQ-framing rule was violated in a way that is
    /// fatal to the connection, per
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>: a
    /// client-initiated unidirectional stream, a server-initiated stream
    /// seen by a client-role `Connection`, STREAM FIN before a full message
    /// arrived, or a second message framed on a stream that already carried
    /// one. The caller should close the QUIC connection with
    /// `DoqError::ProtocolError`.
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
        dns_bytes: Vec<u8>,

        /// Whether these bytes arrived while the QUIC connection was still
        /// in early data (0-RTT). See
        /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.5>,
        /// which restricts which DNS opcodes may be safely acted on before
        /// the handshake is confirmed; that policy decision belongs to the
        /// consumer, not the transport.
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
        dns_bytes: Vec<u8>,
    },

    /// STREAM FIN was observed on a stream after all currently-complete
    /// messages have already been surfaced. For a client-role `Connection`
    /// this is the signal that no further [`Event::Response`]s will follow
    /// on that stream.
    Finished,

    /// The peer reset the stream (`RESET_STREAM`) or asked the local side to
    /// stop sending (`STOP_SENDING`). The raw wire error code is passed
    /// through unmapped: there is no `DoqError::from_wire` yet (see the
    /// `quiche::doq` module docs for why), so a caller that needs the
    /// unknown-code mapping in
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.4> must do
    /// it itself for now.
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
    /// this stream arrived (captures `is_0rtt`, see
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.5>).
    is_0rtt: bool,

    /// Server role only: set once the query on this stream has been
    /// surfaced via `Event::Query`. The entry is kept (rather than removed)
    /// so `send_response`/`reset_stream` can still find the stream, and so
    /// any further bytes on it are recognized as a protocol-error second
    /// query rather than silently ignored.
    query_emitted: bool,
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
/// classification, and the parts of the
/// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>
/// protocol-error matrix that are detectable from QUIC-stream usage and
/// framing alone. It does **not** parse DNS message content.
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
    /// violation per
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3> is
    /// detected; the caller should close the connection with
    /// `DoqError::ProtocolError`.
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

    /// Sends a DNS response message on `stream_id`, framed with the 2-octet
    /// length prefix.
    ///
    /// `dns_bytes` is sent verbatim: no padding or other mutation. `fin`
    /// marks this as the last response for the transaction and closes the
    /// stream's send side; a zone-transfer stream sends one or more calls
    /// with `fin = false` followed by a final call with `fin = true`.
    ///
    /// Unlike a byte-stream API, a DoQ message can't be split across
    /// multiple length prefixes, so this call is all-or-nothing with
    /// respect to the current stream capacity: if the stream doesn't
    /// currently have enough send capacity for the whole framed message,
    /// nothing is written and `Err(Error::Done)` is returned. The caller
    /// (the driver) should retry the same call once the stream is reported
    /// writable again.
    ///
    /// Returns `Err(Error::UnknownStream)` if `stream_id` was never seen as
    /// a query stream, or has already been completed or reset — this is a
    /// normal race with the peer, not a bug, and callers should treat it as
    /// a no-op.
    pub fn send_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
        dns_bytes: &[u8], fin: bool,
    ) -> Result<()> {
        if !self.streams.contains_key(&stream_id) {
            return Err(Error::UnknownStream);
        }

        let mut framed = Vec::with_capacity(2 + dns_bytes.len());
        write_dns_message(&mut framed, dns_bytes)
            .map_err(|_| Error::MessageTooLarge)?;

        match conn.stream_capacity(stream_id) {
            Ok(cap) if cap >= framed.len() => {},
            Ok(_) => return Err(Error::Done),
            Err(e) => return Err(e.into()),
        }

        conn.stream_send(stream_id, &framed, fin)?;

        if fin {
            self.streams.remove(&stream_id);
        }

        Ok(())
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
    /// wire error code, dropping the stream's state; the caller should
    /// surface this as `Event::Reset(error)` without draining further.
    fn read_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<Option<u64>> {
        let mut buf = [0; 4096];

        loop {
            match conn.stream_recv(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    let is_0rtt = conn.is_in_early_data();
                    let state = self
                        .streams
                        .entry(stream_id)
                        .or_insert_with(|| StreamState::new(is_0rtt));

                    state.recv_buf.extend_from_slice(&buf[..len]);

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
                    self.streams.remove(&stream_id);
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
            Ok((dns_bytes, consumed)) => {
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

                let dns_bytes = dns_bytes.to_vec();
                let is_0rtt = state.is_0rtt;
                state.query_emitted = true;
                state.recv_buf.clear();

                Ok(vec![Event::Query { dns_bytes, is_0rtt }])
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

            Err(_) => Ok(Vec::new()),
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
                Ok((dns_bytes, consumed)) => {
                    events.push(Event::Response {
                        dns_bytes: dns_bytes.to_vec(),
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

    fn framed(dns_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_dns_message(&mut out, dns_bytes).unwrap();
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
                dns_bytes: b"hello".to_vec(),
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
                dns_bytes: b"answer 1".to_vec()
            }))
        );
        assert_eq!(
            client.poll(&mut pipe.client),
            Ok((0, Event::Response {
                dns_bytes: b"answer 2".to_vec()
            }))
        );
        assert_eq!(
            client.poll(&mut pipe.client),
            Ok((0, Event::Response {
                dns_bytes: b"answer 3".to_vec()
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
                dns_bytes: b"hello".to_vec(),
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
                dns_bytes: b"world".to_vec()
            }))
        );
        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Finished)));

        // The transaction is complete; a second response is now unknown.
        assert_eq!(
            server.send_response(&mut pipe.server, 0, b"again", true),
            Err(Error::UnknownStream)
        );
    }
}
