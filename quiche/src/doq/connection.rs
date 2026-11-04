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
//! [`crate::Connection`], and owns everything needed to turn QUIC
//! stream bytes into framed DNS messages (and back) without parsing DNS content
//! itself.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;

use bytes::BufMut;

use crate::buffers::BufFactory;
use crate::stream::is_bidi;
use crate::stream::is_local;

use super::write_dns_message;
use super::DnsWireError;
use super::DoqError;

/// A specialized [`Result`] type for [`Connection`] operations.
pub type Result<T> = std::result::Result<T, Error>;

/// An error while driving a [`Connection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// There is no more work to do right now.
    Done,

    /// A fatal DoQ protocol violation under [RFC 9250, Section 4.3.3] was
    /// detected.
    ///
    /// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    ProtocolError,

    /// DNS message is larger than the 65535 bytes the 2-octet length prefix
    /// can represent.
    MessageTooLarge,

    /// Client specific functions were called on a server-role connection.
    ClientOnly,

    /// Server specific functions were called on a client-role connection.
    ServerOnly,

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
            Error::ServerOnly => {
                write!(f, "operation requires a server connection")
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
#[non_exhaustive]
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
        /// in early data (0-RTT). [RFC 9250, Section 4.5] restricts which
        /// operations may proceed before handshake confirmation, which
        /// restricts which DNS opcodes may be safely acted on before
        /// the handshake is confirmed; that policy decision belongs to the
        /// consumer, not the transport.
        ///
        /// [RFC 9250, Section 4.5]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
        is_0rtt: bool,
    },

    /// A stream the client-role `Connection` opened has something to read
    /// (client-role `Connection` only). Call
    /// [`recv_response`](Connection::recv_response) for this stream until it
    /// returns `Err(Error::Done)`. `poll` emits this event once per stream
    /// and emits it again only after `recv_response` returned
    /// `Err(Error::Done)` for that stream. `poll` reads no response bytes.
    Data,

    /// The peer reset the stream (`RESET_STREAM`). Server-role `Connection`
    /// only. The client role reports a reset as [`ClientRead::Reset`]. The
    /// raw wire error code is passed through unmapped. A caller that needs
    /// the unknown-code mapping in [RFC 9250, Section 4.3.4] must do it
    /// itself.
    ///
    /// [RFC 9250, Section 4.3.4]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.4
    Reset(u64),
}

/// One item read from a client-role query stream by
/// [`Connection::recv_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientRead {
    /// A complete DNS response message, with the 2-octet length prefix
    /// already stripped. A zone-transfer stream carries several messages.
    /// Each message is one item, followed by a single [`ClientRead::Finished`]
    /// after STREAM FIN.
    Response(Vec<u8>),

    /// The server finished sending responses on this stream. The stream state
    /// is dropped.
    Finished,

    /// The peer reset the stream (`RESET_STREAM`) with this raw wire error
    /// code. The code is not mapped. A caller that needs the unknown-code
    /// mapping in [RFC 9250, Section 4.3.4] must do it itself. The stream
    /// state is dropped. A client that receives `STOP_SENDING` instead gets
    /// [`Error::ProtocolError`], because [RFC 9250, Section 4.3.3] makes that
    /// fatal.
    ///
    /// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    /// [RFC 9250, Section 4.3.4]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.4
    Reset(u64),
}

/// Per-stream reassembly state owned by [`Connection`].
#[derive(Default)]
struct StreamState {
    /// The 2-octet length field of the message in `recv_buf`, as read so far.
    recv_buf_len: [u8; 2],

    /// Number of bytes read into `recv_buf_len`.
    recv_buf_len_read: usize,

    /// Content of the current incoming message read so far. This `Vec` is
    /// returned to the caller when it is complete.
    recv_buf: Vec<u8>,

    /// Whether STREAM FIN has been observed on the receive side.
    fin_received: bool,

    /// Whether the QUIC connection was in early data when the first byte on
    /// this stream arrived (captures `is_0rtt`, per [RFC 9250, Section 4.5]).
    ///
    /// [RFC 9250, Section 4.5]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
    is_0rtt: bool,

    /// Whether this `Connection` opened the stream itself, as opposed to
    /// discovering it by reading peer-initiated bytes. Only
    /// [`Connection::send_query`] sets this, so it is never true on a server.
    /// Client-role methods use it to recognize locally opened query streams.
    is_local: bool,

    /// Whether at least one DNS message has been surfaced on this stream:
    /// [`Event::Query`] on a server, [`ClientRead::Response`] on a client.
    /// This latches, and is never cleared once set: a zone-transfer stream
    /// sets it on its first response and keeps it set across the rest.
    ///
    /// Server role reads it as a latch. Buffered bytes arriving after the
    /// query was surfaced are a second query on the same stream, a protocol
    /// error under [RFC 9250, Section 4.3.3].
    ///
    /// Client role reads it at STREAM FIN. A FIN with no response surfaced is
    /// a protocol error under [RFC 9250, Section 4.2] and
    /// [RFC 9250, Section 4.3.3].
    ///
    /// [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
    /// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    event_triggered: bool,

    /// Client role only. Whether `poll` has emitted [`Event::Data`] for this
    /// stream since `recv_response` last returned `Err(Error::Done)`.
    data_event_triggered: bool,

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

    /// Returns the announced length of the message in `recv_buf`. Returns
    /// `None` until its 2-octet length field is read.
    fn recv_len(&self) -> Option<usize> {
        (self.recv_buf_len_read == 2)
            .then(|| usize::from(u16::from_be_bytes(self.recv_buf_len)))
    }

    /// Returns true if the current incoming message has been read completely.
    fn message_complete(&self) -> bool {
        self.recv_len() == Some(self.recv_buf.len())
    }

    /// Returns true if any byte of the current incoming message has been read.
    fn message_started(&self) -> bool {
        self.recv_buf_len_read > 0
    }

    /// Moves the complete message out, ready for the next message.
    fn take_message(&mut self) -> Vec<u8> {
        self.recv_buf_len_read = 0;
        std::mem::take(&mut self.recv_buf)
    }

    /// Reads the current framed message of `stream_id` into `recv_buf`. It
    /// never reads past the end of the message. It returns when the message
    /// is complete, when STREAM FIN is read, or when the QUIC layer has no
    /// more bytes.
    ///
    /// [RFC 9250, Section 4.2]: "All DNS messages (queries and responses)
    /// sent over DoQ connections MUST be encoded as a 2-octet length field
    /// followed by the message content as specified in [RFC1035]."
    ///
    /// After STREAM FIN, the QUIC layer may collect the stream. Thus this
    /// never calls the QUIC layer again once `fin_received` is set.
    ///
    /// [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
    /// [RFC1035]: https://datatracker.ietf.org/doc/html/rfc1035
    fn read_message<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> crate::Result<()> {
        while !self.message_complete() && !self.fin_received {
            let (read, fin) = match self.recv_len() {
                // Content can arrive over many reads. Ask only for the bytes
                // that are still missing, so the next message stays in the
                // QUIC layer.
                Some(len) => {
                    let missing = len - self.recv_buf.len();
                    let out = (&mut self.recv_buf).limit(missing);
                    stream_read(conn, stream_id, out)?
                },

                // The 2-octet length field can also arrive over two reads.
                None => {
                    let out = &mut self.recv_buf_len[self.recv_buf_len_read..];
                    let (read, fin) = stream_read(conn, stream_id, out)?;

                    self.recv_buf_len_read += read;

                    // The length field is complete. Read the content into a
                    // new buffer of exactly that size.
                    if let Some(len) = self.recv_len() {
                        self.recv_buf = Vec::with_capacity(len);
                    }

                    (read, fin)
                },
            };

            self.fin_received = fin;

            if read == 0 {
                return Ok(());
            }
        }

        Ok(())
    }
}

/// Reads from `stream_id` into `out`. Returns no bytes and no FIN when the
/// QUIC layer has no bytes for now.
fn stream_read<F: BufFactory, B: BufMut>(
    conn: &mut crate::Connection<F>, stream_id: u64, out: B,
) -> crate::Result<(usize, bool)> {
    match conn.stream_recv_buf(stream_id, out) {
        Ok(v) => Ok(v),

        Err(crate::Error::Done) => Ok((0, false)),

        Err(e) => Err(e),
    }
}

/// Checks the send-side status of a locally opened query stream.
fn probe_query_stream<F: BufFactory>(
    conn: &mut crate::Connection<F>, stream_id: u64,
) -> Result<()> {
    match conn.stream_capacity(stream_id) {
        Ok(_) => Ok(()),

        // Fatal for the client role, as in `flush_query`.
        // [RFC 9250, Section 4.3.3] lists "a client receives a STOP_SENDING
        // request" among the fatal error conditions.
        //
        // [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
        Err(crate::Error::StreamStopped(_)) => fail_protocol_error(conn),

        Err(e) => Err(e.into()),
    }
}

/// Closes the connection with `DOQ_PROTOCOL_ERROR` and returns
/// [`Error::ProtocolError`].
fn fail_protocol_error<T, F: BufFactory>(
    conn: &mut crate::Connection<F>,
) -> Result<T> {
    conn.close(
        true,
        DoqError::ProtocolError.to_wire(),
        b"DoQ protocol error",
    )?;
    Err(Error::ProtocolError)
}

/// A synchronous, IO-less DoQ transport connection.
///
/// `Connection` sits directly on top of a `quiche::Connection` (like
/// [`crate::h3::Connection`] does for HTTP/3): it owns per-stream byte
/// reassembly, DoQ's 2-octet length-prefix framing, stream-role
/// classification, and the parts of the [RFC 9250, Section 4.3.3]
/// protocol-error matrix that are detectable from QUIC-stream usage and
/// framing alone. It does **not** parse DNS message content.
///
/// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
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
    ///
    /// The server role reads each readable stream and returns
    /// [`Event::Query`] and [`Event::Reset`]. The client role reads no
    /// response bytes. It returns [`Event::Data`] once per readable query
    /// stream. Call [`recv_response`](Self::recv_response) to read the stream.
    /// Before it reports a client stream, `poll` checks that the peer did not
    /// send `STOP_SENDING`, which is fatal for a client.
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
            if !self.is_server {
                if let Some(ev) = self.poll_client_stream(conn, stream_id)? {
                    return Ok((stream_id, ev));
                }

                continue;
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

                Err(Error::ProtocolError) => return fail_protocol_error(conn),

                Err(e) => return Err(e),
            }
        }

        Err(Error::Done)
    }

    /// Opens a client-initiated bidirectional stream and queues one framed DNS
    /// query on it.
    ///
    /// [RFC 9250, Section 4.2]: "The client MUST send the DNS query over the
    /// selected stream and MUST indicate through the STREAM FIN mechanism
    /// that no further data will be sent on that stream."
    ///
    /// Call [`flush_query`](Self::flush_query) for every writable notification
    /// on a tracked query stream, including when
    /// [`send_pending`](Self::send_pending) returns `false`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClientOnly`] on a server and [`Error::MessageTooLarge`]
    /// if `data` exceeds 65,535 bytes. Stream creation and query flushing
    /// errors are propagated; these failures remove the local stream state.
    /// A peer `STOP_SENDING` attempts a protocol-error close. The close error
    /// is propagated if that attempt fails.
    ///
    /// Returns [`Error::StreamIdExhausted`] if advancing the next stream ID
    /// overflows. This check occurs after queuing the current query.
    ///
    /// [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
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
                return fail_protocol_error(conn);
            },
            Err(e) => {
                self.streams.remove(&stream_id);
                return Err(e.into());
            },
        }

        // The transport stream exists. Its ID is consumed even if the
        // flush below fails, so a later query never reuses it.
        let next_stream_id = stream_id.checked_add(4);

        if let Some(next_stream_id) = next_stream_id {
            self.next_query_stream_id = next_stream_id;
        }

        if let Err(e) = self.flush_query(conn, stream_id) {
            // `stream_send` reports accepted bytes only through `Ok(sent)`.
            // The failed flush leaves the created stream open without a
            // fin. Reset both directions on a best-effort basis, so the peer
            // does not wait for a query that never completes.
            self.streams.remove(&stream_id);

            let code = DoqError::InternalError.to_wire();
            let _ = conn.stream_shutdown(stream_id, crate::Shutdown::Read, code);
            let _ = conn.stream_shutdown(stream_id, crate::Shutdown::Write, code);

            return Err(e);
        }

        next_stream_id.ok_or(Error::StreamIdExhausted)?;

        Ok(stream_id)
    }

    /// Flushes framed query bytes queued by [`send_query`](Self::send_query).
    ///
    /// This probes the QUIC send side even after the query bytes have drained.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClientOnly`] on a server and [`Error::UnknownStream`]
    /// if the stream is not a tracked local query. A peer `STOP_SENDING`
    /// attempts a protocol-error close. Other transport errors, including
    /// errors from that close attempt, are propagated.
    ///
    /// A write with no capacity returns `Ok(())` and retains queued bytes.
    /// An error does not remove local query state.
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

        probe_query_stream(conn, stream_id)?;

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
            // bytes stay in `send_buf`, where `send_pending` reports them
            // until a later call drains them. Catch this before the arm
            // below, which would surface backpressure as `Error::Done`.
            Err(crate::Error::Done) => Ok(()),

            // [RFC 9250, Section 4.3.3] lists "a client receives a STOP_SENDING
            // request" among the fatal error conditions.
            // The server role stays per-stream. [RFC 9250, Section 4.3.1]:
            // "Servers SHOULD NOT continue processing a DNS transaction if
            // they receive a STOP_SENDING."
            //
            // [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
            // [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
            Err(crate::Error::StreamStopped(_)) => fail_protocol_error(conn),

            Err(e) => Err(e.into()),
        }
    }

    /// Cancels the outstanding query on `stream_id`.
    ///
    /// [RFC 9250, Section 4.3.1]: "If a DoQ client wishes to cancel an
    /// outstanding request, it MUST issue a QUIC STOP_SENDING, and it SHOULD
    /// use the error code DOQ_REQUEST_CANCELLED.  It MAY use a more specific
    /// error code registered according to Section 8.4."
    /// Pass [`DoqError::RequestCancelled`] as `error` unless a more specific
    /// code applies.
    ///
    /// [RFC 9250, Section 4.3.1]: "The STOP_SENDING request may be sent at any
    /// time but will have no effect if the server response has already been
    /// sent, in which case the client will simply discard the incoming
    /// response.  The corresponding DNS transaction MUST be abandoned."
    /// The stream state is dropped, so a response already in flight is
    /// discarded instead of being returned by
    /// [`recv_response`](Self::recv_response).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClientOnly`] on a server and [`Error::UnknownStream`]
    /// if the stream is not a tracked local query, including an already
    /// completed or cancelled query.
    ///
    /// Local stream state is removed before transport shutdown. Shutdown
    /// errors are propagated, except [`crate::Error::Done`], which is treated
    /// as success. A shutdown error does not restore local state.
    ///
    /// [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
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
            // [RFC 9250, Section 4.3.1]: "Servers MUST NOT continue processing
            // a DNS transaction if they receive a RESET_STREAM request from
            // the client before the client indicates the STREAM FIN."
            // A half-sent query would otherwise leave the server waiting on
            // a fin that never arrives.
            //
            // [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
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
    /// stream exactly as DNS over TCP does ([RFC 9250, Section 4.2];
    /// [RFC 1035, Section 4.2.2]).
    /// Use [`send_pending`](Self::send_pending) to tell whether queued
    /// bytes remain.
    ///
    /// Returns `Err(Error::ServerOnly)` on a client. Returns
    /// `Err(Error::UnknownStream)` if `stream_id` was never seen as a query
    /// stream, has already been completed (its final response was queued
    /// with `fin = true`), or has been reset — a normal race with the peer,
    /// not a bug, to be treated as a no-op. Returns
    /// `Err(Error::MessageTooLarge)` if `data` is larger than the 65535 bytes
    /// the 2-octet length prefix can represent.
    ///
    /// [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
    /// [RFC 1035, Section 4.2.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
    pub fn send_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64, data: &[u8],
        fin: bool,
    ) -> Result<()> {
        if !self.is_server {
            return Err(Error::ServerOnly);
        }

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
    /// Returns `Err(Error::ServerOnly)` on a client. Returns `Ok(())`
    /// whether or not any bytes were written (a stream with no capacity is
    /// a normal, retryable condition); use
    /// [`send_pending`](Self::send_pending) to tell whether data
    /// remains queued. Returns `Err(Error::UnknownStream)` if the stream
    /// isn't tracked, or a [`Error::TransportError`] if the peer stopped the
    /// stream (`STOP_SENDING`) as described by [RFC 9250, Section 4.3.1].
    ///
    /// [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    pub fn flush_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<()> {
        if !self.is_server {
            return Err(Error::ServerOnly);
        }

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

    /// Returns `true` if `stream_id` has queued bytes not yet accepted by the
    /// QUIC layer. On a client, these are query bytes. On a server, these are
    /// response bytes.
    ///
    /// A driver uses this to decide whether to wait for the stream to become
    /// writable before it produces the next message, so the per-stream buffer
    /// stays bounded to roughly one in-flight message.
    pub fn send_pending(&self, stream_id: u64) -> bool {
        self.streams
            .get(&stream_id)
            .is_some_and(|s| !s.send_buf.is_empty())
    }

    /// Abandons the transaction on `stream_id`, sending `RESET_STREAM` with
    /// the given DoQ error code and dropping the stream's state as described
    /// by [RFC 9250, Section 4.3.2].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownStream`] if the stream is not tracked.
    /// Local stream state is removed before transport shutdown. Shutdown
    /// errors are propagated, except [`crate::Error::Done`], which is treated
    /// as success. A shutdown error does not restore local state.
    ///
    /// On a client, this resets only the query direction. The server can
    /// still send its response, and the client no longer reads it. To
    /// cancel a query, call [`cancel_query`](Self::cancel_query), which
    /// sends `STOP_SENDING` as described by [RFC 9250, Section 4.3.1].
    ///
    /// [RFC 9250, Section 4.3.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.2
    /// [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
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

    /// Client-role readiness check for one readable stream.
    ///
    /// Returns `Ok(Some(Event::Data))` when the stream is a tracked query
    /// stream that has not been reported since the last
    /// `Err(Error::Done)` from [`recv_response`](Self::recv_response).
    /// Returns `Ok(None)` for a stream that needs no event. Reads no bytes.
    fn poll_client_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<Option<Event>> {
        // A client-role `Connection` only ever reads on the bidirectional
        // streams it opened itself to send queries; servers never initiate
        // streams in DoQ per [RFC 9250, Section 3.4] and
        // [RFC 9250, Section 4.3.3].
        //
        // [RFC 9250, Section 3.4]: https://datatracker.ietf.org/doc/html/rfc9250#section-3.4
        // [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
        if !is_local(stream_id, self.is_server) {
            return fail_protocol_error(conn);
        }

        let Some(state) = self.streams.get_mut(&stream_id) else {
            return Ok(None);
        };

        if !state.is_local || !is_bidi(stream_id) {
            return Ok(None);
        }

        // After FIN the transport may have collected the stream, so its send
        // side can no longer be probed.
        if !state.fin_received {
            probe_query_stream(conn, stream_id)?;
        }

        if state.data_event_triggered {
            return Ok(None);
        }

        state.data_event_triggered = true;

        Ok(Some(Event::Data))
    }

    /// Reads at most one item from a query stream the client-role
    /// `Connection` opened.
    ///
    /// Returns [`ClientRead::Response`] for each complete response message,
    /// then [`ClientRead::Finished`] after STREAM FIN, or
    /// [`ClientRead::Reset`] if the peer reset the stream. Returns
    /// `Err(Error::Done)` when no complete item is available yet. That also
    /// re-arms the [`Event::Data`] readiness event for the stream. Call this
    /// until it returns `Err(Error::Done)`, `Finished`, or `Reset`.
    ///
    /// This is the only source of client responses and resets. It reads only
    /// the 2-octet length prefix and then exactly the announced message
    /// length, directly into the buffer that is returned. The per-stream
    /// buffer therefore holds at most 65,535 bytes, and unread bytes stay in
    /// the QUIC layer under flow control. A received STREAM FIN is served
    /// without calling the QUIC layer.
    ///
    /// [RFC 9250, Section 4.2] requires a server response before STREAM FIN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClientOnly`] on a server and [`Error::UnknownStream`]
    /// if the stream is not a tracked local query. A completed, reset, or
    /// cancelled query is not tracked. Returns `Err(Error::Done)` if the
    /// connection has a local close error.
    ///
    /// Returns [`Error::ProtocolError`] after a close with
    /// `DOQ_PROTOCOL_ERROR` in these cases:
    ///
    /// 1. The peer sent `STOP_SENDING` for the query stream ([RFC 9250, Section
    ///    4.3.3]).
    /// 2. STREAM FIN arrived before any response.
    /// 3. STREAM FIN arrived inside a message or after bytes that do not form a
    ///    message.
    ///
    /// Other transport errors are propagated.
    ///
    /// [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
    /// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    pub fn recv_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<ClientRead> {
        if self.is_server {
            return Err(Error::ClientOnly);
        }

        if conn.local_error().is_some() {
            return Err(Error::Done);
        }

        match self.streams.get(&stream_id) {
            Some(state) if state.is_local => (),
            _ => return Err(Error::UnknownStream),
        }

        match self.read_response(conn, stream_id) {
            Err(Error::Done) => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.data_event_triggered = false;
                }

                Err(Error::Done)
            },

            // The STOP_SENDING probe has already closed the connection. Any
            // other protocol error is detected here, and this call closes it.
            Err(Error::ProtocolError) if conn.local_error().is_some() =>
                Err(Error::ProtocolError),

            Err(Error::ProtocolError) => fail_protocol_error(conn),

            Ok(result) => Ok(result),

            Err(e) => Err(e),
        }
    }

    /// Body of [`recv_response`](Self::recv_response). A protocol error
    /// detected here is returned without closing the connection. The caller
    /// closes it.
    fn read_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<ClientRead> {
        // After FIN the transport may have collected the stream, so its send
        // side can no longer be probed.
        match self.streams.get(&stream_id) {
            Some(state) if !state.fin_received =>
                probe_query_stream(conn, stream_id)?,

            Some(_) => (),

            None => return Err(Error::UnknownStream),
        }

        let Some(state) = self.streams.get_mut(&stream_id) else {
            return Err(Error::UnknownStream);
        };

        match state.read_message(conn, stream_id) {
            Ok(()) => (),

            Err(crate::Error::StreamReset(error)) => {
                self.streams.remove(&stream_id);
                return Ok(ClientRead::Reset(error));
            },

            Err(e) => return Err(e.into()),
        }

        if state.message_complete() {
            state.event_triggered = true;
            return Ok(ClientRead::Response(state.take_message()));
        }

        if !state.fin_received {
            return Err(Error::Done);
        }

        // FIN is a protocol error in two cases:
        // 1. No response was surfaced before FIN.
        // 2. FIN arrived inside a message.
        //
        // [RFC 9250, Section 4.2]: "The server MUST send the response(s) on
        // the same stream and MUST indicate, after the last response, through
        // the STREAM FIN mechanism that no further data will be sent on that
        // stream."
        //
        // [RFC 9250, Section 4.3.3] lists these protocol errors: "a client or
        // server receives a STREAM FIN before receiving all the bytes for a
        // message indicated in the 2-octet length field" and "a client
        // receives a STREAM FIN before receiving all the expected responses".
        //
        // [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
        // [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
        if !state.event_triggered || state.message_started() {
            return Err(Error::ProtocolError);
        }

        self.streams.remove(&stream_id);
        Ok(ClientRead::Finished)
    }

    /// Server-role stream classification and reassembly. Reads and
    /// reassembles any newly available bytes on `stream_id` and returns the
    /// resulting events (possibly none, if no complete message is ready yet).
    fn process_readable_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<Vec<Event>> {
        // DoQ servers never open streams of their own; a readable
        // locally-initiated stream can't happen in practice and isn't
        // ours to process.
        if is_local(stream_id, self.is_server) {
            return Ok(Vec::new());
        }

        // Clients MUST send queries on a bidirectional stream per
        // [RFC 9250, Section 4.3.3].
        //
        // [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
        if !is_bidi(stream_id) {
            return Err(Error::ProtocolError);
        }

        if let Some(error) = self.read_stream(conn, stream_id)? {
            return Ok(vec![Event::Reset(error)]);
        }

        self.drain_server_stream(stream_id)
    }

    /// Reads the query on `stream_id` from the QUIC layer into the stream
    /// state, then reads until STREAM FIN. Server role only. It reads the
    /// query directly into its final buffer. After a complete query, it reads
    /// one more byte, so it can tell STREAM FIN from a second query.
    ///
    /// Returns `Ok(Some(error))` if the peer reset the stream with the given
    /// wire error code, dropping the stream's state and not reading any
    /// further; the caller should surface this as `Event::Reset(error)`. If
    /// the server's own reset below fails instead, this returns that error.
    /// [RFC 9250, Section 4.3.1] requires the following behavior:
    /// "Servers MUST NOT continue processing a DNS transaction if they
    /// receive a RESET_STREAM request from the client before the client
    /// indicates the STREAM FIN. The server MUST issue a RESET_STREAM to
    /// indicate that the transaction is abandoned unless: it has already
    /// done so for another reason or it has already both sent the
    /// response and indicated the STREAM FIN."
    ///
    /// Returns [`Error::ProtocolError`] if a byte follows the complete query.
    /// [RFC 9250, Section 4.3.3] makes a second query on the same stream a
    /// protocol error.
    ///
    /// [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    /// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    fn read_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> Result<Option<u64>> {
        let created = !self.streams.contains_key(&stream_id);

        // Sampled before the first `stream_recv` so a handshake that
        // completes between data arrival and this call doesn't make 0-RTT
        // data look like it arrived after the handshake was confirmed. Only
        // the call that creates the stream state uses the sample.
        let is_0rtt = conn.is_in_early_data();

        let state = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| StreamState::new(is_0rtt));

        let mut result = state.read_message(conn, stream_id);

        // A complete query must be followed by STREAM FIN. Read one more byte
        // to tell the two cases apart: 1. STREAM FIN. 2. A byte of a second
        // query.
        if result.is_ok() && state.message_complete() && !state.fin_received {
            let mut probe = [0; 1];

            result = match conn.stream_recv(stream_id, &mut probe) {
                Ok((0, fin)) => {
                    state.fin_received = fin;
                    Ok(())
                },

                Ok(_) => return Err(Error::ProtocolError),

                Err(crate::Error::Done) => Ok(()),

                Err(e) => Err(e),
            };
        }

        match result {
            Ok(()) => {
                // Do not keep state for a stream that gave no bytes.
                if created && !state.message_started() && !state.fin_received {
                    self.streams.remove(&stream_id);
                }

                Ok(None)
            },

            Err(crate::Error::StreamReset(error)) => {
                // A reset after the complete query and FIN have been read
                // can be suppressed by the transport. Such a reset does not
                // reach this branch.
                //
                // We don't check whether this stream was already reset (e.g.
                // via `reset_stream`) because calling `stream_shutdown` again
                // below is a no-op.
                //
                // We only check whether the server already sent the response
                // with FIN. `self.streams` no longer has an entry for it in
                // that case (`flush_response` removes it once fully drained),
                // so we ask `conn` directly instead: the RESET_STREAM being
                // handled here always finishes the receive side, so for this
                // bidirectional stream `stream_closed` (both directions
                // finished) is true here exactly when the send side had
                // already finished too.
                let fin_sent = conn.stream_closed(stream_id);

                self.streams.remove(&stream_id);

                if !fin_sent {
                    match conn.stream_shutdown(
                        stream_id,
                        crate::Shutdown::Write,
                        error,
                    ) {
                        Ok(()) | Err(crate::Error::Done) => (),
                        Err(e) => return Err(e.into()),
                    }
                }

                Ok(Some(error))
            },

            Err(e) => Err(e.into()),
        }
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

        if state.event_triggered || !state.fin_received {
            return Ok(Vec::new());
        }

        // STREAM FIN before a full message arrived is a truncated message per
        // [RFC 9250, Section 4.3.3].
        //
        // [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
        if !state.message_complete() {
            return Err(Error::ProtocolError);
        }

        let data = state.take_message();
        state.event_triggered = true;

        Ok(vec![Event::Query {
            data,
            is_0rtt: state.is_0rtt,
        }])
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

    /// Calls `recv_response` for `stream_id` until it returns `Done`,
    /// `Finished`, or `Reset`, and returns every item read, including that
    /// terminal item.
    fn read_stream_items(
        client: &mut Connection, transport: &mut crate::Connection,
        stream_id: u64,
    ) -> Vec<ClientRead> {
        let mut items = Vec::new();

        loop {
            match client.recv_response(transport, stream_id) {
                Ok(item) => {
                    let terminal = matches!(
                        item,
                        ClientRead::Finished | ClientRead::Reset(_)
                    );
                    items.push(item);

                    if terminal {
                        return items;
                    }
                },

                Err(Error::Done) => return items,

                Err(e) => panic!("unexpected recv_response error: {e:?}"),
            }

            assert!(items.len() < 100, "read loop did not terminate");
        }
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
        assert!(!client.send_pending(0));
        assert!(!client.send_pending(4));
        assert!(!client.send_pending(8));

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

        // `poll` reports one readiness event per stream and reads nothing.
        let mut ready = Vec::new();
        for _ in 0..3 {
            match client.poll(&mut pipe.client).unwrap() {
                (stream_id, Event::Data) => ready.push(stream_id),
                (_, event) => panic!("unexpected event: {event:?}"),
            }
        }
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
        ready.sort_unstable();
        assert_eq!(ready, vec![0, 4, 8]);

        let mut responses = Vec::new();
        for stream_id in ready {
            let items =
                read_stream_items(&mut client, &mut pipe.client, stream_id);
            assert_eq!(items.len(), 2);
            assert_eq!(items[1], ClientRead::Finished);
            match items.into_iter().next() {
                Some(ClientRead::Response(data)) =>
                    responses.push((stream_id, data)),
                item => panic!("unexpected item: {item:?}"),
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
        assert!(client.send_pending(0));

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

            if !client.send_pending(0) {
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

        assert!(!client.send_pending(0));
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
        assert!(client.send_pending(0));
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
        assert!(client.send_pending(0));

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
        assert!(!client.send_pending(0));
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
            probe_query_stream(&mut pipe.client, 0),
            Err(Error::TransportError(crate::Error::InvalidStreamState(0)))
        );
    }

    #[test]
    fn server_reset_on_opened_query_surfaces_as_client_read() {
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

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Reset(42))
        );

        // The reset is delivered once and the stream state is dropped.
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Err(Error::UnknownStream)
        );
        assert!(pipe.client.local_error().is_none());
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
        assert!(!client.send_pending(0));
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
        assert!(!client.send_pending(0));
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
    fn query_second_message_in_later_packet_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // The first query is complete, but FIN has not arrived. The server
        // holds the query back.
        pipe.client
            .stream_send(0, &framed(b"hello"), false)
            .unwrap();
        pipe.advance().unwrap();
        assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));

        // One byte of a second query arrives in a later packet. The 1-byte
        // read after the complete query gets it.
        pipe.client.stream_send(0, &[0], false).unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::ProtocolError));
        assert_protocol_close(&pipe.server);
    }

    #[test]
    fn query_fin_in_later_packet_surfaces_query() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // The read takes exactly the query, and FIN is not known yet.
        pipe.client
            .stream_send(0, &framed(b"hello"), false)
            .unwrap();
        pipe.advance().unwrap();
        assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));

        // FIN arrives alone. The 1-byte read sees it and the query surfaces.
        pipe.client.stream_send(0, b"", true).unwrap();
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
    fn query_split_into_single_bytes() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        let wire = framed(b"hello");

        // Each byte arrives in its own packet. No query surfaces before FIN.
        for (i, byte) in wire.iter().enumerate() {
            let fin = i == wire.len() - 1;
            pipe.client.stream_send(0, &[*byte], fin).unwrap();
            pipe.advance().unwrap();

            if !fin {
                assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));
            }
        }

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: b"hello".to_vec(),
                is_0rtt: false,
            }))
        );
    }

    #[test]
    fn query_zero_length_message_surfaces_empty_query() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // The length prefix is zero, so the message is complete after the
        // prefix.
        pipe.client.stream_send(0, &framed(b""), true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(
            server.poll(&mut pipe.server),
            Ok((0, Event::Query {
                data: Vec::new(),
                is_0rtt: false,
            }))
        );
    }

    #[test]
    fn query_fin_without_bytes_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // The stream carries only FIN, so it holds no message.
        pipe.client.stream_send(0, b"", true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::ProtocolError));
        assert_protocol_close(&pipe.server);
    }

    #[test]
    fn query_truncated_inside_length_prefix_is_protocol_error() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // FIN arrives after only 1 byte of the 2-octet length prefix.
        pipe.client
            .stream_send(0, &framed(b"hello")[..1], true)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Err(Error::ProtocolError));
        assert_protocol_close(&pipe.server);
    }

    #[test]
    fn query_reset_after_partial_length_prefix_surfaces_as_event() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // The server reads 1 byte of the length prefix.
        pipe.client
            .stream_send(0, &framed(b"hello")[..1], false)
            .unwrap();
        pipe.advance().unwrap();
        assert_eq!(server.poll(&mut pipe.server), Err(Error::Done));

        // The client then abandons the query with RESET_STREAM.
        pipe.client
            .stream_shutdown(0, crate::Shutdown::Write, 42)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(server.poll(&mut pipe.server), Ok((0, Event::Reset(42))));
        assert_eq!(
            server.send_response(&mut pipe.server, 0, b"too late", true),
            Err(Error::UnknownStream)
        );
    }

    /// Returns a config whose windows hold one framed message of the maximum
    /// size.
    fn max_message_config() -> crate::Config {
        let mut config = doq_config();
        config.set_initial_max_data(200_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config
    }

    #[test]
    fn query_of_maximum_size_surfaces() {
        let mut config = max_message_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();

        // The length prefix announces 65,535 bytes, the largest u16 value.
        // The congestion window limits each flight, so the client sends the
        // rest after each `advance`. The query surfaces only after FIN.
        let query = vec![7; usize::from(u16::MAX)];
        let wire = framed(&query);
        let mut sent = 0;
        let mut event = None;

        for _ in 0..100 {
            if sent < wire.len() {
                if let Ok(n) = pipe.client.stream_send(0, &wire[sent..], true) {
                    sent += n;
                }
            }

            pipe.advance().unwrap();

            match server.poll(&mut pipe.server) {
                Ok(item) => {
                    event = Some(item);
                    break;
                },

                Err(Error::Done) => (),

                Err(e) => panic!("unexpected poll error: {e:?}"),
            }
        }

        assert_eq!(sent, wire.len());
        assert_eq!(
            event,
            Some((0, Event::Query {
                data: query,
                is_0rtt: false,
            }))
        );
    }

    #[test]
    fn client_reads_response_of_maximum_size() {
        let mut config = max_message_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        // The length prefix announces 65,535 bytes, the largest u16 value.
        // The congestion window limits each flight, so the server sends the
        // rest after each `advance`.
        let response = vec![9; usize::from(u16::MAX)];
        let wire = framed(&response);
        let mut sent = 0;
        let mut items = Vec::new();

        for _ in 0..100 {
            if sent < wire.len() {
                if let Ok(n) = pipe.server.stream_send(0, &wire[sent..], true) {
                    sent += n;
                }
            }

            pipe.advance().unwrap();
            items.extend(read_stream_items(&mut client, &mut pipe.client, 0));

            if items.last() == Some(&ClientRead::Finished) {
                break;
            }
        }

        assert_eq!(sent, wire.len());
        assert_eq!(items, vec![
            ClientRead::Response(response),
            ClientRead::Finished
        ]);
    }

    #[test]
    fn client_reads_response_split_into_single_bytes() {
        let mut config = doq_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        let wire = framed(b"answer");

        // Each byte arrives in its own packet. The response is returned only
        // when its last byte is read.
        for (i, byte) in wire.iter().enumerate() {
            let fin = i == wire.len() - 1;
            pipe.server.stream_send(0, &[*byte], fin).unwrap();
            pipe.advance().unwrap();

            if !fin {
                assert_eq!(
                    client.recv_response(&mut pipe.client, 0),
                    Err(Error::Done)
                );
            }
        }

        assert_eq!(read_stream_items(&mut client, &mut pipe.client, 0), vec![
            ClientRead::Response(b"answer".to_vec()),
            ClientRead::Finished
        ]);
    }

    #[test]
    fn client_reads_zero_length_last_response() {
        let mut config = doq_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        // The last message before FIN has a zero length prefix.
        let mut wire = framed(b"answer");
        wire.extend_from_slice(&framed(b""));
        pipe.server.stream_send(0, &wire, true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(read_stream_items(&mut client, &mut pipe.client, 0), vec![
            ClientRead::Response(b"answer".to_vec()),
            ClientRead::Response(Vec::new()),
            ClientRead::Finished
        ]);
        assert!(pipe.client.local_error().is_none());
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

        // `poll` only reports readiness. `recv_response` detects the FIN
        // that arrived before any response.
        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Err(Error::ProtocolError)
        );
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

        // The query FIN was acknowledged by `advance`, so the transport may
        // collect the stream once the client reads the response FIN.
        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));

        // One `recv_response` call returns one item.
        for answer in [b"answer 1", b"answer 2", b"answer 3"] {
            assert_eq!(
                client.recv_response(&mut pipe.client, 0),
                Ok(ClientRead::Response(answer.to_vec()))
            );
        }
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Finished)
        );
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Err(Error::UnknownStream)
        );
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

        // Track stream 0 as a local query stream. The test writes the
        // partial query below through the transport directly.
        client.streams.insert(0, StreamState {
            is_local: true,
            ..Default::default()
        });

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

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Reset(42))
        );
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

        // [RFC 9250, Section 4.3.1] forbids a second RESET_STREAM because the
        // server already reset the stream for another reason.
        //
        // [RFC 9250, Section 4.3.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
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

        // The server has read the complete query and FIN. The transport counts
        // this matching-final-size reset without exposing it to the DoQ layer.
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

        assert_eq!(client.send_query(&mut pipe.client, b"hello"), Ok(0));
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

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Response(b"world".to_vec()))
        );
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Finished)
        );

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
    /// small window in [`small_window_config`] to grow enough. After each
    /// round trip, `client` reads the stream on every readiness event and
    /// the helper collects every item along the way. Bounded so a regression
    /// that never drains fails the test instead of hanging it.
    fn drain_response(
        pipe: &mut Pipe, server: &mut Connection, client: &mut Connection,
        stream_id: u64,
    ) -> Vec<ClientRead> {
        let mut items = Vec::new();
        let mut iterations = 0;

        loop {
            pipe.advance().unwrap();

            loop {
                match client.poll(&mut pipe.client) {
                    Ok((id, Event::Data)) => items.extend(read_stream_items(
                        client,
                        &mut pipe.client,
                        id,
                    )),
                    Ok((_, ev)) => panic!("unexpected client event: {ev:?}"),
                    Err(Error::Done) => break,
                    Err(e) => panic!("unexpected client poll error: {e:?}"),
                }
            }

            pipe.advance().unwrap();

            if !server.send_pending(stream_id) {
                break;
            }

            server.flush_response(&mut pipe.server, stream_id).unwrap();

            iterations += 1;
            assert!(iterations < 50, "drain loop did not terminate");
        }

        items
    }

    #[test]
    fn send_response_partial_write_drains_across_flushes() {
        let mut config = small_window_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        let mut client = Connection::with_transport(&pipe.client).unwrap();

        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
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
            server.send_pending(0),
            "200 bytes shouldn't fit in the 20-byte window in one write"
        );

        let events = drain_response(&mut pipe, &mut server, &mut client, 0);

        assert!(!server.send_pending(0));
        assert_eq!(events, vec![
            ClientRead::Response(body),
            ClientRead::Finished,
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

        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
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
            server.send_pending(0),
            "200 bytes shouldn't fit in the 20-byte window in one write"
        );

        // Only the first partial write has reached the client so far, so
        // the framed message is still incomplete: even though quiche
        // cleared the QUIC-level FIN flag on the truncated write, the
        // client must not report `Finished` yet.
        pipe.advance().unwrap();
        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(client.recv_response(&mut pipe.client, 0), Err(Error::Done));

        let events = drain_response(&mut pipe, &mut server, &mut client, 0);

        assert!(!server.send_pending(0));
        assert_eq!(events, vec![
            ClientRead::Response(body),
            ClientRead::Finished,
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
            server.send_pending(0),
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

        assert_eq!(client.send_query(&mut pipe.client, b"axfr query"), Ok(0));
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
        assert!(server.send_pending(0));

        let events = drain_response(&mut pipe, &mut server, &mut client, 0);

        assert!(!server.send_pending(0));
        assert_eq!(events, vec![
            ClientRead::Response(body1),
            ClientRead::Response(body2),
            ClientRead::Response(body3),
            ClientRead::Finished,
        ]);
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
    }

    /// Sets up a handshaken pipe with a DoQ client and one query on stream 0.
    fn client_with_query(config: &mut crate::Config) -> (Pipe, Connection) {
        let mut pipe = Pipe::with_config(config).unwrap();
        pipe.handshake().unwrap();

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        pipe.advance().unwrap();

        (pipe, client)
    }

    #[test]
    fn client_readiness_is_emitted_once_until_rearmed() {
        let mut config = doq_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        // The first response message arrives without FIN.
        pipe.server
            .stream_send(0, &framed(b"answer 1"), false)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));

        // The stream is still readable, but it is not reported again.
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));

        // More data arrives while the first message is unread. `poll` reads
        // no bytes and emits nothing.
        pipe.server
            .stream_send(0, &framed(b"answer 2"), false)
            .unwrap();
        pipe.advance().unwrap();
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
        assert!(!client.streams[&0].message_started());

        // A read that returns an item does not re-arm the event.
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Response(b"answer 1".to_vec()))
        );
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));

        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Response(b"answer 2".to_vec()))
        );

        // `Done` re-arms the event.
        assert_eq!(client.recv_response(&mut pipe.client, 0), Err(Error::Done));
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));

        pipe.server
            .stream_send(0, &framed(b"answer 3"), true)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(read_stream_items(&mut client, &mut pipe.client, 0), vec![
            ClientRead::Response(b"answer 3".to_vec()),
            ClientRead::Finished
        ]);
    }

    #[test]
    fn client_reads_all_messages_after_stream_is_collectable() {
        let mut config = doq_config();
        config.set_initial_max_data(10_000);
        let (mut pipe, mut client) = client_with_query(&mut config);

        // The query FIN is acknowledged. Several responses and the response
        // FIN arrive in one flight. The client reads the FIN with the last
        // message. After that quiche may collect the stream, so `Finished`
        // comes from DoQ state.
        let mut wire = Vec::new();
        for i in 0..5u8 {
            wire.extend_from_slice(&framed(&[i; 50]));
        }
        pipe.server.stream_send(0, &wire, true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));

        let items = read_stream_items(&mut client, &mut pipe.client, 0);
        let mut expected: Vec<ClientRead> = (0..5u8)
            .map(|i| ClientRead::Response(vec![i; 50]))
            .collect();
        expected.push(ClientRead::Finished);
        assert_eq!(items, expected);
        assert!(pipe.client.local_error().is_none());
    }

    #[test]
    fn client_serves_fin_without_transport() {
        let mut config = doq_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        pipe.server
            .stream_send(0, &framed(b"answer"), true)
            .unwrap();
        pipe.advance().unwrap();

        // The body read takes the last byte, so it also reads the FIN. After
        // that the transport collects the stream.
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Response(b"answer".to_vec()))
        );
        assert!(client.streams[&0].fin_received);
        assert!(pipe.client.stream_closed(0));

        // `stream_capacity` fails on a collected stream, so this call
        // succeeds only if it does not reach the transport.
        assert_eq!(
            pipe.client.stream_capacity(0),
            Err(crate::Error::InvalidStreamState(0))
        );
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Finished)
        );
    }

    #[test]
    fn client_recv_buf_is_bounded_and_flow_control_stalls_the_server() {
        let mut config = doq_config();
        // The server's send window on stream 0 is the client's `bidi_local`
        // limit.
        config.set_initial_max_stream_data_bidi_local(1_000);
        config.set_initial_max_data(10_000);
        let (mut pipe, mut client) = client_with_query(&mut config);

        let messages: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 600]).collect();
        let mut wire = Vec::new();
        for message in &messages {
            wire.extend_from_slice(&framed(message));
        }

        // The server writes until the stream window is full.
        let sent = pipe.server.stream_send(0, &wire, true).unwrap();
        assert_eq!(sent, 1_000);
        pipe.advance().unwrap();
        assert_eq!(pipe.server.stream_capacity(0), Ok(0));

        // A slow client reads nothing in `poll`. The server stays stalled.
        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert!(!client.streams[&0].message_started());
        pipe.advance().unwrap();
        assert_eq!(pipe.server.stream_capacity(0), Ok(0));

        // The client reads one message at a time. The buffer never holds
        // more than one message body, and it is allocated with the
        // announced length of that body.
        let mut offset = sent;
        let mut received = Vec::new();
        let mut finished = false;
        for _ in 0..50 {
            match client.recv_response(&mut pipe.client, 0) {
                Ok(ClientRead::Response(data)) => received.push(data),
                Ok(ClientRead::Finished) => {
                    finished = true;
                    break;
                },
                Ok(item) => panic!("unexpected item: {item:?}"),
                Err(Error::Done) => (),
                Err(e) => panic!("unexpected error: {e:?}"),
            }

            if let Some(state) = client.streams.get(&0) {
                assert!(state.recv_buf.len() <= 600);
                assert!(state.recv_buf.capacity() <= 600);
            }

            // The consumed bytes return credit, and the server continues.
            pipe.advance().unwrap();

            if offset < wire.len() {
                if let Ok(n) = pipe.server.stream_send(0, &wire[offset..], true) {
                    offset += n;
                }
            }

            pipe.advance().unwrap();
        }

        // All four messages arrive in order, and the server's FIN ends the
        // stream before the loop runs out.
        assert_eq!(received, messages);
        assert!(finished);
    }

    #[test]
    fn client_stop_sending_with_unread_response_is_fatal_in_recv_response() {
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

        // The caller reads the stream without a prior `poll`. The response
        // is buffered in the transport and unread, and `STOP_SENDING` wins.
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Err(Error::ProtocolError)
        );
        assert_protocol_close(&pipe.client);
        assert_eq!(client.poll(&mut pipe.client), Err(Error::Done));
        assert_eq!(client.recv_response(&mut pipe.client, 0), Err(Error::Done));
    }

    #[test]
    fn client_reset_while_response_unread_yields_reset() {
        let mut config = doq_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        pipe.server
            .stream_send(0, &framed(b"answer")[..4], false)
            .unwrap();
        pipe.server
            .stream_shutdown(0, crate::Shutdown::Write, 7)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Reset(7))
        );
        assert!(!client.streams.contains_key(&0));
    }

    #[test]
    fn client_truncated_fin_is_protocol_error_in_recv_response() {
        let mut config = doq_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        let wire = framed(b"answer");
        pipe.server
            .stream_send(0, &wire[..wire.len() - 1], true)
            .unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Err(Error::ProtocolError)
        );
        assert_protocol_close(&pipe.client);
    }

    #[test]
    fn client_bytes_after_last_message_at_fin_are_protocol_error() {
        let mut config = doq_config();
        let (mut pipe, mut client) = client_with_query(&mut config);

        // A complete message, then one stray byte, then FIN.
        let mut wire = framed(b"answer");
        wire.push(0);
        pipe.server.stream_send(0, &wire, true).unwrap();
        pipe.advance().unwrap();

        assert_eq!(client.poll(&mut pipe.client), Ok((0, Event::Data)));
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Response(b"answer".to_vec()))
        );
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Err(Error::ProtocolError)
        );
        assert_protocol_close(&pipe.client);
    }

    #[test]
    fn recv_response_rejects_server_role_and_unknown_streams() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        let mut server = Connection::with_transport(&pipe.server).unwrap();
        assert_eq!(
            server.recv_response(&mut pipe.server, 0),
            Err(Error::ClientOnly)
        );

        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Err(Error::UnknownStream)
        );
    }

    #[test]
    fn response_methods_on_client_are_server_only() {
        let mut config = doq_config();
        let mut pipe = Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();

        // The client sends a complete query on stream 0.
        let mut client = Connection::with_transport(&pipe.client).unwrap();
        assert_eq!(client.send_query(&mut pipe.client, b"query"), Ok(0));
        pipe.advance().unwrap();

        // `send_response` fails with `ServerOnly` before it checks the
        // stream or the data: on the query stream, on an untracked stream,
        // and with a message that is too large.
        assert_eq!(
            client.send_response(&mut pipe.client, 0, b"response", true),
            Err(Error::ServerOnly)
        );
        assert_eq!(
            client.send_response(&mut pipe.client, 4, b"response", true),
            Err(Error::ServerOnly)
        );
        assert_eq!(
            client.send_response(&mut pipe.client, 0, &[0; 65_536], true),
            Err(Error::ServerOnly)
        );

        // `flush_response` fails with `ServerOnly` and keeps the query
        // state.
        assert_eq!(
            client.flush_response(&mut pipe.client, 0),
            Err(Error::ServerOnly)
        );

        // The server answers. The client still tracks the query, so it
        // reads the response and then the end of the stream.
        assert_eq!(
            pipe.server.stream_send(0, &framed(b"response"), true),
            Ok(10)
        );
        pipe.advance().unwrap();
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Response(b"response".to_vec()))
        );
        assert_eq!(
            client.recv_response(&mut pipe.client, 0),
            Ok(ClientRead::Finished)
        );
    }
}
