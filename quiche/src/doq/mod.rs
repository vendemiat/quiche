// Copyright (C) 2024, Cloudflare, Inc.
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

//! Build a DNS over QUIC (DoQ) client or server.
//!
//! Enable the `doq` feature to use this module.
//!
//! # Set up the QUIC connection
//!
//! Start with a QUIC connection. Application code owns its socket and timers
//! and moves packets between the socket and QUIC. DoQ uses that connection to
//! carry DNS queries and responses. It adds message framing and keeps the
//! state for each query stream.
//!
//! Before creating the QUIC connection, set [`DOQ_ALPN`]
//! with [`crate::Config::set_application_protos`], configure TLS credentials
//! and peer verification, and select connection and bidirectional-stream
//! flow-control limits.
//! Choose the idle timeout with [`crate::Config::set_max_idle_timeout`].
//! Start with an established connection for the steps below. Early-data
//! support uses [`crate::Config::enable_early_data`]; application code must
//! also choose which DNS transactions it can process in early data.
//!
//! This example sets ALPN and transport limits. These limits are application
//! choices:
//!
//! ```
//! use quiche::doq;
//!
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! config.set_application_protos(&[doq::DOQ_ALPN])?;
//! config.set_initial_max_data(1_048_576);
//! config.set_initial_max_stream_data_bidi_local(65_537);
//! config.set_initial_max_stream_data_bidi_remote(65_537);
//! config.set_initial_max_streams_bidi(16);
//! config.set_initial_max_streams_uni(0);
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! Before creating the QUIC connection, complete TLS setup. On a server, load
//! the PEM certificate chain with
//! [`crate::Config::load_cert_chain_from_pem_file`] and the private key with
//! [`crate::Config::load_priv_key_from_pem_file`].
//!
//! On a client, call [`verify_peer(true)`](crate::Config::verify_peer). Load
//! trusted CA certificates with
//! [`crate::Config::load_verify_locations_from_file`]
//! or [`crate::Config::load_verify_locations_from_directory`]. Pass the server
//! DNS name to [`crate::connect`] when creating the client connection so TLS
//! can check that name.
//!
//! # Send the first query
//!
//! Once QUIC is established, create a DoQ [`Connection`] with
//! [`Connection::with_transport`]. It copies the client or server role from
//! QUIC. It does not configure or check TLS or ALPN. Keep one DoQ connection
//! for each QUIC connection and pass that same QUIC connection to every DoQ
//! operation.
//!
//! On the client, prepare a DNS query and call [`Connection::send_query`].
//! This opens a query stream, adds the length prefix, and tries to write the
//! query and FIN to QUIC. Save the returned stream ID to match later events
//! to the query. Here, `transport` is a mutable reference to an established
//! QUIC client connection. `query` contains a DNS message prepared by
//! application code:
//!
//! ```no_run
//! use quiche::doq;
//!
//! fn send_query(
//!     transport: &mut quiche::Connection, query: &[u8],
//! ) -> doq::Result<u64> {
//!     let mut connection = doq::Connection::with_transport(transport)?;
//!     let stream_id = connection.send_query(transport, query)?;
//!     Ok(stream_id)
//! }
//! ```
//!
//! Supply the DNS message without a DoQ length prefix. Application code
//! handles DNS validation, IDs, opcode and transfer policy, and padding.
//! A DNS message, including its DNS header, can contain at most 65,535 bytes.
//! DoQ adds a two-byte length prefix before the DNS message.
//! [`MAX_DOQ_MESSAGE_LEN`] is therefore 65,537 bytes.
//!
//! # Read a query or response
//!
//! Feed incoming packets to [`crate::Connection::recv`]. Then call
//! [`Connection::poll`] until it returns [`Error::Done`]. DoQ reads the QUIC
//! streams and joins message fragments. Each returned event has a stream ID
//! and a complete DNS message where applicable. The length prefix is removed.
//! This helper collects the events ready after a packet or timeout:
//!
//! ```
//! use quiche::doq;
//!
//! fn collect_events(
//!     connection: &mut doq::Connection, transport: &mut quiche::Connection,
//! ) -> doq::Result<Vec<(u64, doq::Event)>> {
//!     let mut events = Vec::new();
//!     loop {
//!         match connection.poll(transport) {
//!             Ok(event) => events.push(event),
//!             Err(doq::Error::Done) => return Ok(events),
//!             Err(error) => return Err(error),
//!         }
//!     }
//! }
//! ```
//!
//! On the client, process each [`Event::Response`] for its query. Continue
//! reading until [`Event::Finished`] ends that response stream. One query can
//! receive several responses. The application decides whether that response
//! sequence is valid for the DNS transaction.
//!
//! # Answer a query on the server
//!
//! Create the server's DoQ connection from its QUIC connection in the same
//! way. Poll it after packet input. A server receives [`Event::Query`] after
//! the complete query and its FIN arrive. Parse the DNS message and apply
//! DNS policy before preparing a response. Check the event's `is_0rtt` flag
//! if early data should be accepted.
//!
//! Pass the query's stream ID and DNS response to
//! [`Connection::send_response`]. Supply the response without a length prefix.
//! Set `fin = true` for a single response. For several responses, use
//! `fin = false` until the final message:
//!
//! ```
//! use quiche::doq;
//!
//! fn answer_query(
//!     connection: &mut doq::Connection, transport: &mut quiche::Connection,
//!     stream_id: u64, response: &[u8],
//! ) -> doq::Result<()> {
//!     connection.send_response(transport, stream_id, response, true)
//! }
//! ```
//!
//! # Keep packets and message data moving
//!
//! A successful query or response write can leave data in the DoQ buffer
//! when QUIC has insufficient capacity. Continue driving both connections:
//!
//! 1. Give received packets to [`crate::Connection::recv`]. Use
//!    [`crate::Connection::timeout`] to schedule
//!    [`crate::Connection::on_timeout`] when no packet arrives first.
//! 2. Poll DoQ until [`Error::Done`] and process the returned events.
//! 3. Check [`crate::Connection::writable`]. For each tracked client query
//!    stream reported writable, call [`Connection::flush_query`] even if
//!    [`Connection::query_pending`] is false. This also checks for a peer stop
//!    after the query buffer drains. On the server, call
//!    [`Connection::flush_response`] for writable streams with buffered
//!    responses.
//! 4. Call [`crate::Connection::send`] until it returns [`crate::Error::Done`].
//!    Send each produced packet through the socket using its
//!    [`crate::SendInfo`]. Do this after application writes as well as packet
//!    input and timeouts.
//! 5. Wait for packet input, a timeout, or new application work, then repeat.
//!
//! Flushing a message passes bytes to QUIC. Packet output still requires
//! step 4. Acceptance by QUIC does not mean the peer received or acknowledged
//! the data. A successful final response can also leave buffered bytes;
//! continue flushing until they drain.
//!
//! Before producing another message, check [`Connection::query_pending`] or
//! [`Connection::response_pending`] to limit data still buffered in DoQ.
//! Stop tracking a query when it finishes or is cancelled. Keep the connection
//! pair for other active queries and for later queries.
//!
//! # Cancel work and close the connection
//!
//! If a client no longer needs a response, call [`Connection::cancel_query`].
//! To abandon a tracked transaction, call [`Connection::reset_stream`].
//! [`Event::Reset`] carries the peer's raw error code; application code decides
//! how to report it. A server observes peer stops through response writes or
//! flushes. The transport can suppress a reset after the complete query and
//! FIN have been read. See [`Connection::flush_response`] and [`Event::Reset`]
//! for these visibility limits.
//!
//! Treat [`Error::Done`] from polling as a wait for more work.
//! [`Error::UnknownStream`] can occur when work races with completion or
//! reset. Handle other errors in the application. A detected protocol
//! violation attempts to close QUIC with [`DoqError::ProtocolError`]; the
//! close operation can return a transport error. Continue packet output so
//! QUIC can send the close.
//!
//! When [`crate::Connection::is_closed`] is true, stop work for that connection
//! and drop its DoQ state. Inspect [`crate::Connection::local_error`],
//! [`crate::Connection::peer_error`], and [`crate::Connection::is_timed_out`]
//! for transport close information.
//!
//! See the [client], [server], and [zone-transfer] examples for complete
//! socket and DNS-content handling.
//!
//! [client]: ../../src/doq_client/doq-client.rs.html
//! [server]: ../../src/doq_server/doq-server.rs.html
//! [zone-transfer]: ../../src/doq_zone_transfer/doq-zone-transfer.rs.html

use std::fmt;
use std::io::Write;

mod connection;

pub use connection::Connection;
pub use connection::Error;
pub use connection::Event;
pub use connection::Result;

/// Set the DoQ ALPN token required by [RFC 9250, Section 4.1].
///
/// [RFC 9250, Section 4.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.1
pub const DOQ_ALPN: &[u8] = b"doq";

/// Set the DoQ default port required by [RFC 9250, Section 4.1.1].
///
/// [RFC 9250, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.1.1
pub const DOQ_PORT: u16 = 853;

/// Maximum bytes in one encoded DoQ DNS message.
///
/// [RFC 9250, Section 4.2]: "All DNS messages (queries and responses) sent over
/// DoQ connections MUST be encoded as a 2-octet length field followed by the
/// message content as specified in [RFC1035]."
///
/// [RFC 9250, Section 4.6]: "DoQ implementations always assume that the maximum
/// message size is 65535 bytes."
///
/// [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
/// [RFC1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
/// [RFC 9250, Section 4.6]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.6
pub const MAX_DOQ_MESSAGE_LEN: usize = 65_537;

/// Define DoQ error codes from [RFC 9250, Section 4.3].
///
/// [RFC 9250, Section 4.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum DoqError {
    /// No error (DOQ_NO_ERROR).
    NoError          = 0x0,

    /// Internal error (DOQ_INTERNAL_ERROR).
    InternalError    = 0x1,

    /// Signal protocol violations enumerated by [RFC 9250, Section 4.3.3].
    ///
    /// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    ProtocolError    = 0x2,

    /// Request cancelled (DOQ_REQUEST_CANCELLED).
    RequestCancelled = 0x3,

    /// Excessive load (DOQ_EXCESSIVE_LOAD).
    ExcessiveLoad    = 0x4,

    /// Unspecified error (DOQ_UNSPECIFIED_ERROR).
    UnspecifiedError = 0x5,

    /// Reserved error for testing (DOQ_ERROR_RESERVED).
    ErrorReserved    = 0xd098ea5e,
}

impl DoqError {
    /// Convert the error to its wire format representation.
    pub fn to_wire(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for DoqError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            DoqError::NoError => "no error",
            DoqError::InternalError => "internal error",
            DoqError::ProtocolError => "protocol error",
            DoqError::RequestCancelled => "request cancelled",
            DoqError::ExcessiveLoad => "excessive load",
            DoqError::UnspecifiedError => "unspecified error",
            DoqError::ErrorReserved => "reserved error",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for DoqError {}

/// DoQ DNS wire-format read/write errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum DnsWireError {
    /// length is less than 2 bytes
    LenDataIncomplete,

    /// DNS message is less than specified length
    DnsMessageIncomplete,

    /// DNS message is too large (max 65535 bytes)
    DnsMessageTooLarge,

    /// IO error
    IoError(std::io::Error),
}

impl fmt::Display for DnsWireError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsWireError::LenDataIncomplete =>
                write!(f, "length is less than 2 bytes"),
            DnsWireError::DnsMessageIncomplete =>
                write!(f, "DNS message is less than specified length"),
            DnsWireError::DnsMessageTooLarge =>
                write!(f, "DNS message is too large (max 65535 bytes)"),
            DnsWireError::IoError(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for DnsWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DnsWireError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DnsWireError {
    fn from(e: std::io::Error) -> Self {
        DnsWireError::IoError(e)
    }
}

/// Returns whether a DNS opcode is considered replayable in 0-RTT data.
///
/// The `opcode` is the 4-bit DNS OPCODE field defined by [RFC 1035, Section
/// 4.1.1].
/// Treat QUERY (0) and NOTIFY (4) as safe for 0-RTT per [RFC 9250, Section
/// 4.5]. [RFC 9250, Appendix A] explains why NOTIFY is included.
/// Implementations already throttle the SOA/XFR
/// queries a NOTIFY triggers, so a replayed NOTIFY has negligible impact
/// in practice.
///
/// [RFC 1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// [RFC 9250, Section 4.5]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
/// [RFC 9250, Appendix A]: https://datatracker.ietf.org/doc/html/rfc9250#appendix-A
pub fn is_replayable_opcode(opcode: u8) -> bool {
    matches!(opcode, 0 | 4)
}

/// Read a DNS message with the 2-octet length prefix.
/// Returns the DNS message without the length prefix and the number of bytes
/// consumed.
pub fn read_dns_message(
    data: &[u8],
) -> std::result::Result<(&[u8], usize), DnsWireError> {
    if data.len() < 2 {
        return Err(DnsWireError::LenDataIncomplete);
    }

    let length = u16::from_be_bytes([data[0], data[1]]) as usize;

    if data.len() < 2 + length {
        return Err(DnsWireError::DnsMessageIncomplete);
    }

    Ok((&data[2..2 + length], 2 + length))
}

/// Write a DNS message with the 2-octet length prefix.
pub fn write_dns_message<W: Write>(
    writer: &mut W, data: &[u8],
) -> std::result::Result<(), DnsWireError> {
    if data.len() > 65535 {
        return Err(DnsWireError::DnsMessageTooLarge);
    }

    let length = (data.len() as u16).to_be_bytes();
    writer.write_all(&length)?;
    writer.write_all(data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_replayable_opcode() {
        // QUERY (0) is replayable
        assert!(is_replayable_opcode(0));

        // NOTIFY (4) is replayable
        assert!(is_replayable_opcode(4));

        // Other opcodes are not replayable (opcode is 4-bit, max value 15)
        assert!(!is_replayable_opcode(1)); // IQUERY
        assert!(!is_replayable_opcode(2)); // STATUS
        assert!(!is_replayable_opcode(3)); // Reserved
        assert!(!is_replayable_opcode(5)); // UPDATE
        assert!(!is_replayable_opcode(6)); // DNS Stateful Operations
        assert!(!is_replayable_opcode(15)); // Max opcode value
    }

    #[test]
    fn test_read_dns_message_success() {
        // Valid DNS message: length prefix (0x00, 0x05) + 5 bytes of data
        let data = vec![0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];

        let result = read_dns_message(&data);
        assert!(result.is_ok());

        let (dns_msg, consumed) = result.unwrap();
        assert_eq!(dns_msg, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_read_dns_message_zero_length() {
        // Valid zero-length message
        let data = vec![0x00, 0x00];

        let result = read_dns_message(&data);
        assert!(result.is_ok());

        let (dns_msg, consumed) = result.unwrap();
        assert_eq!(dns_msg.len(), 0);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_read_dns_message_max_length() {
        // Maximum length (65535 bytes)
        let mut data = vec![0xFF, 0xFF];
        data.extend(vec![0xAA; 65535]);

        let result = read_dns_message(&data);
        assert!(result.is_ok());

        let (dns_msg, consumed) = result.unwrap();
        assert_eq!(dns_msg.len(), 65535);
        assert_eq!(consumed, 65537);
    }

    #[test]
    fn test_read_dns_message_incomplete_length() {
        // Only 1 byte - can't read length prefix
        let data = vec![0x00];

        let result = read_dns_message(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            DnsWireError::LenDataIncomplete => {},
            _ => panic!("Expected LenDataIncomplete error"),
        }
    }

    #[test]
    fn test_read_dns_message_empty_data() {
        // Empty data
        let data = vec![];

        let result = read_dns_message(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            DnsWireError::LenDataIncomplete => {},
            _ => panic!("Expected LenDataIncomplete error"),
        }
    }

    #[test]
    fn test_read_dns_message_incomplete_message() {
        // Length says 10 bytes, but only 5 bytes provided
        let data = vec![0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05];

        let result = read_dns_message(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            DnsWireError::DnsMessageIncomplete => {},
            _ => panic!("Expected DnsMessageIncomplete error"),
        }
    }

    #[test]
    fn test_read_dns_message_with_trailing_data() {
        // Valid message with extra trailing data
        let data = vec![0x00, 0x03, 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0xFF];

        let result = read_dns_message(&data);
        assert!(result.is_ok());

        let (dns_msg, consumed) = result.unwrap();
        assert_eq!(dns_msg, &[0x01, 0x02, 0x03]);
        assert_eq!(consumed, 5); // Only consumed the actual message
    }

    #[test]
    fn test_write_dns_message_success() {
        let dns_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut buffer = Vec::new();

        let result = write_dns_message(&mut buffer, &dns_data);
        assert!(result.is_ok());

        // Check length prefix
        assert_eq!(buffer[0], 0x00);
        assert_eq!(buffer[1], 0x05);

        // Check data
        assert_eq!(&buffer[2..], &dns_data[..]);
    }

    #[test]
    fn test_write_dns_message_zero_length() {
        let dns_data = vec![];
        let mut buffer = Vec::new();

        let result = write_dns_message(&mut buffer, &dns_data);
        assert!(result.is_ok());

        assert_eq!(buffer, vec![0x00, 0x00]);
    }

    #[test]
    fn test_write_dns_message_max_length() {
        let dns_data = vec![0xBB; 65535];
        let mut buffer = Vec::new();

        let result = write_dns_message(&mut buffer, &dns_data);
        assert!(result.is_ok());

        // Check length prefix
        assert_eq!(buffer[0], 0xFF);
        assert_eq!(buffer[1], 0xFF);

        // Check data
        assert_eq!(&buffer[2..], &dns_data[..]);
    }

    #[test]
    fn test_write_dns_message_too_large() {
        let dns_data = vec![0xCC; 65536];
        let mut buffer = Vec::new();

        let result = write_dns_message(&mut buffer, &dns_data);
        assert!(result.is_err());

        match result.unwrap_err() {
            DnsWireError::DnsMessageTooLarge => {},
            _ => panic!("Expected DnsMessageTooLarge error"),
        }
    }
}
