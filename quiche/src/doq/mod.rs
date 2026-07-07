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

//! DNS over QUIC (DoQ) support.

use std::fmt;
use std::io::Write;

mod connection;

pub use connection::Connection;
pub use connection::Error;
pub use connection::Event;
pub use connection::Result;

/// The ALPN token for DoQ as specified in
/// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.1>
pub const DOQ_ALPN: &[u8] = b"doq";

/// The default port for DNS over QUIC (DoQ) as specified in
/// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.1.1>
pub const DOQ_PORT: u16 = 853;

/// DoQ error codes as specified in
/// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum DoqError {
    /// No error (DOQ_NO_ERROR).
    NoError          = 0x0,

    /// Internal error (DOQ_INTERNAL_ERROR).
    InternalError    = 0x1,

    /// Protocol error (DOQ_PROTOCOL_ERROR). Conditions are enumerated in
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3>.
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
/// The `opcode` is the 4-bit DNS OPCODE field (values 0-15) as defined in
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>. QUERY (0)
/// and NOTIFY (4) are safe for 0-RTT per
/// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.5>.
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
    writer: &mut W, dns_data: &[u8],
) -> std::result::Result<(), DnsWireError> {
    if dns_data.len() > 65535 {
        return Err(DnsWireError::DnsMessageTooLarge);
    }

    let length = (dns_data.len() as u16).to_be_bytes();
    writer.write_all(&length)?;
    writer.write_all(dns_data)?;
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
