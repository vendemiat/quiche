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

//! DNS over QUIC (DoQ) support module.

use std::io::Write;

/// The default port for DNS over QUIC (DoQ) as specified in RFC 9250.
pub const DOQ_PORT: u16 = 853;

/// The ALPN token for DoQ as specified in RFC 9250.
pub const DOQ_ALPN: &[u8] = b"doq";

/// DoQ error codes as specified in RFC 9250 Section 4.3.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u64)]
pub enum DoqError {
    /// No error. See RFC 9250 Section 4.3 (DOQ_NO_ERROR).
    NoError = 0x0,

    /// Implementation error. See RFC 9250 Section 4.3 (DOQ_INTERNAL_ERROR).
    InternalError = 0x1,

    /// Protocol error. See RFC 9250 Section 4.3 (DOQ_PROTOCOL_ERROR).
    ProtocolError = 0x2,

    /// Request cancelled. See RFC 9250 Section 4.3 (DOQ_REQUEST_CANCELLED).
    RequestCancelled = 0x3,

    /// Excessive load. See RFC 9250 Section 4.3 (DOQ_EXCESSIVE_LOAD).
    ExcessiveLoad = 0x4,

    /// Unspecified error. See RFC 9250 Section 4.3 (DOQ_UNSPECIFIED_ERROR).
    UnspecifiedError = 0x5,

    /// Reserved for tests. See RFC 9250 Section 4.3 (DOQ_ERROR_RESERVED).
    ErrorReserved = 0xd098ea5e,
}

impl DoqError {
    /// Convert the error to its wire format representation.
    pub fn to_wire(self) -> u64 {
        self as u64
    }
}

/// DNS opcodes that are considered replayable for 0-RTT.
pub fn is_replayable_opcode(opcode: u8) -> bool {
    // QUERY (0) and NOTIFY (4) are safe for 0-RTT
    matches!(opcode, 0 | 4)
}

/// Parse a DNS message with the 2-octet length prefix.
/// Returns the DNS message without the length prefix and the number of bytes consumed.
pub fn parse_dns_message(data: &[u8]) -> Result<(&[u8], usize), String> {
    if data.len() < 2 {
        return Err("Insufficient data for length field".to_string());
    }

    let length = u16::from_be_bytes([data[0], data[1]]) as usize;

    if data.len() < 2 + length {
        return Err(format!(
            "Insufficient data for DNS message: expected {}, got {}",
            length,
            data.len() - 2
        ));
    }

    Ok((&data[2..2 + length], 2 + length))
}

/// Write a DNS message with the 2-octet length prefix.
pub fn write_dns_message<W: Write>(
    writer: &mut W, dns_data: &[u8],
) -> Result<(), std::io::Error> {
    if dns_data.len() > 65535 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS message too large",
        ));
    }

    let length = (dns_data.len() as u16).to_be_bytes();
    writer.write_all(&length)?;
    writer.write_all(dns_data)?;
    Ok(())
}
