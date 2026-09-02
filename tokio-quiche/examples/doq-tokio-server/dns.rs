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

//! DNS validation and wire-preserving transformations.

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use domain::base::Message;

    fn parse_query(data: &[u8]) -> Option<Message<&[u8]>> {
        let message = Message::from_octets(data).ok()?;

        if message.header().id() != 0 {
            return None;
        }
        if message.header().qr() {
            return None;
        }
        message.sole_question().ok()?;
        if message.iter().any(|record| record.is_err()) {
            return None;
        }
        Some(message)
    }

    fn query(id: u16, qtype: u16) -> Bytes {
        let mut query =
            b"\0\0\0\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01"
                .to_vec();
        query[..2].copy_from_slice(&id.to_be_bytes());
        query[25..27].copy_from_slice(&qtype.to_be_bytes());
        Bytes::from(query)
    }

    #[test]
    fn rejects_short_and_malformed_queries() {
        assert!(parse_query(&[0; 11]).is_none());
        let mut malformed = query(0, 1).to_vec();
        malformed[12] = 64;
        assert!(parse_query(&malformed).is_none());
    }

    #[test]
    fn rejects_nonzero_id() {
        assert!(parse_query(&query(1, 1)).is_none());
    }
}
