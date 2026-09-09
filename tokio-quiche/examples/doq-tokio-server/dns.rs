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

use bytes::Bytes;
use bytes::BytesMut;
use domain::base::iana::Rcode;
use domain::base::message::ShortMessage;
use domain::base::message_builder::PushError;
use domain::base::opt::exterr::ExtendedError;
use domain::base::wire::ParseError;
use domain::base::Header;
use domain::base::Message;
use domain::base::MessageBuilder;

/// A validated DNS query received over DoQ.
pub(crate) struct DoqDnsQuery<T>(Message<T>);

/// A validated DNS response ready to send over DoQ.
#[derive(Clone)]
pub(crate) struct DoqDnsResponse<T>(Message<T>);

#[derive(Debug, thiserror::Error)]
pub(crate) enum DnsError {
    #[error("invalid DNS message")]
    InvalidMessage(#[from] ShortMessage),

    #[error("invalid DNS question")]
    InvalidQuestion(#[from] ParseError),

    #[error("failed to construct DNS message")]
    Build(#[from] PushError),

    #[error("invalid DNS response")]
    InvalidResponse,
}

fn update_id(
    message: Message<Bytes>, id: u16,
) -> Result<Message<Bytes>, DnsError> {
    // Reuse the original allocation when Bytes is uniquely owned.
    // Copy only when the buffer is shared.
    let mut message =
        Message::from_octets(BytesMut::from(message.into_octets()))?;
    message.header_mut().set_id(id);
    Ok(Message::from_octets(message.into_octets().freeze())?)
}

pub(crate) fn build_failed_response(
    query: &Message<Bytes>, rcode: Rcode, ede: Vec<ExtendedError<Bytes>>,
) -> Result<DoqDnsResponse<Bytes>, DnsError> {
    let mut additional = MessageBuilder::new_bytes()
        .start_answer(query, rcode)?
        .additional();
    additional.header_mut().set_id(0);

    if !ede.is_empty() && query.opt().is_some() {
        additional.opt(|opt| {
            for ede in ede {
                opt.push(&ede)?;
            }
            Ok(())
        })?;
    }

    Ok(DoqDnsResponse(additional.into_message()))
}

impl DoqDnsQuery<Bytes> {
    /// Return the DNS opcode.
    pub(crate) fn opcode(&self) -> u8 {
        self.0.header().opcode().into()
    }

    /// Return this query with a random DNS message ID.
    pub(crate) fn prepare_upstream_query(
        self,
    ) -> Result<Message<Bytes>, DnsError> {
        // RFC 9250, Section 4.2.1: "When forwarding a DNS message from DoQ
        // over another transport, a DNS Message ID MUST be generated according
        // to the rules of the protocol that is in use."
        // https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
        let mut header = Header::new();
        header.set_random_id();
        update_id(self.0, header.id())
    }

    /// Build a terminal DNS response for this query.
    pub(crate) fn failed_reponse(
        &self, rcode: Rcode, ede: Vec<ExtendedError<Bytes>>,
    ) -> Result<DoqDnsResponse<Bytes>, DnsError> {
        build_failed_response(&self.0, rcode, ede)
    }
}

impl TryFrom<Message<Bytes>> for DoqDnsQuery<Bytes> {
    type Error = DnsError;

    fn try_from(message: Message<Bytes>) -> Result<Self, Self::Error> {
        // RFC 9250, Section 4.2.1: "When sending queries over a QUIC
        // connection, the DNS Message ID MUST be set to 0."
        // https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
        if message.header().id() != 0 || message.header().qr() {
            return Err(DnsError::InvalidResponse);
        }

        message.sole_question()?;
        if message
            .opt()
            .is_some_and(|opt| opt.opt().tcp_keepalive().is_some())
        {
            return Err(DnsError::InvalidResponse);
        }

        Ok(Self(message))
    }
}

impl DoqDnsResponse<Bytes> {
    /// Parse, correlate, and convert an upstream response to a DoQ response.
    pub(crate) fn from_upstream_bytes(
        response: Bytes, query: &Message<Bytes>,
    ) -> Result<Self, DnsError> {
        Self::from_upstream(Message::from_octets(response)?, query)
    }

    /// Correlate an upstream response and convert it to a DoQ response.
    pub(crate) fn from_upstream(
        response: Message<Bytes>, query: &Message<Bytes>,
    ) -> Result<Self, DnsError> {
        // RFC 5936, Section 2.2: "For subsequent messages, it MAY do the same
        // or leave the Question section empty."
        // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2
        let xfr_response_without_question = query.is_xfr()
            && response.header().qr()
            && response.header().id() == query.header().id()
            && response.header_counts().qdcount() == 0;
        if !response.is_answer(query) && !xfr_response_without_question {
            return Err(DnsError::InvalidResponse);
        }

        // RFC 9250, Section 4.2.1: "When forwarding a DNS message from another
        // transport over DoQ, the Message ID MUST be set to 0."
        // https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
        let response = update_id(response, 0)?;
        Self::try_from(response)
    }

    /// Return the bare DNS response bytes.
    pub(crate) fn into_bytes(self) -> Bytes {
        self.0.into_octets()
    }
}

impl TryFrom<Message<Bytes>> for DoqDnsResponse<Bytes> {
    type Error = DnsError;

    fn try_from(message: Message<Bytes>) -> Result<Self, Self::Error> {
        if message.header().id() != 0 || !message.header().qr() {
            return Err(DnsError::InvalidResponse);
        }
        Ok(Self(message))
    }
}

#[cfg(test)]
pub(crate) fn query(id: u16, qtype: domain::base::iana::Rtype) -> Bytes {
    use domain::base::name::Name;
    use std::str::FromStr;

    let mut builder = MessageBuilder::new_bytes();
    builder.header_mut().set_id(id);

    let mut questions = builder.question();
    questions
        .push((Name::<Vec<u8>>::from_str("www.example").unwrap(), qtype))
        .unwrap();

    questions.into_message().into_octets()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use domain::base::iana::Rtype;

    use super::*;

    fn parse_doq_query(data: Bytes) -> Result<DoqDnsQuery<Bytes>, DnsError> {
        let message = Message::from_octets(data)?;
        DoqDnsQuery::try_from(message)
    }

    #[test]
    fn rejects_short_and_malformed_queries() {
        assert!(parse_doq_query(Bytes::from_static(&[0; 11])).is_err());
        let mut malformed = query(0, Rtype::A).to_vec();
        // Byte 12 is the first QNAME label length. A length of 64 exceeds
        // DNS's 63-octet label limit, making the QNAME malformed.
        malformed[12] = 64;
        assert!(parse_doq_query(Bytes::from(malformed)).is_err());
    }

    #[test]
    fn rejects_nonzero_id() {
        assert!(parse_doq_query(query(1, Rtype::A)).is_err());
    }

    #[test]
    fn rejects_response_form_query() {
        let mut response = query(0, Rtype::A).to_vec();
        // Set the QR flag in the header's third byte to make this a response.
        response[2] |= 0x80;
        assert!(parse_doq_query(Bytes::from(response)).is_err());
    }

    #[test]
    fn preserves_zone_transfer_types() {
        assert!(parse_doq_query(query(0, Rtype::AXFR)).unwrap().0.is_xfr());
        assert!(parse_doq_query(query(0, Rtype::IXFR)).unwrap().0.is_xfr());
        assert!(!parse_doq_query(query(0, Rtype::A)).unwrap().0.is_xfr());
    }

    #[test]
    fn translates_and_restores_only_the_dns_id() {
        let expected = query(0, Rtype::A);
        let expected_body = expected.as_ref()[2..].to_vec();
        let validated = parse_doq_query(query(0, Rtype::A)).unwrap();
        let original_ptr = validated.0.as_slice().as_ptr();
        let upstream_query = validated.prepare_upstream_query().unwrap();
        assert_eq!(upstream_query.as_slice().as_ptr(), original_ptr);
        assert_eq!(&upstream_query.as_slice()[2..], expected_body.as_slice());

        let response = MessageBuilder::new_bytes()
            .start_answer(&upstream_query, Rcode::NOERROR)
            .unwrap()
            .additional()
            .into_message();
        let original_ptr = response.as_slice().as_ptr();
        let response =
            DoqDnsResponse::from_upstream(response, &upstream_query).unwrap();
        assert_eq!(response.0.as_slice().as_ptr(), original_ptr);
        assert_eq!(response.0.header().id(), 0);
    }

    #[test]
    fn terminal_response_resets_prepared_query_id() {
        let query = parse_doq_query(query(0, Rtype::A)).unwrap();
        let upstream_query = query.prepare_upstream_query().unwrap();
        let response =
            build_failed_response(&upstream_query, Rcode::SERVFAIL, vec![])
                .unwrap();

        assert_eq!(response.0.header().id(), 0);
    }

    #[test]
    fn rejects_response_with_unexpected_id() {
        let query = parse_doq_query(query(0, Rtype::A)).unwrap();
        let response = query.failed_reponse(Rcode::NOERROR, vec![]).unwrap();
        let upstream_query = query.prepare_upstream_query().unwrap();
        let response = Message::from_octets(response.into_bytes()).unwrap();
        assert!(DoqDnsResponse::from_upstream(response, &upstream_query).is_err());
    }

    #[test]
    fn rejects_response_with_another_question() {
        let validated_query = parse_doq_query(query(0, Rtype::A)).unwrap();
        let upstream_query = validated_query.prepare_upstream_query().unwrap();
        let other_query = Message::from_octets(query(
            upstream_query.header().id(),
            Rtype::AAAA,
        ))
        .unwrap();
        let response = MessageBuilder::new_bytes()
            .start_answer(&other_query, Rcode::NOERROR)
            .unwrap()
            .additional()
            .into_message();
        assert!(DoqDnsResponse::from_upstream(response, &upstream_query).is_err());
    }
}
