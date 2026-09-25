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
use domain::base::iana::Rtype;
use domain::base::message::CopyRecordsError;
use domain::base::message::ShortMessage;
use domain::base::message_builder::AdditionalBuilder;
use domain::base::message_builder::PushError;
use domain::base::opt::exterr::ExtendedError;
use domain::base::wire::ParseError;
use domain::base::Header;
use domain::base::Message;
use domain::base::MessageBuilder;
use domain::rdata::AllRecordData;

// RFC 9715, Section 3.2: "UDP requestors should limit the requestor's maximum
// UDP payload size to fit in the minimum of the interface MTU, the network MTU
// value configured by the network operators, and the RECOMMENDED maximum
// DNS/UDP payload size 1400. A smaller limit may be allowed."
// https://datatracker.ietf.org/doc/html/rfc9715#section-3.2
pub(crate) const MAX_DNS_UDP_BUFFER_SIZE: u16 = 1400;

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

    #[error("failed to copy DNS records")]
    CopyRecords(#[from] CopyRecordsError),

    #[error("extended RCODE does not fit in the header RCODE field")]
    ExtendedRcodeOverflow,
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

/// Return a message builder that holds a copy of `source` without its OPT
/// records.
///
/// Copy the header, the sole question, and every other record. Write names
/// without compression. Fail when `source` does not have exactly one question.
/// Return the builder positioned at the additional section.
fn builder_from_msg_without_opt(
    source: &Message<Bytes>,
) -> Result<AdditionalBuilder<BytesMut>, DnsError> {
    let mut builder = MessageBuilder::new_bytes();
    *builder.header_mut() = source.header();

    // `copy_records` does not copy the question section, so push the question
    // first.
    let mut questions = builder.question();
    questions.push(source.sole_question()?)?;

    // The closure cannot return an error, so keep the first parse error and
    // return it after copying.
    let mut parse_error = None;

    // `copy_records` copies the answer, authority, and additional sections of
    // `source` in order, starting with the answer builder it receives. It
    // passes each record to the closure and pushes the record the closure
    // returns. Returning `None` omits the record. It returns the builder
    // positioned at the additional section.
    let additional = source.copy_records(questions.answer(), |record| {
        if record.rtype() == Rtype::OPT {
            return None;
        }
        record
            .to_any_record::<AllRecordData<_, _>>()
            .map_err(|error| parse_error.get_or_insert(error))
            .ok()
    })?;

    match parse_error {
        Some(error) => Err(error.into()),
        None => Ok(additional),
    }
}

/// Build an ID-zero failure response from the original DoQ query.
/// Include EDE only when that query contains EDNS.
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

    /// Return whether this query has an AXFR or IXFR question.
    pub(crate) fn is_xfr(&self) -> bool {
        self.0.is_xfr()
    }

    /// Build the upstream query with a random ID.
    ///
    /// Two cases:
    /// 1. `udp_payload_size` is `None`: change only the ID.
    /// 2. `udp_payload_size` is `Some`: build a copy of the query with one OPT
    ///    record. The OPT record keeps the client's EDNS fields and options and
    ///    advertises the given UDP payload size. Add an OPT record when the
    ///    client query has none.
    pub(crate) fn prepare_upstream_query(
        &self, udp_payload_size: Option<u16>,
    ) -> Result<Message<Bytes>, DnsError> {
        // RFC 9250, Section 4.2.1: "When forwarding a DNS message from DoQ
        // over another transport, a DNS Message ID MUST be generated according
        // to the rules of the protocol that is in use."
        // https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
        let mut header = Header::new();
        header.set_random_id();
        let Some(udp_payload_size) = udp_payload_size else {
            return update_id(self.0.clone(), header.id());
        };

        let mut additional = builder_from_msg_without_opt(&self.0)?;
        additional.header_mut().set_id(header.id());
        let source_opt = self.0.opt();
        // RFC 6891, Section 6.2.3: "The requestor's UDP payload size (encoded
        // in the RR CLASS field) is the number of octets of the largest UDP
        // payload that can be reassembled and delivered in the requestor's
        // network stack."
        // https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.3
        additional.opt(|opt| {
            if let Some(source_opt) = source_opt.as_ref() {
                opt.clone_from(source_opt)?;
            }
            opt.set_udp_payload_size(udp_payload_size);
            Ok(())
        })?;
        Ok(additional.into_message())
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
        let xfr_response_without_question = query.is_xfr() &&
            response.header().qr() &&
            response.header().id() == query.header().id() &&
            response.header_counts().qdcount() == 0;
        if !response.is_answer(query) && !xfr_response_without_question {
            return Err(DnsError::InvalidResponse);
        }

        // RFC 9250, Section 4.2.1: "When forwarding a DNS message from another
        // transport over DoQ, the Message ID MUST be set to 0."
        // https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
        let response = update_id(response, 0)?;
        Self::try_from(response)
    }

    /// Adapt this response to the EDNS support of the client query.
    ///
    /// Two cases:
    /// 1. The client query has an OPT record: return the response unchanged.
    /// 2. The client query has no OPT record: remove every OPT record. Fail
    ///    when the full RCODE needs the OPT record to be represented.
    pub(crate) fn prepare_client_response(
        self, client_query: &DoqDnsQuery<Bytes>,
    ) -> Result<Self, DnsError> {
        if client_query.0.opt().is_some() {
            return Ok(self);
        }

        // RFC 6891, Section 6.1.3: "Note that EXTENDED-RCODE value 0
        // indicates that an unextended RCODE is in use (values 0 through
        // 15)."
        // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3
        if self.0.opt_rcode().to_int() >= 16 {
            return Err(DnsError::ExtendedRcodeOverflow);
        }

        // RFC 6891, Section 7: "Lack of presence of an OPT record in a request
        // MUST be taken as an indication that the requestor does not implement
        // any part of this specification and that the responder MUST NOT
        // include an OPT record in its response."
        // https://datatracker.ietf.org/doc/html/rfc6891#section-7
        if self.0.opt().is_none() {
            return Ok(self);
        }
        Self::try_from(builder_from_msg_without_opt(&self.0)?.into_message())
    }

    /// Return whether this response requires retrying over TCP.
    pub(crate) fn is_truncated(&self) -> bool {
        self.0.header().tc()
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
    use domain::base::iana::Class;
    use domain::base::iana::OptRcode;
    use domain::base::Record;
    use domain::base::Ttl;
    use domain::rdata::A;

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
    fn classifies_axfr_query() {
        let query = parse_doq_query(query(0, Rtype::AXFR)).unwrap();
        assert_eq!(query.0.qtype(), Some(Rtype::AXFR));
        assert!(query.0.is_xfr());
    }

    #[test]
    fn classifies_ixfr_query() {
        let query = parse_doq_query(query(0, Rtype::IXFR)).unwrap();
        assert_eq!(query.0.qtype(), Some(Rtype::IXFR));
        assert!(query.0.is_xfr());
    }

    #[test]
    fn classifies_ordinary_query() {
        assert!(!parse_doq_query(query(0, Rtype::A)).unwrap().0.is_xfr());
    }

    /// Build a query with a 4096-byte payload size, DO, and padding.
    fn edns_query() -> Message<Bytes> {
        let query = Message::from_octets(query(0, Rtype::A)).unwrap();
        let mut additional = MessageBuilder::new_bytes().question();
        for question in query.question() {
            additional.push(question.unwrap()).unwrap();
        }
        let mut additional = additional.additional();
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(4096);
                opt.set_dnssec_ok(true);
                opt.padding(8)?;
                Ok(())
            })
            .unwrap();
        additional.into_message()
    }

    /// Build a response to `query` with the full RCODE, one A record, and an
    /// OPT record.
    fn response_with_opt_rcode(
        query: &Message<Bytes>, rcode: u16,
    ) -> DoqDnsResponse<Bytes> {
        assert!(rcode <= 0x0FFF);
        let rcode = OptRcode::masked_from_int(rcode);
        let mut answer = MessageBuilder::new_bytes()
            .start_answer(query, rcode.rcode())
            .unwrap();
        answer
            .push(Record::new(
                query.sole_question().unwrap().into_qname(),
                Class::IN,
                Ttl::from_secs(300),
                A::from_octets(192, 0, 2, 1),
            ))
            .unwrap();
        let mut additional = answer.additional();
        additional
            .opt(|opt| {
                opt.set_rcode(rcode);
                opt.padding(8)?;
                Ok(())
            })
            .unwrap();
        DoqDnsResponse::try_from(additional.into_message()).unwrap()
    }

    #[test]
    fn upstream_query_changes_only_the_id() {
        let query = edns_query();
        let upstream_query = DoqDnsQuery::try_from(query.clone())
            .unwrap()
            .prepare_upstream_query(None)
            .unwrap();

        assert_eq!(&upstream_query.as_slice()[2..], &query.as_slice()[2..]);
    }

    #[test]
    fn udp_upstream_query_preserves_existing_edns_options() {
        let query = edns_query();
        let udp_query = DoqDnsQuery::try_from(query.clone())
            .unwrap()
            .prepare_upstream_query(Some(MAX_DNS_UDP_BUFFER_SIZE))
            .unwrap();
        let original_opt = query.opt().unwrap();
        let udp_opt = udp_query.opt().unwrap();

        assert_eq!(udp_opt.udp_payload_size(), MAX_DNS_UDP_BUFFER_SIZE);
        assert!(udp_opt.dnssec_ok());
        assert_eq!(udp_opt.opt(), original_opt.opt());
        assert_eq!(udp_query.header_counts(), query.header_counts());
        assert_eq!(
            udp_query.sole_question().unwrap(),
            query.sole_question().unwrap()
        );
    }

    #[test]
    fn udp_upstream_query_adds_opt_when_absent() {
        let query = Message::from_octets(query(0, Rtype::A)).unwrap();
        let udp_query = DoqDnsQuery::try_from(query.clone())
            .unwrap()
            .prepare_upstream_query(Some(MAX_DNS_UDP_BUFFER_SIZE))
            .unwrap();
        let udp_opt = udp_query.opt().unwrap();

        assert_eq!(udp_query.header_counts().arcount(), 1);
        assert_eq!(udp_opt.udp_payload_size(), MAX_DNS_UDP_BUFFER_SIZE);
        assert_eq!(udp_opt.version(), 0);
        assert!(!udp_opt.dnssec_ok());
        assert!(udp_opt.opt().is_empty());
    }

    #[test]
    fn udp_upstream_query_keeps_every_section() {
        let source = Message::from_octets(query(0, Rtype::A)).unwrap();
        let question = source.sole_question().unwrap();
        let mut questions = MessageBuilder::new_bytes().question();
        questions.push(&question).unwrap();
        let mut answer = questions.answer();
        answer
            .push(Record::new(
                question.qname(),
                Class::IN,
                Ttl::from_secs(300),
                A::from_octets(192, 0, 2, 1),
            ))
            .unwrap();
        let query = answer.additional().into_message();
        let udp_query = DoqDnsQuery::try_from(query.clone())
            .unwrap()
            .prepare_upstream_query(Some(MAX_DNS_UDP_BUFFER_SIZE))
            .unwrap();

        assert_eq!(udp_query.header().opcode(), query.header().opcode());
        assert_eq!(udp_query.header().flags(), query.header().flags());
        assert_eq!(udp_query.sole_question().unwrap(), question);
        let records = udp_query
            .answer()
            .unwrap()
            .limit_to::<A>()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(*records[0].data(), A::from_octets(192, 0, 2, 1));
    }

    #[test]
    fn response_opt_is_removed_for_client_without_opt() {
        let client_query = parse_doq_query(query(0, Rtype::A)).unwrap();
        let response = response_with_opt_rcode(&client_query.0, 0);
        let response = response.prepare_client_response(&client_query).unwrap();

        assert!(response.0.opt().is_none());
        assert_eq!(response.0.header_counts().arcount(), 0);
        assert!(response.0.is_answer(&client_query.0));
        let records = response
            .0
            .answer()
            .unwrap()
            .limit_to::<A>()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(*records[0].data(), A::from_octets(192, 0, 2, 1));
    }

    #[test]
    fn response_is_unchanged_for_client_with_opt() {
        let client_query = DoqDnsQuery::try_from(edns_query()).unwrap();
        for rcode in [0, 16, 4095] {
            let response = response_with_opt_rcode(&client_query.0, rcode);
            let expected = response.clone().into_bytes();

            let response =
                response.prepare_client_response(&client_query).unwrap();
            assert_eq!(response.into_bytes(), expected);
        }
    }

    #[test]
    fn unextended_rcodes_are_forwarded_to_client_without_opt() {
        let client_query = parse_doq_query(query(0, Rtype::A)).unwrap();
        for rcode in 0..16 {
            let response = response_with_opt_rcode(&client_query.0, rcode)
                .prepare_client_response(&client_query)
                .unwrap();

            assert_eq!(u16::from(response.0.header().rcode().to_int()), rcode);
            assert!(response.0.opt().is_none());
        }
    }

    #[test]
    fn extended_rcodes_are_rejected_for_client_without_opt() {
        let client_query = parse_doq_query(query(0, Rtype::A)).unwrap();
        for rcode in [16, 17, 4095] {
            let response = response_with_opt_rcode(&client_query.0, rcode);

            assert!(matches!(
                response.prepare_client_response(&client_query),
                Err(DnsError::ExtendedRcodeOverflow)
            ));
        }
    }

    #[test]
    fn terminal_response_resets_prepared_query_id() {
        let query = parse_doq_query(query(0, Rtype::A)).unwrap();
        let upstream_query = query.prepare_upstream_query(None).unwrap();
        let response =
            build_failed_response(&upstream_query, Rcode::SERVFAIL, vec![])
                .unwrap();

        assert_eq!(response.0.header().id(), 0);
    }

    #[test]
    fn rejects_response_with_unexpected_id() {
        let query = parse_doq_query(query(0, Rtype::A)).unwrap();
        let response = query.failed_reponse(Rcode::NOERROR, vec![]).unwrap();
        let upstream_query = query.prepare_upstream_query(None).unwrap();
        let response = Message::from_octets(response.into_bytes()).unwrap();
        assert!(DoqDnsResponse::from_upstream(response, &upstream_query).is_err());
    }

    #[test]
    fn rejects_response_with_another_question() {
        let validated_query = parse_doq_query(query(0, Rtype::A)).unwrap();
        let upstream_query =
            validated_query.prepare_upstream_query(None).unwrap();
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
