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

//! Common DNS utilities for DoQ examples using the domain crate.

use std::str::FromStr;

use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::name::Name;
use domain::base::{Message, MessageBuilder, Question};

/// Parse a DNS message using the domain crate.
fn parse_domain_message(data: &[u8]) -> Result<Message<&[u8]>, String> {
    Message::from_octets(data)
        .map_err(|e| format!("Failed to parse DNS message: {}", e))
}

/// Build a DNS query using the domain crate.
pub fn build_dns_query(
    domain: &str, query_type: Rtype,
) -> Result<Vec<u8>, String> {
    let mut builder = MessageBuilder::new_vec();

    // Set header
    builder.header_mut().set_id(0); // DoQ requires ID to be 0
    builder.header_mut().set_opcode(Opcode::from_int(0)); // QUERY
    builder.header_mut().set_rd(true); // Recursion desired

    // Move to question section
    let mut question_builder = builder.question();

    // Add the question
    let domain_name = Name::<Vec<u8>>::from_str(domain)
        .map_err(|e| format!("Invalid domain name: {}", e))?;

    question_builder
        .push(Question::new(domain_name, query_type, Class::IN))
        .map_err(|e| format!("Failed to add question: {}", e))?;

    // Get the message
    let message = question_builder.finish();
    Ok(message)
}

/// Build a DNS response with a specific rcode.
pub fn build_dns_response(query: &[u8], rcode: Rcode) -> Result<Vec<u8>, String> {
    // Parse the query
    let query_msg = parse_domain_message(query)?;

    // Build response
    let mut builder = MessageBuilder::new_vec();

    // Copy header fields and set response fields
    builder.header_mut().set_id(0); // DoQ requires ID to be 0
    builder.header_mut().set_qr(true); // This is a response
    builder.header_mut().set_opcode(query_msg.header().opcode());
    builder.header_mut().set_rd(query_msg.header().rd());
    builder.header_mut().set_rcode(rcode);

    // Move to question section and copy questions
    let mut response_builder = builder.question();

    for question in query_msg.question() {
        let q =
            question.map_err(|e| format!("Failed to read question: {}", e))?;
        response_builder
            .push(q)
            .map_err(|e| format!("Failed to add question: {}", e))?;
    }

    // Get the message
    let message = response_builder.finish();
    Ok(message)
}

/// Helper functions for DNS message inspection.
pub struct DnsMessageInfo;

impl DnsMessageInfo {
    /// Get the opcode from a DNS message.
    pub fn get_opcode(data: &[u8]) -> Result<Opcode, String> {
        let msg = parse_domain_message(data)?;
        Ok(msg.header().opcode())
    }

    /// Get the message ID (should be 0 for DoQ).
    pub fn get_id(data: &[u8]) -> Result<u16, String> {
        let msg = parse_domain_message(data)?;
        Ok(msg.header().id())
    }

    /// Get response code from a DNS response.
    pub fn get_response_code(data: &[u8]) -> Result<Rcode, String> {
        let msg = parse_domain_message(data)?;
        Ok(msg.header().rcode())
    }

    /// Get answer count.
    pub fn get_answer_count(data: &[u8]) -> Result<u16, String> {
        let msg = parse_domain_message(data)?;
        Ok(msg.header_counts().ancount())
    }
}

/// Format a response code as a string.
pub fn format_rcode(rcode: Rcode) -> &'static str {
    match rcode.to_int() {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }
}

/// Helper for formatting DNS messages.
pub struct DnsFormatter;

impl DnsFormatter {
    /// Format a DNS message for display.
    pub fn format_message(data: &[u8]) -> Result<String, String> {
        let msg = parse_domain_message(data)?;

        let mut result = format!("DNS Message (ID: {})\n", msg.header().id());
        result.push_str(&format!(
            "  Opcode: {:?}, Response: {}, Rcode: {:?}\n",
            msg.header().opcode(),
            msg.header().qr(),
            msg.header().rcode()
        ));

        let counts = msg.header_counts();
        result.push_str(&format!(
            "  Questions: {}, Answers: {}, Authority: {}, Additional: {}\n",
            counts.qdcount(),
            counts.ancount(),
            counts.nscount(),
            counts.arcount()
        ));

        // Questions
        if counts.qdcount() > 0 {
            result.push_str("\nQuestions:\n");
            for (idx, question) in msg.question().enumerate() {
                match question {
                    Ok(q) => {
                        result.push_str(&format!(
                            "  {}: {} {} {}\n",
                            idx + 1,
                            q.qname(),
                            q.qtype(),
                            q.qclass()
                        ));
                    },
                    Err(e) => {
                        result.push_str(&format!(
                            "  {}: Error: {}\n",
                            idx + 1,
                            e
                        ));
                    },
                }
            }
        }

        Ok(result)
    }
}
