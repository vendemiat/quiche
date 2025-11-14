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

// TODO use domain crate builder functions instead of passing around [u8]

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
    let query_msg = Message::from_octets(query)
        .map_err(|e| format!("Failed to parse DNS message: {}", e))?;

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
