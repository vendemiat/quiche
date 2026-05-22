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

use domain::base::iana::Class;
use domain::base::iana::Rcode;
use domain::base::iana::Rtype;
use domain::base::name::Name;
use domain::base::Message;
use domain::base::MessageBuilder;

// TODO use domain crate builder functions instead of passing around [u8]

/// Build a DNS query using the domain crate.
#[allow(unused)]
pub fn build_dns_query(
    domain: &str, query_type: Rtype,
) -> anyhow::Result<Vec<u8>> {
    let mut builder = MessageBuilder::new_vec();

    // Set header
    let h = builder.header_mut();
    h.set_id(0); // DoQ requires ID to be 0
    h.set_rd(true); // Recursion desired

    // Move to question section
    let mut question_builder = builder.question();

    // Add the question
    let domain_name = Name::<Vec<u8>>::from_str(domain)?;

    question_builder.push((domain_name, query_type, Class::IN))?;

    // Get the message
    let message = question_builder.finish();
    Ok(message)
}

/// Build a DNS response with a specific rcode.
#[allow(unused)]
pub fn build_dns_response(query: &[u8], rcode: Rcode) -> anyhow::Result<Vec<u8>> {
    // Parse the query
    let query_msg = Message::from_octets(query)?;

    // Build response with the caller-supplied rcode.
    let builder = MessageBuilder::new_vec().start_answer(&query_msg, rcode)?;

    // Get the message
    let message = builder.finish();
    Ok(message)
}
