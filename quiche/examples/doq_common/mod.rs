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

use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use domain::base::iana::exterr::ExtendedErrorCode;
use domain::base::iana::Class;
use domain::base::iana::Rcode;
use domain::base::iana::Rtype;
use domain::base::name::Name;
use domain::base::opt::exterr::ExtendedError;
use domain::base::Message;
use domain::base::MessageBuilder;

// TODO use domain crate builder functions instead of passing around [u8]

/// Resolve a user-supplied server string into a socket address and an optional
/// TLS SNI server name.
///
/// Accepts `ip`, `ip:port`, `[v6]`, `[v6]:port`, bare `v6`, `host`, and
/// `host:port`; host names are resolved via the system resolver. For IP
/// literals no SNI is returned (RFC 6066 forbids IP-literal SNI); for host
/// names the host is returned as the SNI value.
#[allow(unused)]
pub fn resolve_server(
    server: &str, default_port: u16,
) -> anyhow::Result<(SocketAddr, Option<String>)> {
    // ip:port or [v6]:port
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok((addr, None));
    }

    // bare IPv4/IPv6 literal without a port
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok((SocketAddr::new(ip, default_port), None));
    }

    // bracketed IPv6 literal without a port: [v6]
    if let Some(inner) =
        server.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Ok((SocketAddr::new(ip, default_port), None));
        }
    }

    // host[:port] — a host name never contains ':', so a single trailing ':'
    // separates the host from the port.
    let (host, port) = match server.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port = p.parse::<u16>().map_err(|_| {
                anyhow::anyhow!("invalid port in server address: {server}")
            })?;
            (h, port)
        },
        _ => (server, default_port),
    };

    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses found for host: {host}"))?;

    Ok((addr, Some(host.to_string())))
}

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

/// Build a DNS response with a specific rcode and optional EDE codes.
#[allow(unused)]
pub fn build_dns_response(
    query: &[u8], rcode: Rcode, ede_codes: Vec<ExtendedErrorCode>,
) -> anyhow::Result<Vec<u8>> {
    let query_msg = Message::from_octets(query)?;

    let mut additional = MessageBuilder::new_vec()
        .start_answer(&query_msg, rcode)?
        .additional();

    if !ede_codes.is_empty() {
        additional.opt(|opt| {
            for code in &ede_codes {
                let ede: ExtendedError<Vec<u8>> = (*code).into();
                opt.push(&ede)?;
            }
            Ok(())
        })?;
    }

    Ok(additional.finish())
}
