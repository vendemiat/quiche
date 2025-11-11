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

//! DNS over QUIC (DoQ) client implementation.
//!
//! This example demonstrates how to send DNS queries over QUIC according to RFC 9250.

#[macro_use]
extern crate log;

use ring::rand::*;

use std::collections::HashMap;

const MAX_DATAGRAM_SIZE: usize = 1350;

use quiche::doq::*;

mod doq_common;
use doq_common::*;

use domain::base::iana::Rtype;

struct PendingQuery {
    domain: String,
    qtype: Rtype,
    start_time: std::time::Instant,
}

fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();
    let cmd = &args.next().unwrap();

    if args.len() < 2 {
        println!("Usage: {cmd} <server> <domain> [type]");
        println!();
        println!("Examples:");
        println!("  {cmd} 127.0.0.1 example.com");
        println!("  {cmd} 127.0.0.1 example.com A");
        println!("  {cmd} 127.0.0.1 example.com AAAA");
        println!("  {cmd} [::1] example.com");
        return;
    }

    let server_str = args.next().unwrap();
    let domain = args.next().unwrap();
    let qtype_str = args.next().unwrap_or_else(|| "A".to_string());

    let qtype = match qtype_str.to_uppercase().as_str() {
        "A" => Rtype::A,
        "AAAA" => Rtype::AAAA,
        "NS" => Rtype::NS,
        "CNAME" => Rtype::CNAME,
        "SOA" => Rtype::SOA,
        "PTR" => Rtype::PTR,
        "MX" => Rtype::MX,
        "TXT" => Rtype::TXT,
        "SRV" => Rtype::SRV,
        "ANY" => Rtype::ANY,
        _ => {
            eprintln!("Unsupported query type: {}", qtype_str);
            return;
        },
    };

    // Parse server address, defaulting to DoQ port
    let server_addr = if server_str.contains(':') && !server_str.starts_with('[')
    {
        // IPv4 with port or IPv6 without brackets
        server_str.parse::<std::net::SocketAddr>()
    } else if server_str.starts_with('[') {
        // IPv6 with brackets
        server_str.parse::<std::net::SocketAddr>()
    } else {
        // Just an IP address, add default DoQ port
        format!("{}:{}", server_str, DOQ_PORT).parse::<std::net::SocketAddr>()
    };

    let peer_addr = match server_addr {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to parse server address: {}", e);
            return;
        },
    };

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Bind to appropriate address family.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the QUIC configuration.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // Configure for DoQ.
    config.set_application_protos(&[DOQ_ALPN]).unwrap();
    config.verify_peer(false); // For testing; in production, verify the server!

    config.set_max_idle_timeout(30000); // 30 seconds
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0); // DoQ doesn't use unidirectional streams

    // Generate a random source connection ID.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr().unwrap();

    // Create the QUIC connection.
    let mut conn = quiche::connect(
        Some(&peer_addr.to_string()),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    info!(
        "Connecting to {} from {} for DNS query: {} {}",
        peer_addr,
        socket.local_addr().unwrap(),
        domain,
        qtype_str
    );

    // Initial handshake.
    let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }
        panic!("send() failed: {:?}", e);
    }
    debug!("written {}", write);

    let mut queries_sent = false;
    let mut pending_queries = HashMap::new();
    let query_start = std::time::Instant::now();
    let mut next_stream_id = 0;

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets.
        'read: loop {
            if events.is_empty() {
                debug!("timed out");
                conn.on_timeout();
                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }
                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,
                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };

            debug!("processed {} bytes", read);
        }

        debug!("done reading");

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            if !queries_sent {
                eprintln!("Connection closed before sending query");
            }
            break;
        }

        // Send DNS query once connected.
        if conn.is_established() && !queries_sent {
            info!("Connection established, sending DNS query");

            // Build the DNS query.
            let query = match build_dns_query(&domain, qtype) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("Failed to build DNS query: {}", e);
                    break;
                },
            };

            // Prepare the message with length prefix.
            let mut dns_message = Vec::new();
            if let Err(e) = write_dns_message(&mut dns_message, &query) {
                eprintln!("Failed to format DNS message: {}", e);
                break;
            }

            // Send on the next available stream.
            let stream_id = next_stream_id;
            next_stream_id += 4; // Client-initiated bidirectional streams: 0, 4, 8, ...

            match conn.stream_send(stream_id, &dns_message, true) {
                Ok(written) => {
                    if written < dns_message.len() {
                        error!(
                            "Failed to send complete query: {} < {}",
                            written,
                            dns_message.len()
                        );
                        break;
                    }
                    info!("Sent DNS query on stream {}", stream_id);
                    pending_queries.insert(
                        stream_id,
                        PendingQuery {
                            domain: domain.clone(),
                            qtype,
                            start_time: std::time::Instant::now(),
                        },
                    );
                    queries_sent = true;
                },
                Err(e) => {
                    error!("Failed to send query: {:?}", e);
                    break;
                },
            }
        }

        // Process readable streams (responses).
        for stream_id in conn.readable() {
            let mut stream_buf = Vec::new();
            let mut is_fin = false;

            // Read all data from the stream.
            loop {
                match conn.stream_recv(stream_id, &mut buf) {
                    Ok((read, fin)) => {
                        stream_buf.extend_from_slice(&buf[..read]);
                        is_fin = fin;
                        if read == 0 {
                            break;
                        }
                    },
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("stream_recv failed: {:?}", e);
                        break;
                    },
                }
            }

            if let Some(query_info) = pending_queries.remove(&stream_id) {
                let elapsed = query_info.start_time.elapsed();

                debug!(
                    "Received {} bytes on stream {} (fin={}) in {:?}",
                    stream_buf.len(),
                    stream_id,
                    is_fin,
                    elapsed
                );

                // Parse the DNS response.
                match parse_dns_message(&stream_buf) {
                    Ok((dns_data, _)) => {
                        match DnsMessageInfo::get_id(dns_data) {
                            Ok(id) if id != 0 => {
                                warn!(
                                    "Received DNS response with non-zero ID: {}",
                                    id
                                );
                            },
                            _ => {},
                        }

                        println!(
                            "\nDNS Response for {} ({}):",
                            query_info.domain, query_info.qtype
                        );
                        println!("  Response time: {:?}", elapsed);

                        // Use the domain crate to parse and display response
                        match DnsFormatter::format_message(dns_data) {
                            Ok(formatted) => {
                                println!("{}", formatted);
                            },
                            Err(e) => {
                                error!("Failed to format DNS response: {}", e);
                            },
                        }
                    },
                    Err(e) => {
                        error!("Failed to parse DNS message: {}", e);
                    },
                }

                // Close the connection after receiving the response.
                info!("Response received, closing connection");
                conn.close(true, DoqError::NoError.to_wire(), b"done").ok();
            }
        }

        // Generate outgoing QUIC packets.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },
                Err(e) => {
                    error!("send failed: {:?}", e);
                    conn.close(false, DoqError::InternalError.to_wire(), b"fail")
                        .ok();
                    break;
                },
            };

            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }
                panic!("send() failed: {:?}", e);
            }

            debug!("written {}", write);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Timeout check.
        if query_start.elapsed() > std::time::Duration::from_secs(10) {
            eprintln!("Query timeout");
            break;
        }
    }

    if !queries_sent {
        eprintln!("Failed to establish connection or send query");
    }
}
