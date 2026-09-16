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
//! This example demonstrates how to send DNS queries over QUIC according to RFC
//! 9250.

#[macro_use]
extern crate log;

use ring::rand::*;

use std::collections::HashMap;

const MAX_DATAGRAM_SIZE: usize = 1350;

use quiche::doq::*;

use core::str::FromStr;
use domain::base::iana::Rtype;
use domain::base::Message;

mod doq_common;
use doq_common::build_dns_query;
use doq_common::resolve_server;

struct PendingQuery {
    domain: String,
    qtype: Rtype,
    start_time: std::time::Instant,
    response_received: bool,
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
        println!("  {cmd} 127.0.0.1:853 example.com AAAA");
        println!("  {cmd} [::1] example.com");
        println!("  {cmd} h.root-servers.net . SOA");
        return;
    }

    let server_str = args.next().unwrap();
    let domain = args.next().unwrap();
    let qtype_str = args.next().unwrap_or_else(|| "A".to_string());

    let qtype = match Rtype::from_str(&qtype_str) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Invalid record type '{}': {}", qtype_str, e);
            eprintln!("Examples: A, AAAA, MX, TXT, CNAME, NS, SOA, SRV");
            return;
        },
    };

    // Resolve the server address (accepts IPs, bracketed IPv6, and host names)
    // and derive the TLS SNI server name, defaulting to the DoQ port.
    let (peer_addr, server_name) = match resolve_server(&server_str, DOQ_PORT) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to resolve server address '{}': {}", server_str, e);
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
    // WARNING: Peer verification is disabled — do NOT use in production.
    // In production, call config.load_verify_locations_from_file() with a
    // trusted CA bundle and remove this line so the server certificate is
    // authenticated.
    config.verify_peer(false);
    warn!("Peer verification disabled — do NOT use in production");

    config.set_max_idle_timeout(30000); // 30 seconds
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0); // DoQ doesn't use unidirectional
                                           // streams

    // Generate a random source connection ID.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr().unwrap();

    // Create the QUIC connection. server_name is the TLS SNI, which
    // resolve_server() leaves unset (None) for IP-literal targets.
    let mut conn = quiche::connect(
        server_name.as_deref(),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();
    let mut doq_conn = Connection::with_transport(&conn).unwrap();

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
                to: local_addr,
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

            match doq_conn.send_query(&mut conn, &query) {
                Ok(stream_id) => {
                    info!("Sent DNS query on stream {}", stream_id);
                    pending_queries.insert(stream_id, PendingQuery {
                        domain: domain.clone(),
                        qtype,
                        start_time: std::time::Instant::now(),
                        response_received: false,
                    });
                    queries_sent = true;
                },
                Err(e) => {
                    error!("Failed to send query: {:?}", e);
                    break;
                },
            }
        }

        // Process DoQ responses. `Connection` owns stream reassembly and
        // framing, returning one event per complete DNS message.
        loop {
            match doq_conn.poll(&mut conn) {
                Ok((stream_id, Event::Response { data })) => {
                    let Some(query_info) = pending_queries.get_mut(&stream_id)
                    else {
                        continue;
                    };
                    if query_info.response_received {
                        error!(
                            "Received more than one DNS response on stream {}",
                            stream_id
                        );
                        conn.close(
                            true,
                            DoqError::ProtocolError.to_wire(),
                            b"multiple responses",
                        )
                        .ok();
                        break;
                    }
                    query_info.response_received = true;
                    let elapsed = query_info.start_time.elapsed();

                    debug!(
                        "Received response on stream {} in {:?}",
                        stream_id, elapsed
                    );

                    // Parse the DNS response.
                    match Message::from_octets(data) {
                        Ok(msg) => {
                            let id = msg.header().id();
                            if id != 0 {
                                warn!(
                                    "Received DNS response with non-zero ID: {}",
                                    id
                                );
                            }
                            info!(
                                "\nDNS Response for {} {}:",
                                query_info.domain, query_info.qtype
                            );
                            println!("{}", msg.display_dig_style());
                        },
                        Err(e) => {
                            error!("Failed to parse DNS message: {}", e);
                        },
                    }

                    println!(";; Response time: {:?}", elapsed);
                },
                Ok((stream_id, Event::Reset(code))) => {
                    if pending_queries.remove(&stream_id).is_some() {
                        error!(
                            "DNS query stream {} was reset: {}",
                            stream_id, code
                        );
                        conn.close(
                            true,
                            DoqError::NoError.to_wire(),
                            b"query reset",
                        )
                        .ok();
                    }
                },
                Ok((stream_id, Event::Finished)) => {
                    let Some(query_info) = pending_queries.remove(&stream_id)
                    else {
                        continue;
                    };
                    if !query_info.response_received {
                        error!(
                            "DNS query stream {} finished without a response",
                            stream_id
                        );
                        conn.close(
                            true,
                            DoqError::ProtocolError.to_wire(),
                            b"missing response",
                        )
                        .ok();
                        break;
                    }
                    info!(
                        "DNS response stream {} finished, closing connection",
                        stream_id
                    );
                    conn.close(true, DoqError::NoError.to_wire(), b"done").ok();
                },
                Ok((_, Event::Query { .. })) =>
                    unreachable!("client received query"),
                Err(Error::Done) => break,
                Err(Error::ProtocolError) => {
                    error!("DoQ protocol error; connection close is pending");
                    break;
                },
                Err(e) => {
                    error!("DoQ response processing failed: {:?}", e);
                    break;
                },
            }
        }

        // Probe every writable stream. A tracked query must be flushed even
        // after its bytes drain, because this detects a later STOP_SENDING.
        for stream_id in conn.writable() {
            let pending = doq_conn.query_pending(stream_id);
            match doq_conn.flush_query(&mut conn, stream_id) {
                Ok(()) if pending =>
                    debug!("Flushed pending query on stream {}", stream_id),
                Ok(()) => {},
                Err(Error::UnknownStream) => {},
                Err(Error::ProtocolError) => {
                    error!("DoQ protocol error; connection close is pending");
                    break;
                },
                Err(e) => {
                    error!("Failed to flush query stream {}: {:?}", stream_id, e);
                    break;
                },
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
