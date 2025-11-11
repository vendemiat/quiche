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

//! DNS zone transfer over QUIC (DoQ) client example.
//!
//! This example demonstrates how to perform AXFR/IXFR zone transfers over DoQ.

#[macro_use]
extern crate log;

use ring::rand::*;

use std::collections::HashMap;

const MAX_DATAGRAM_SIZE: usize = 1350;

use quiche::doq::*;

mod doq_common;
use doq_common::*;

use domain::base::iana::Rtype;

struct ZoneTransfer {
    zone: String,
    transfer_type: Rtype,
    start_time: std::time::Instant,
    messages_received: usize,
    total_bytes: usize,
}

fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();
    let cmd = &args.next().unwrap();

    if args.len() < 2 {
        println!("Usage: {cmd} <server> <zone> [AXFR|IXFR]");
        println!();
        println!("Examples:");
        println!("  {cmd} 127.0.0.1 example.com AXFR");
        println!("  {cmd} 127.0.0.1 example.com IXFR");
        return;
    }

    let server_str = args.next().unwrap();
    let zone = args.next().unwrap();
    let transfer_type_str = args.next().unwrap_or_else(|| "AXFR".to_string());

    let transfer_type = match transfer_type_str.to_uppercase().as_str() {
        "AXFR" => Rtype::AXFR,
        "IXFR" => Rtype::IXFR,
        _ => {
            eprintln!(
                "Invalid transfer type: {} (use AXFR or IXFR)",
                transfer_type_str
            );
            return;
        },
    };

    // Parse server address.
    let peer_addr = match format!("{}:{}", server_str, DOQ_PORT)
        .parse::<std::net::SocketAddr>()
    {
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
    config.verify_peer(false); // For testing; verify in production!

    config.set_max_idle_timeout(120000); // 2 minutes for zone transfers
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);

    // Larger limits for zone transfers.
    config.set_initial_max_data(100_000_000); // 100MB
    config.set_initial_max_stream_data_bidi_local(50_000_000); // 50MB
    config.set_initial_max_stream_data_bidi_remote(50_000_000);
    config.set_initial_max_streams_bidi(10); // Allow multiple concurrent transfers
    config.set_initial_max_streams_uni(0);

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
        "Connecting to {} for {} zone transfer of {}",
        peer_addr, transfer_type_str, zone
    );

    // Initial handshake.
    let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            continue;
        }
        panic!("send() failed: {:?}", e);
    }

    let mut transfer_sent = false;
    let mut active_transfers: HashMap<u64, ZoneTransfer> = HashMap::new();
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

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            match conn.recv(&mut buf[..len], recv_info) {
                Ok(_) => {},
                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Send zone transfer request once connected.
        if conn.is_established() && !transfer_sent {
            info!(
                "Connection established, sending {} request",
                transfer_type_str
            );

            // Build the zone transfer query.
            let query = match build_dns_query(&zone, transfer_type) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("Failed to build zone transfer query: {}", e);
                    break;
                },
            };

            // For IXFR, we would normally add SOA record in the authority section
            // to indicate the current serial number. This is simplified here.

            // Prepare the message with length prefix.
            let mut dns_message = Vec::new();
            if let Err(e) = write_dns_message(&mut dns_message, &query) {
                eprintln!("Failed to format DNS message: {}", e);
                break;
            }

            // Send on the next available stream.
            let stream_id = next_stream_id;
            next_stream_id += 4;

            match conn.stream_send(stream_id, &dns_message, true) {
                Ok(written) => {
                    if written < dns_message.len() {
                        error!("Failed to send complete query");
                        break;
                    }
                    info!(
                        "Sent {} request on stream {}",
                        transfer_type_str, stream_id
                    );
                    active_transfers.insert(
                        stream_id,
                        ZoneTransfer {
                            zone: zone.clone(),
                            transfer_type,
                            start_time: std::time::Instant::now(),
                            messages_received: 0,
                            total_bytes: 0,
                        },
                    );
                    transfer_sent = true;
                },
                Err(e) => {
                    error!("Failed to send query: {:?}", e);
                    break;
                },
            }
        }

        // Process responses.
        for stream_id in conn.readable() {
            let mut stream_buf = Vec::new();
            let mut is_fin = false;

            // Read all available data from the stream.
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

            if let Some(transfer) = active_transfers.get_mut(&stream_id) {
                transfer.total_bytes += stream_buf.len();

                // Parse potentially multiple DNS messages in the stream.
                let mut pos = 0;
                while pos < stream_buf.len() {
                    match parse_dns_message(&stream_buf[pos..]) {
                        Ok((dns_data, consumed)) => {
                            pos += consumed;
                            transfer.messages_received += 1;

                            match DnsMessageInfo::get_response_code(dns_data) {
                                Ok(rcode) if rcode.to_int() != 0 => {
                                    eprintln!(
                                        "Transfer failed with error: {}",
                                        format_rcode(rcode)
                                    );
                                    conn.close(
                                        true,
                                        DoqError::NoError.to_wire(),
                                        b"done",
                                    )
                                    .ok();
                                    break;
                                },
                                Ok(_) => {
                                    if let Ok(answer_count) =
                                        DnsMessageInfo::get_answer_count(dns_data)
                                    {
                                        debug!(
                                            "Received zone transfer message {} ({} answers)",
                                            transfer.messages_received, answer_count
                                        );
                                    }
                                },
                                Err(e) => {
                                    error!("Failed to parse DNS response: {}", e);
                                },
                            }
                        },
                        Err(e) => {
                            if is_fin {
                                // Stream finished, we're done.
                                break;
                            }
                            error!("Failed to parse DNS message: {}", e);
                            break;
                        },
                    }
                }

                if is_fin {
                    let elapsed = transfer.start_time.elapsed();
                    println!("\n{} Transfer Complete:", transfer_type_str);
                    println!("  Zone: {}", transfer.zone);
                    println!(
                        "  Messages received: {}",
                        transfer.messages_received
                    );
                    println!("  Total bytes: {}", transfer.total_bytes);
                    println!("  Duration: {:?}", elapsed);
                    println!(
                        "  Throughput: {:.2} KB/s",
                        (transfer.total_bytes as f64 / 1024.0)
                            / elapsed.as_secs_f64()
                    );

                    active_transfers.remove(&stream_id);

                    // Close the connection if no more transfers.
                    if active_transfers.is_empty() {
                        info!("All transfers complete, closing connection");
                        conn.close(true, DoqError::NoError.to_wire(), b"done")
                            .ok();
                    }
                }
            }
        }

        // Generate outgoing QUIC packets.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("send failed: {:?}", e);
                    conn.close(false, DoqError::InternalError.to_wire(), b"fail")
                        .ok();
                    break;
                },
            };

            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                panic!("send() failed: {:?}", e);
            }
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }
    }
}
