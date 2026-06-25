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
//! This example demonstrates how to perform AXFR zone transfers over DoQ.

#[macro_use]
extern crate log;

use ring::rand::*;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;

const MAX_DATAGRAM_SIZE: usize = 1350;

use quiche::doq::*;

mod doq_common;
use doq_common::*;

use domain::base::iana::Rcode;
use domain::base::iana::Rtype;
use domain::base::message::Message;
use domain::rdata::AllRecordData;

struct ZoneTransfer {
    zone: String,
    start_time: std::time::Instant,
    messages_received: usize,
    total_bytes: usize,
    records_written: usize,
    // Set when the server returns a non-zero RCODE or an unparseable message.
    failed: bool,
    // Records are streamed to this file as each message is parsed, so the full
    // zone is persisted without ever holding the whole transfer in memory.
    out_path: String,
    out: BufWriter<File>,
}

fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();
    let cmd = &args.next().unwrap();

    if args.len() < 2 {
        println!("Usage: {cmd} <server> <zone>");
        println!();
        println!("Examples:");
        println!("  {cmd} 127.0.0.1 example.com");
        println!("  {cmd} 127.0.0.1:853 example.com");
        println!("  {cmd} [::1] example.com");
        println!("  {cmd} ns.example.com example.com");
        return;
    }

    let server_str = args.next().unwrap();
    let zone = args.next().unwrap();

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

    // Create the QUIC connection. The SNI server name is set only for host
    // names (RFC 6066 forbids IP-literal SNI).
    let mut conn = quiche::connect(
        server_name.as_deref(),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    info!(
        "Connecting to {} for AXFR zone transfer of {}",
        peer_addr, zone
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
    // Per-stream receive buffers persist across event-loop iterations so that
    // large zone-transfer responses are not lost when they arrive in chunks.
    let mut stream_bufs: HashMap<u64, Vec<u8>> = HashMap::new();
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
            info!("Connection established, sending AXFR request");

            // Build the zone transfer query.
            let query = match build_dns_query(&zone, Rtype::AXFR) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("Failed to build zone transfer query: {}", e);
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
            next_stream_id += 4;

            match conn.stream_send(stream_id, &dns_message, true) {
                Ok(written) => {
                    if written < dns_message.len() {
                        error!("Failed to send complete query");
                        break;
                    }
                    info!("Sent AXFR request on stream {}", stream_id);

                    // Stream received records straight to a zone file so the
                    // full zone is written out without buffering it in memory.
                    let stem = zone.trim_end_matches('.');
                    let stem = if stem.is_empty() { "root" } else { stem };
                    let out_path = format!("{stem}.zone");
                    let file = match File::create(&out_path) {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!(
                                "Failed to create zone file {}: {}",
                                out_path, e
                            );
                            break;
                        },
                    };

                    active_transfers.insert(stream_id, ZoneTransfer {
                        zone: zone.clone(),
                        start_time: std::time::Instant::now(),
                        messages_received: 0,
                        total_bytes: 0,
                        records_written: 0,
                        failed: false,
                        out_path,
                        out: BufWriter::new(file),
                    });
                    transfer_sent = true;
                },
                Err(e) => {
                    error!("Failed to send query: {:?}", e);
                    break;
                },
            }
        }

        // Process responses. Each complete DNS message is parsed and its
        // records streamed to the zone file as soon as it arrives, then its
        // bytes are discarded. The persistent buffer therefore only ever holds
        // an in-flight partial message (< one max DNS message, ~64 KiB) rather
        // than the entire zone, so memory stays bounded regardless of zone
        // size.
        for stream_id in conn.readable() {
            let mut is_fin = false;

            let stream_buf = stream_bufs.entry(stream_id).or_default();
            loop {
                match conn.stream_recv(stream_id, &mut buf) {
                    Ok((read, fin)) => {
                        stream_buf.extend_from_slice(&buf[..read]);
                        is_fin = fin;
                        if fin || read == 0 {
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

            let mut transfer_failed = false;
            if let Some(transfer) = active_transfers.get_mut(&stream_id) {
                // Parse and emit every complete message currently buffered.
                let mut consumed_total = 0;
                // Stops once there are not enough bytes for another full
                // message; the remainder is kept for the next iteration.
                while let Ok((dns_data, consumed)) =
                    read_dns_message(&stream_buf[consumed_total..])
                {
                    consumed_total += consumed;
                    transfer.messages_received += 1;
                    transfer.total_bytes += consumed;

                    match write_message_records(transfer, dns_data) {
                        Ok(rcode) if rcode == Rcode::NOERROR => {},
                        Ok(rcode) => {
                            eprintln!("Transfer failed with rcode: {rcode}");
                            transfer.failed = true;
                            transfer_failed = true;
                            break;
                        },
                        Err(e) => {
                            eprintln!("Failed to process DNS message: {}", e);
                            transfer.failed = true;
                            transfer_failed = true;
                            break;
                        },
                    }
                }

                // Discard fully processed bytes, keeping only the partial tail.
                stream_buf.drain(..consumed_total);
            }

            if transfer_failed {
                conn.close(true, DoqError::NoError.to_wire(), b"done").ok();
            }

            if !is_fin {
                // Zone response not yet complete; keep buffering the tail.
                continue;
            }

            // Stream finished: flush the zone file and finalize the transfer.
            stream_bufs.remove(&stream_id);

            if let Some(mut transfer) = active_transfers.remove(&stream_id) {
                if let Err(e) = transfer.out.flush() {
                    eprintln!("Failed to flush zone file: {}", e);
                }

                let elapsed = transfer.start_time.elapsed();
                if transfer.failed {
                    // The server rejected the request (e.g. NOTIMPL/REFUSED) or
                    // sent a malformed message; remove the empty/partial file.
                    let _ = std::fs::remove_file(&transfer.out_path);
                    println!("\nAXFR Transfer FAILED:");
                    println!("  Zone: {}", transfer.zone);
                    println!(
                        "  Messages received: {}",
                        transfer.messages_received
                    );
                    println!("  Duration: {:?}", elapsed);
                } else {
                    println!("\nAXFR Transfer Complete:");
                    println!("  Zone: {}", transfer.zone);
                    println!(
                        "  Messages received: {}",
                        transfer.messages_received
                    );
                    println!("  Records written: {}", transfer.records_written);
                    println!("  Zone file: {}", transfer.out_path);
                    println!("  Total bytes: {}", transfer.total_bytes);
                    println!("  Duration: {:?}", elapsed);
                    println!(
                        "  Throughput: {:.2} KB/s",
                        (transfer.total_bytes as f64 / 1024.0) /
                            elapsed.as_secs_f64()
                    );
                }

                // Close the connection if no more transfers.
                if active_transfers.is_empty() {
                    info!("All transfers complete, closing connection");
                    conn.close(true, DoqError::NoError.to_wire(), b"done").ok();
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

/// Parse a single DNS message and append its answer-section records to the
/// transfer's zone file in presentation (zone-file) format.
///
/// Records are written out as they are parsed and never retained, so the full
/// zone is persisted to disk without ever buffering it in memory. Returns the
/// message RCODE so the caller can detect a failed transfer (a non-zero RCODE).
fn write_message_records(
    transfer: &mut ZoneTransfer, dns_data: &[u8],
) -> Result<Rcode, Box<dyn std::error::Error>> {
    let msg = Message::from_octets(dns_data)?;

    let rcode = msg.header().rcode();
    if rcode != Rcode::NOERROR {
        return Ok(rcode);
    }

    for record in msg.answer()? {
        let record = record?;
        if let Some(record) = record.into_record::<AllRecordData<_, _>>()? {
            writeln!(transfer.out, "{record}")?;
            transfer.records_written += 1;
        }
    }

    Ok(rcode)
}
