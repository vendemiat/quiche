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

//! DNS over QUIC (DoQ) server implementation.
//!
//! This example demonstrates a simple DoQ server according to RFC 9250.

// TODO: Use DoH to 1.1.1.1 to process queries

#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::net;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

use quiche::doq::*;

mod doq_common;
use doq_common::*;

use domain::base::{iana::Rcode, message::Message};

struct PartialDnsQuery {
    data: Vec<u8>,
    expected_len: Option<usize>,
}

struct Client {
    conn: quiche::Connection,
    partial_queries: HashMap<u64, PartialDnsQuery>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();
    let cmd = &args.next().unwrap();

    if args.len() > 1 {
        println!("Usage: {cmd} [address:port]");
        println!();
        println!("Default: 127.0.0.1:{}", DOQ_PORT);
        return;
    }

    let listen_addr = args
        .next()
        .unwrap_or_else(|| format!("127.0.0.1:{}", DOQ_PORT));

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket.
    let mut socket =
        mio::net::UdpSocket::bind(listen_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    info!("DoQ server listening on {}", socket.local_addr().unwrap());

    // Create the configuration for QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // Configure for DoQ.
    config.set_application_protos(&[DOQ_ALPN]).unwrap();

    // Load certificate and key (using the example certificates).
    config
        .load_cert_chain_from_pem_file("quiche/examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("quiche/examples/cert.key")
        .unwrap();

    config.set_max_idle_timeout(30000); // 30 seconds
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(0); // DoQ doesn't use unidirectional streams
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0);
    config.set_disable_active_migration(true);

    // Enable 0-RTT.
    config.enable_early_data();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    let local_addr = socket.local_addr().unwrap();

    info!("DoQ server ready to accept connections");

    loop {
        // Find the shorter timeout from all the active connections.
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets.
        'read: loop {
            if events.is_empty() {
                debug!("timed out");
                clients.values_mut().for_each(|c| c.conn.on_timeout());
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

            debug!("got {} bytes from {}", len, from);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,
                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup or create a connection.
            let client = if !clients.contains_key(&hdr.dcid)
                && !clients.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();
                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }
                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);
                let scid = quiche::ConnectionId::from_ref(&scid);

                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }
                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                let scid = hdr.dcid.clone();

                debug!("New DoQ connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                let client = Client {
                    conn,
                    partial_queries: HashMap::new(),
                };

                clients.insert(scid.clone(), client);
                clients.get_mut(&scid).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,
                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            // Process the incoming packet.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,
                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            debug!("{} processed {} bytes", client.conn.trace_id(), read);

            // Process 0-RTT data if available.
            if client.conn.is_in_early_data() {
                debug!("{} processing 0-RTT data", client.conn.trace_id());

                for stream_id in client.conn.readable() {
                    handle_stream(client, stream_id, true);
                }
            }

            if client.conn.is_established() {
                // Handle readable streams.
                for stream_id in client.conn.readable() {
                    handle_stream(client, stream_id, false);
                }
            }
        }

        // Generate outgoing QUIC packets.
        for client in clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.conn.trace_id());
                        break;
                    },
                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);
                        client
                            .conn
                            .close(
                                false,
                                DoqError::InternalError.to_wire(),
                                b"fail",
                            )
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

                debug!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            if c.conn.is_closed() {
                info!(
                    "{} connection closed {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }
            !c.conn.is_closed()
        });
    }
}

/// Handle incoming data on a stream.
fn handle_stream(client: &mut Client, stream_id: u64, is_early_data: bool) {
    let conn_id = client.conn.trace_id().to_string();
    debug!("{} stream {} is readable", conn_id, stream_id);

    let mut buf = [0; 65535];
    let mut stream_data = Vec::new();
    let mut expected_len = None;
    let mut is_complete = false;

    // Check if we have partial data
    if let Some(partial) = client.partial_queries.get(&stream_id) {
        stream_data = partial.data.clone();
        expected_len = partial.expected_len;
    }

    // Read data from the stream.
    loop {
        match client.conn.stream_recv(stream_id, &mut buf) {
            Ok((read, fin)) => {
                if read > 0 {
                    stream_data.extend_from_slice(&buf[..read]);
                    debug!(
                        "{} received {} bytes on stream {} (total: {})",
                        conn_id,
                        read,
                        stream_id,
                        stream_data.len()
                    );
                }

                // Check if we have enough data to parse the length.
                if expected_len.is_none() && stream_data.len() >= 2 {
                    let len = u16::from_be_bytes([stream_data[0], stream_data[1]])
                        as usize;
                    expected_len = Some(2 + len);
                    debug!(
                        "{} expecting {} bytes total on stream {}",
                        conn_id,
                        2 + len,
                        stream_id
                    );
                }

                // Check if we have a complete DNS message.
                if let Some(expected) = expected_len {
                    if stream_data.len() >= expected || fin {
                        if stream_data.len() < expected && fin {
                            error!(
                                "{} incomplete DNS message on stream {}: {} < {}",
                                conn_id,
                                stream_id,
                                stream_data.len(),
                                expected
                            );
                            client
                                .conn
                                .stream_send(
                                    stream_id,
                                    b"\x00\x00", // Empty response
                                    true,
                                )
                                .ok();
                            client.partial_queries.remove(&stream_id);
                            return;
                        }

                        is_complete = true;
                        break;
                    }
                }

                if read == 0 || fin {
                    break;
                }
            },
            Err(quiche::Error::Done) => break,
            Err(e) => {
                error!("{} stream recv error: {:?}", conn_id, e);
                break;
            },
        }
    }

    // Update partial state if not complete
    if !is_complete {
        if stream_data.is_empty() {
            return;
        }

        client.partial_queries.insert(
            stream_id,
            PartialDnsQuery {
                data: stream_data,
                expected_len,
            },
        );
        return;
    }

    // Process complete message
    client.partial_queries.remove(&stream_id);

    // Parse and handle the DNS query.
    match read_dns_message(&stream_data) {
        Ok((dns_query, _)) => {
            handle_dns_query(client, stream_id, dns_query, is_early_data);
        },
        Err(e) => {
            error!("{} failed to parse DNS message: {}", conn_id, e);
            client
                .conn
                .stream_send(
                    stream_id,
                    b"\x00\x00", // Empty response
                    true,
                )
                .ok();
        },
    }
}

/// Handle a complete DNS query.
fn handle_dns_query(
    client: &mut Client, stream_id: u64, query: &[u8], is_early_data: bool,
) {
    let conn_id = client.conn.trace_id().to_string();
    let msg = Message::from_octets(query).unwrap();
    let id = msg.header().id();
    let opcode = msg.header().opcode();

    // Check message ID.
    if id != 0 {
        warn!("{} received DNS query with non-zero ID: {}", conn_id, id);
    }

    // Check opcode for 0-RTT.
    if is_early_data && !is_replayable_opcode(opcode.into()) {
        error!(
            "{} non-replayable opcode {:?} in 0-RTT data",
            conn_id, opcode
        );
        // Send REFUSED response.
        let response = build_dns_response(query, Rcode::masked_from_int(5))
            .unwrap_or_else(|_| vec![]);
        send_dns_response(client, stream_id, &response);
        return;
    }

    info!(
        "{} received DNS query on stream {} ({} bytes)",
        conn_id,
        stream_id,
        query.len()
    );

    // For this example, we'll send a simple NXDOMAIN response.
    // In a real implementation, you would process the query and generate appropriate responses.
    let response = build_dns_response(query, Rcode::masked_from_int(3))
        .unwrap_or_else(|e| {
            error!("{} failed to build response: {}", conn_id, e);
            vec![]
        });
    send_dns_response(client, stream_id, &response);
}

/// Send a DNS response on a stream.
fn send_dns_response(client: &mut Client, stream_id: u64, response: &[u8]) {
    let conn_id = client.conn.trace_id().to_string();

    // Prepare the response with length prefix.
    let mut dns_message = Vec::new();
    if let Err(e) = write_dns_message(&mut dns_message, response) {
        error!("{} failed to format DNS response: {}", conn_id, e);
        return;
    }

    match client.conn.stream_send(stream_id, &dns_message, true) {
        Ok(written) => {
            if written < dns_message.len() {
                error!(
                    "{} failed to send complete response: {} < {}",
                    conn_id,
                    written,
                    dns_message.len()
                );
            } else {
                info!(
                    "{} sent DNS response on stream {} ({} bytes)",
                    conn_id, stream_id, written
                );
            }
        },
        Err(e) => {
            error!("{} failed to send response: {:?}", conn_id, e);
        },
    }
}

// Note: build_nxdomain_response and build_error_response have been removed
// in favor of using the domain crate's build_dns_response function

/// Generate a stateless retry token.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validate a stateless retry token.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}
