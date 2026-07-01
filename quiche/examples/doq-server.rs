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
//! This example demonstrates a simple DoQ server according to
//! <https://datatracker.ietf.org/doc/html/rfc9250>.

// TODO: Use DoH to 1.1.1.1 to process queries
// TODO: https://datatracker.ietf.org/doc/html/rfc9250#name-address-validation
// TODO: https://datatracker.ietf.org/doc/html/rfc9250#name-padding

#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::net;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;
const MAX_CLIENTS: usize = 1024;

// Upper bound on the total bytes a single client may buffer across all of its
// incomplete (partial) DNS queries. QUIC flow control already caps each stream
// at 65537 bytes, but without an application-level limit a slow-loris client
// could open many streams and dribble bytes to pin ~6.5 MB per connection. Cap
// the aggregate so abandoned/slow streams cannot accumulate unbounded memory;
// exceeding it is treated as DOQ_EXCESSIVE_LOAD
// (<https://datatracker.ietf.org/doc/html/rfc9250#section-4.3>).
const MAX_PARTIAL_QUERY_BYTES: usize = 256 * 1024;

use quiche::doq::*;

mod doq_common;
use doq_common::*;

use domain::base::iana::exterr::ExtendedErrorCode;
use domain::base::iana::Rcode;
use domain::base::message::Message;

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

    if args.len() > 3 {
        println!("Usage: {cmd} [address:port] [cert_path] [key_path]");
        println!();
        println!("Defaults: 127.0.0.1:{}, quiche/examples/cert.crt, quiche/examples/cert.key", DOQ_PORT);
        return;
    }

    let listen_addr = args
        .next()
        .unwrap_or_else(|| format!("127.0.0.1:{}", DOQ_PORT));

    let cert_path = args
        .next()
        .unwrap_or_else(|| "quiche/examples/cert.crt".to_string());
    let key_path = args
        .next()
        .unwrap_or_else(|| "quiche/examples/cert.key".to_string());

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

    // Load certificate and key.
    config.load_cert_chain_from_pem_file(&cert_path).unwrap();
    config.load_priv_key_from_pem_file(&key_path).unwrap();

    config.set_max_idle_timeout(30000); // 30 seconds
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    // DNS messages are at most 65535 bytes + 2-byte length prefix. Cap
    // per-stream flow control at the protocol maximum so a misbehaving client
    // cannot force more than one max-size message worth of buffering per
    // stream.
    // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.6>
    // <https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2>
    config.set_initial_max_stream_data_bidi_remote(65537);
    config.set_initial_max_stream_data_uni(0); // DoQ doesn't use unidirectional streams
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0);
    // Disable migration for privacy.
    // <https://datatracker.ietf.org/doc/html/rfc9250#section-5.5.4>
    config.set_disable_active_migration(true);

    // Enable 0-RTT.
    //
    // WARNING: 0-RTT data is replayable by an on-path attacker. This example
    // gates non-replayable opcodes via `is_replayable_opcode` and otherwise
    // just returns NXDOMAIN with no backend work, so replay has no effect here.
    // In production, even the opcodes permitted in 0-RTT are not
    // consequence-free when replayed: a replayed QUERY still forces repeated
    // (potentially expensive) resolution/validation and skews rate-limit and
    // metrics accounting, and a replayed NOTIFY can repeatedly trigger zone
    // transfers. A production server MUST bound replay-induced load with an
    // anti-replay cache and/or rate limiting before acting on 0-RTT queries.
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

        // TODO: handle DoqError::RequestCancelled and STOP_SENDING
        // A STOP_SENDING frame requests that the receiving endpoint send a
        // RESET_STREAM frame. An endpoint that receives a STOP_SENDING
        // frame MUST send a RESET_STREAM frame if the stream is in the "
        // Ready" or "Send" state. If the stream is in the "Data Sent" state, the
        // endpoint MAY defer sending the RESET_STREAM frame until the packets
        // containing outstanding data are acknowledged or declared lost.
        // If any outstanding data is declared lost, the endpoint SHOULD
        // send a RESET_STREAM frame instead of retransmitting the data.
        //
        // TODO: handle other DoQError
        //
        // TODO: Process SRVFAIL
        // If a server is incapable of sending a DNS response due to an internal
        // error, it SHOULD issue a QUIC RESET_STREAM frame. The error
        // code SHOULD be set to DOQ_INTERNAL_ERROR. The corresponding DNS
        // transaction MUST be abandoned.
        //
        // TODO: Handle all https://datatracker.ietf.org/doc/html/rfc9250#name-protocol-errors
        // TODO: https://datatracker.ietf.org/doc/html/rfc9250#name-alternative-error-codes

        // Read incoming UDP packets.
        'read: loop {
            if events.is_empty() {
                debug!("timed out");
                for c in clients.values_mut() {
                    if c.conn.timeout().is_some_and(|t| t.is_zero()) {
                        c.conn.on_timeout();
                    }
                }
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
            let client = if !clients.contains_key(&hdr.dcid) &&
                !clients.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if clients.len() >= MAX_CLIENTS {
                    warn!(
                        "rejecting new connection from {}: {} active",
                        from,
                        clients.len()
                    );
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

                let token = match hdr.token.as_ref() {
                    Some(t) => t,
                    None => {
                        error!("Initial packet missing token field");
                        continue 'read;
                    },
                };

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &from, &conn_id_seed);

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

                let odcid = validate_token(&from, token, &conn_id_seed);

                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                // After Retry the client's DCID must be the scid we
                // chose (length MAX_CONN_ID_LEN). A different length
                // means this Initial didn't come from our Retry path.
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
                to: local_addr,
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

            let is_early_data = client.conn.is_in_early_data();

            if is_early_data || client.conn.is_established() {
                for stream_id in client.conn.readable() {
                    handle_stream(client, stream_id, is_early_data, &mut buf);
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
///
/// `buf` is a caller-provided scratch buffer (reused across calls) used to
/// drain the stream, avoiding a 64 KiB stack allocation per invocation.
fn handle_stream(
    client: &mut Client, stream_id: u64, is_early_data: bool, buf: &mut [u8],
) {
    let conn_id = client.conn.trace_id().to_string();
    debug!("{} stream {} is readable", conn_id, stream_id);

    // Take ownership of any previously buffered partial data.
    let (mut stream_data, mut expected_len) = client
        .partial_queries
        .remove(&stream_id)
        .map(|p| (p.data, p.expected_len))
        .unwrap_or_default();

    // Read all available data from the stream.
    let mut fin = false;
    loop {
        match client.conn.stream_recv(stream_id, buf) {
            Ok((0, _)) => break,
            Ok((n, f)) => {
                stream_data.extend_from_slice(&buf[..n]);
                if f {
                    fin = true;
                    break;
                }
            },
            Err(quiche::Error::Done) => break,
            Err(e) => {
                error!("{} stream recv error: {:?}", conn_id, e);
                return;
            },
        }
    }

    // Parse the 2-octet length prefix if not yet known.
    if expected_len.is_none() && stream_data.len() >= 2 {
        let len = u16::from_be_bytes([stream_data[0], stream_data[1]]) as usize;
        expected_len = Some(2 + len);
    }

    // Check whether we have a complete message.
    let is_complete =
        expected_len.is_some_and(|expected| stream_data.len() >= expected);

    if !is_complete {
        if fin {
            // Stream FIN'd before the full message arrived — protocol error.
            error!("{} incomplete DNS message on stream {}", conn_id, stream_id);
            client
                .conn
                .close(
                    true,
                    DoqError::ProtocolError.to_wire(),
                    b"incomplete dns message",
                )
                .ok();
            return;
        }

        // Still waiting for more data; save partial state.
        if !stream_data.is_empty() {
            // Enforce a per-client cap on buffered partial-query bytes so a
            // slow-loris client cannot pin unbounded memory across many
            // streams. The entry for this stream was already removed above, so
            // the running total excludes it.
            let buffered: usize =
                client.partial_queries.values().map(|p| p.data.len()).sum();

            if buffered + stream_data.len() > MAX_PARTIAL_QUERY_BYTES {
                error!(
                    "{} exceeded partial-query buffer limit ({} bytes)",
                    conn_id, MAX_PARTIAL_QUERY_BYTES
                );
                client
                    .conn
                    .close(
                        true,
                        DoqError::ExcessiveLoad.to_wire(),
                        b"excessive buffered data",
                    )
                    .ok();
                return;
            }

            client.partial_queries.insert(stream_id, PartialDnsQuery {
                data: stream_data,
                expected_len,
            });
        }
        return;
    }

    // Process the complete message.
    match read_dns_message(&stream_data) {
        Ok((dns_query, _)) => {
            handle_dns_query(client, stream_id, dns_query, is_early_data);
        },
        Err(e) => {
            error!("{} failed to parse DNS message: {}", conn_id, e);
            client
                .conn
                .close(
                    true,
                    DoqError::ProtocolError.to_wire(),
                    b"dns parse error",
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
    let msg = match Message::from_octets(query) {
        Ok(m) => m,
        Err(e) => {
            // The wire framing was valid but the DNS payload is malformed.
            // This should abort the connection with DOQ_PROTOCOL_ERROR; for
            // this example we just log and bail so a hostile client can't panic
            // the server.
            error!("{} malformed DNS query: {}", conn_id, e);
            return;
        },
    };
    let id = msg.header().id();
    let opcode = msg.header().opcode();

    // Check message ID: ID 0 is required; a non-zero ID is a fatal protocol
    // error.
    // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1>
    if id != 0 {
        error!("{} received DNS query with non-zero ID: {}", conn_id, id);
        client
            .conn
            .close(
                true,
                DoqError::ProtocolError.to_wire(),
                b"non-zero message id",
            )
            .ok();
        return;
    }

    // Check opcode for 0-RTT.
    if is_early_data && !is_replayable_opcode(opcode.into()) {
        error!(
            "{} non-replayable opcode {:?} in 0-RTT data",
            conn_id, opcode
        );
        // Reply with REFUSED + EDE "Too Early" (code 26).
        // <https://datatracker.ietf.org/doc/html/rfc9250#section-4.5>
        // <https://datatracker.ietf.org/doc/html/rfc9250#section-8.3>
        let response = build_dns_response(query, Rcode::REFUSED, vec![
            ExtendedErrorCode::from_int(26),
        ])
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
    // In a real implementation, you would process the query and generate
    // appropriate responses.
    let response = match build_dns_response(query, Rcode::NXDOMAIN, vec![]) {
        Ok(r) => r,
        Err(e) => {
            error!("{} failed to build response: {}", conn_id, e);
            client
                .conn
                .stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Write,
                    DoqError::InternalError.to_wire(),
                )
                .ok();
            return;
        },
    };
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
        Ok(written) if written < dns_message.len() => {
            // quiche accepted only part of the data; the remainder (and FIN)
            // are lost because this example does not buffer for retry.
            // Close the connection with DOQ_INTERNAL_ERROR rather than leaving
            // the stream in a half-sent state.
            error!(
                "{} partial stream_send on stream {} ({}/{}): closing \
                 connection",
                conn_id,
                stream_id,
                written,
                dns_message.len()
            );
            client
                .conn
                .close(true, DoqError::InternalError.to_wire(), b"partial send")
                .ok();
        },
        Ok(written) => {
            info!(
                "{} sent DNS response on stream {} ({} bytes)",
                conn_id, stream_id, written
            );
        },
        Err(e) => {
            error!("{} failed to send response: {:?}", conn_id, e);
        },
    }
}

/// Generate a stateless retry token.
///
/// The token is HMAC-signed with the server's connection ID key so that
/// an attacker cannot forge a valid token for a different source address.
fn mint_token(
    hdr: &quiche::Header, src: &net::SocketAddr, key: &ring::hmac::Key,
) -> Vec<u8> {
    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    let mut body = Vec::new();
    body.extend_from_slice(&addr);
    body.extend_from_slice(&hdr.dcid);

    let tag = ring::hmac::sign(key, &body);

    let mut token = Vec::new();
    token.extend_from_slice(tag.as_ref());
    token.extend_from_slice(&body);
    token
}

/// Validate a stateless retry token and return the original DCID.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8], key: &ring::hmac::Key,
) -> Option<quiche::ConnectionId<'a>> {
    let tag_len = ring::hmac::HMAC_SHA256.digest_algorithm().output_len();
    if token.len() < tag_len {
        return None;
    }

    let (tag, body) = token.split_at(tag_len);

    // Verify the HMAC to prevent token forgery.
    if ring::hmac::verify(key, body, tag).is_err() {
        return None;
    }

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if body.len() < addr.len() || &body[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&body[addr.len()..]))
}
