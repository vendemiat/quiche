// Copyright (C) 2026, Cloudflare, Inc.
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

//! Test-only helpers for the DoQ driver's unit tests, mirroring
//! `http3::driver::test_utils`'s `DriverTestHelper`.

use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use futures::FutureExt as _;
use quiche::doq;
use tokio::sync::mpsc::error::TryRecvError;

use crate::buf_factory::BufFactory;
use crate::doq::DoqController;
use crate::doq::DoqEvent;
use crate::doq::DoqResponder;
use crate::doq::DoqServerDriver;
use crate::quic::HandshakeInfo;
use crate::ApplicationOverQuic as _;

type Pipe = quiche::test_utils::Pipe<BufFactory>;

pub fn default_quiche_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_application_protos(&[doq::DOQ_ALPN]).unwrap();
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(10_000);
    config.set_initial_max_stream_data_bidi_remote(10_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(5);
    config.verify_peer(false);
    config
}

/// Wraps a `Pipe` with a `DoqServerDriver` on the server side and a raw
/// `doq::Connection` (client role) as the peer. The peer's `Connection` has
/// no query-sending API of its own (see `quiche::doq::connection`'s own
/// tests): queries are written directly onto a fresh client-initiated bidi
/// stream via [`Self::peer_send_query`].
pub struct DoqDriverTestHelper {
    pub pipe: Pipe,
    pub driver: DoqServerDriver,
    pub controller: DoqController,
    pub peer: doq::Connection,
    next_client_stream_id: u64,
}

impl DoqDriverTestHelper {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_pipe(Pipe::with_config_and_buf(&mut default_quiche_config())?)
    }

    pub fn with_pipe(mut pipe: Pipe) -> anyhow::Result<Self> {
        pipe.handshake().context("handshake")?;

        // The client's own `peer_streams_left_bidi()`, read before it has
        // opened any stream, is exactly the server's negotiated
        // `initial_max_streams_bidi`: it's derived from the server's
        // advertised transport parameter (`update_peer_max_streams_bidi`,
        // `quiche/src/lib.rs`, called with `peer_params
        // .initial_max_streams_bidi` once the handshake completes).
        let initial_max_streams_bidi = pipe.client.peer_streams_left_bidi();

        let (mut driver, controller) =
            DoqServerDriver::new(initial_max_streams_bidi);
        driver
            .on_conn_established(
                &mut pipe.server,
                &HandshakeInfo::new(Instant::now(), None),
            )
            .map_err(anyhow::Error::from_boxed)
            .context("on_conn_established")?;

        let peer = doq::Connection::with_transport(&pipe.client)
            .context("create doq peer connection")?;

        Ok(Self {
            pipe,
            driver,
            controller,
            peer,
            next_client_stream_id: 0,
        })
    }

    /// Runs one iteration of the driver's worker-loop steps, without
    /// advancing the pipe: `process_reads`, `process_writes`, then a
    /// single non-blocking poll of `wait_for_data`.
    pub fn work_loop_iter(&mut self) -> anyhow::Result<()> {
        self.driver
            .process_reads(&mut self.pipe.server)
            .map_err(anyhow::Error::from_boxed)
            .context("process_reads")?;
        self.driver
            .process_writes(&mut self.pipe.server)
            .map_err(anyhow::Error::from_boxed)
            .context("process_writes")?;
        tokio::task::unconstrained(
            self.driver.wait_for_data(&mut self.pipe.server),
        )
        .now_or_never()
        .unwrap_or(Ok(()))
        .map_err(anyhow::Error::from_boxed)
        .context("wait_for_data")?;
        Ok(())
    }

    /// Advances the pipe and runs the worker loop enough times for pending
    /// work on both ends to settle into a fixed point.
    pub fn advance_and_run_loop(&mut self) -> anyhow::Result<()> {
        for _ in 0..3 {
            self.pipe.advance()?;
            self.work_loop_iter()?;
        }
        self.pipe.advance()?;
        Ok(())
    }

    /// Opens a fresh client-initiated bidi stream and sends `data` on it,
    /// framed with the DoQ length prefix and FIN, exactly as a real DoQ
    /// query is sent (RFC 9250
    /// <https://datatracker.ietf.org/doc/html/rfc9250#section-4.2>: one
    /// query per stream). Returns the stream ID used.
    pub fn peer_send_query(&mut self, data: &[u8]) -> anyhow::Result<u64> {
        let stream_id = self.next_stream_id();

        let mut wire = Vec::new();
        doq::write_dns_message(&mut wire, data).unwrap();
        self.pipe.client.stream_send(stream_id, &wire, true)?;

        Ok(stream_id)
    }

    /// Returns a fresh client-initiated bidi stream ID (0, 4, 8, ...)
    /// without sending anything on it yet, for tests that need to control
    /// the write calls themselves.
    pub fn next_stream_id(&mut self) -> u64 {
        let stream_id = self.next_client_stream_id;
        self.next_client_stream_id += 4;
        stream_id
    }

    /// Tries to receive the next `DoqEvent` from the controller.
    pub fn try_recv_event(&mut self) -> Result<DoqEvent, TryRecvError> {
        self.controller
            .event_receiver_mut()
            .expect("event receiver already taken")
            .try_recv()
    }

    /// Receives the next `DoqEvent`, asserting it's a `Query`, and returns
    /// its fields.
    pub fn expect_query_event(&mut self) -> (Bytes, bool, DoqResponder) {
        match self.try_recv_event() {
            Ok(DoqEvent::Query {
                data,
                is_0rtt,
                responder,
            }) => (data, is_0rtt, responder),
            other => panic!("expected DoqEvent::Query, got {other:?}"),
        }
    }
}
