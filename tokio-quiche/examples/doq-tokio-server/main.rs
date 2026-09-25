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

//! Request core for the Tokio DoQ server.

mod config;
mod dns;
mod request;
mod server;
mod upstream;

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use quiche::doq::MAX_DOQ_MESSAGE_LEN;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio_quiche::doq::DoqServerDriver;
use tokio_quiche::doq::DOQ_ALPN;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::settings::CertificateKind;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;

use crate::config::ServerConfig;
use crate::config::DEFAULT_MAX_CONCURRENT_TRANSACTIONS;
use crate::server::serve;
use crate::upstream::UdpUpstream;

#[derive(Debug, Parser)]
struct Args {
    /// Address on which to listen for DoQ connections.
    #[arg(long, default_value = "127.0.0.1:8853")]
    address: String,

    /// Address of the UDP DNS upstream resolver.
    #[arg(long)]
    upstream_address: SocketAddr,

    /// Maximum number of concurrent upstream transactions across connections.
    #[arg(
        long,
        default_value_t = NonZeroUsize::new(DEFAULT_MAX_CONCURRENT_TRANSACTIONS)
            .expect("default limit must be nonzero")
    )]
    max_concurrent_transactions: NonZeroUsize,

    /// Path to the server TLS certificate.
    #[arg(long, default_value = "examples/cert.crt")]
    tls_cert_path: String,

    /// Path to the server TLS private key.
    #[arg(long, default_value = "examples/cert.key")]
    tls_private_key_path: String,

    /// Disable acceptance of 0-RTT queries.
    #[arg(long)]
    disable_0rtt: bool,
}

fn doq_settings(disable_0rtt: bool) -> QuicSettings {
    let mut settings = QuicSettings::default();
    settings.alpn = vec![DOQ_ALPN.to_vec()];
    settings.enable_dgram = false;
    settings.enable_early_data = !disable_0rtt;
    settings.initial_max_stream_data_bidi_local = MAX_DOQ_MESSAGE_LEN as u64;
    settings.initial_max_stream_data_bidi_remote = MAX_DOQ_MESSAGE_LEN as u64;
    settings.initial_max_streams_uni = 0;
    settings
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();
    let socket = UdpSocket::bind(&args.address)
        .await
        .expect("DoQ UDP socket should be bindable");
    let settings = doq_settings(args.disable_0rtt);
    let max_streams_bidi = settings.initial_max_streams_bidi;
    let upstream = Arc::new(UdpUpstream::new(args.upstream_address));
    let config = ServerConfig {
        concurrent_transactions: Arc::new(Semaphore::new(
            args.max_concurrent_transactions.get(),
        )),
        ..ServerConfig::default()
    };

    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            settings,
            TlsCertificatePaths {
                cert: &args.tls_cert_path,
                private_key: &args.tls_private_key_path,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        ),
        DefaultMetrics,
    )
    .expect("DoQ listener should be constructible");

    while let Some(connection) = listeners[0].next().await {
        let Ok(connection) = connection else {
            continue;
        };
        let (driver, controller) = DoqServerDriver::new(max_streams_bidi);
        connection.start(driver);
        tokio::spawn(serve(controller, Arc::clone(&upstream), config.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enables_early_data_unless_disabled() {
        assert!(doq_settings(false).enable_early_data);
        assert!(!doq_settings(true).enable_early_data);
    }
}
