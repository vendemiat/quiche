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

//! DoQ controller orchestration and transaction concurrency.

use std::sync::Arc;

use domain::base::iana::exterr::ExtendedErrorCode;
use domain::base::iana::Rcode;
use domain::base::Message;
use tokio_quiche::doq::is_replayable_opcode;
use tokio_quiche::doq::DoqController;
use tokio_quiche::doq::DoqError;
use tokio_quiche::doq::DoqEvent;
use tokio_quiche::doq::DoqResponder;

use crate::config::ServerConfig;
use crate::dns::DoqDnsQuery;
use crate::dns::DoqDnsResponse;
use crate::request::Request;
use crate::upstream::Upstream;
use crate::upstream::UpstreamError;

/// Process DoQ events for one connection.
pub(crate) async fn serve<U>(
    mut controller: DoqController, upstream: Arc<U>, config: ServerConfig,
) where
    U: Upstream + 'static,
{
    let Some(mut events) = controller.take_event_receiver() else {
        return;
    };

    while let Some(event) = events.recv().await {
        if let DoqEvent::Query {
            data,
            is_0rtt,
            responder,
        } = event
        {
            let query = match Message::from_octets(data)
                .ok()
                .and_then(|message| DoqDnsQuery::try_from(message).ok())
            {
                Some(query) => query,
                None => {
                    controller.close_connection(
                        DoqError::ProtocolError,
                        b"invalid dns query".to_vec(),
                    );
                    continue;
                },
            };

            if is_0rtt && !is_replayable_opcode(query.opcode()) {
                // RFC 9250, Section 4.5: "Servers supporting 0-RTT MUST NOT
                // immediately process non-replayable transactions received in
                // 0-RTT data but instead MUST adopt one of the following
                // behaviors:" https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
                tokio::spawn(send_terminal(
                    responder,
                    query.failed_reponse(
                        Rcode::REFUSED,
                        vec![ExtendedErrorCode::from_int(26).into()],
                    ),
                ));
                continue;
            }

            let upstream = Arc::clone(&upstream);
            let config = config.clone();
            tokio::spawn(async move {
                let request = match Request::start(&config, query) {
                    Ok(request) => request,
                    Err(_) => {
                        send_terminal(responder, Err(())).await;
                        return;
                    },
                };
                match request.respond(upstream.as_ref(), &responder).await {
                    Ok(()) => {},
                    Err(UpstreamError::Cancelled) => {},
                    Err(error) => {
                        let ede = matches!(
                            error,
                            UpstreamError::DeadlineExceeded(_)
                                | UpstreamError::Failed(_)
                                | UpstreamError::Network(_)
                        )
                        .then(|| ExtendedErrorCode::NETWORK_ERROR.into());
                        send_terminal(
                            responder,
                            request.failed_reponse(
                                Rcode::SERVFAIL,
                                ede.into_iter().collect(),
                            ),
                        )
                        .await;
                    },
                }
            });
        }
    }
}

async fn send_terminal<E>(
    responder: DoqResponder, response: Result<DoqDnsResponse<bytes::Bytes>, E>,
) {
    if let Ok(response) = response {
        if responder.send(response.into_bytes(), true).await.is_ok() {
            return;
        }
    }

    let _ = responder.reset(DoqError::InternalError).await;
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    use futures::StreamExt;
    use tokio::net::UdpSocket;
    use tokio::sync::Notify;
    use tokio_quiche::doq::DoqServerDriver;
    use tokio_quiche::quic::connect_with_config;
    use tokio_quiche::quic::HandshakeInfo;
    use tokio_quiche::quic::QuicheConnection;
    use tokio_quiche::settings::CertificateKind;
    use tokio_quiche::settings::Hooks;
    use tokio_quiche::settings::TlsCertificatePaths;
    use tokio_quiche::socket::Socket;
    use tokio_quiche::ApplicationOverQuic;
    use tokio_quiche::ConnectionParams;
    use tokio_quiche::QuicResult;

    use super::*;
    use crate::dns::query;
    use crate::doq_settings;
    use crate::upstream::ResponseSequence;

    #[derive(Default)]
    struct PendingUpstream {
        /// Count resolver invocations for the test assertion.
        calls: AtomicUsize,
        /// Notify the test after the resolve future starts executing.
        started: Notify,
        /// Notify the test when cancellation drops the resolve future.
        dropped: Notify,
    }

    /// Notify the test when Rust drops the pending future's local guard.
    struct DropSignal<'a>(&'a Notify);

    impl Drop for DropSignal<'_> {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    impl Upstream for PendingUpstream {
        fn resolve<'a>(
            &'a self, _query: &'a Message<bytes::Bytes>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResponseSequence, UpstreamError>>
                    + Send
                    + 'a,
            >,
        > {
            // Record the upstream operation created for the client query.
            self.calls.fetch_add(1, Ordering::Relaxed);

            Box::pin(async move {
                // Keep an observable guard alive until cancellation drops this
                // pending future.
                let _drop_signal = DropSignal(&self.dropped);
                // Signal only after the resolve future begins executing.
                self.started.notify_one();
                // Keep the upstream operation active until cancellation.
                future::pending().await
            })
        }
    }

    #[derive(Clone)]
    struct ClientControl {
        close: Arc<Notify>,
    }

    impl ClientControl {
        fn close(&self) {
            self.close.notify_one();
        }
    }

    struct QueryClient {
        control: ClientControl,
    }

    impl QueryClient {
        fn new() -> (Self, ClientControl) {
            let control = ClientControl {
                close: Arc::new(Notify::new()),
            };

            // Return a separate handle so the test can close the client after
            // moving `QueryClient` into the connection worker.
            (
                Self {
                    control: control.clone(),
                },
                control,
            )
        }
    }

    impl ApplicationOverQuic for QueryClient {
        fn on_conn_established(
            &mut self, qconn: &mut QuicheConnection, _info: &HandshakeInfo,
        ) -> QuicResult<()> {
            let query = query(0, domain::base::iana::Rtype::A);
            let mut wire = Vec::new();
            quiche::doq::write_dns_message(&mut wire, &query).unwrap();
            qconn.stream_send(0, &wire, true)?;
            Ok(())
        }

        fn should_act(&self) -> bool {
            // Keep polling `wait_for_data` so the test can close the
            // connection.
            true
        }

        fn wait_for_data(
            &mut self, qconn: &mut QuicheConnection,
        ) -> impl Future<Output = QuicResult<()>> + Send {
            let close = Arc::clone(&self.control.close);
            async move {
                // Wait until the test requests client disconnection.
                close.notified().await;
                // Close here because this callback owns mutable access to the
                // raw QUIC connection.
                let _ = qconn.close(false, 0, b"test complete");
                Ok(())
            }
        }

        // Ignore inbound application data in this send-and-close test client.
        fn process_reads(
            &mut self, _qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            Ok(())
        }

        // Leave writes empty; the established callback sends the query and
        // `wait_for_data` closes the connection.
        fn process_writes(
            &mut self, _qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn cancels_pending_upstream_when_client_closes_connection() {
        const TEST_TIMEOUT: Duration = Duration::from_secs(5);

        let upstream = Arc::new(PendingUpstream::default());

        // Use loopback UDP because the public server listener only accepts
        // UDP-backed `QuicListener`s.
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let settings = doq_settings(true);
        let max_streams_bidi = settings.initial_max_streams_bidi;
        let mut listeners = tokio_quiche::listen(
            [server_socket],
            ConnectionParams::new_server(
                settings,
                TlsCertificatePaths {
                    cert: "examples/cert.crt",
                    private_key: "examples/cert.key",
                    kind: CertificateKind::X509,
                },
                Hooks::default(),
            ),
            tokio_quiche::metrics::DefaultMetrics,
        )
        .unwrap();
        let mut listener = listeners.remove(0);
        let server_upstream = Arc::clone(&upstream);
        let server_task = tokio::spawn(async move {
            let connection = listener.next().await.unwrap().unwrap();
            let (driver, controller) = DoqServerDriver::new(max_streams_bidi);
            connection.start(driver);
            serve(controller, server_upstream, ServerConfig {
                transaction_timeout: Duration::from_secs(30),
            })
            .await;
        });

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_socket.connect(server_addr).await.unwrap();
        let (client, control) = QueryClient::new();
        let mut client_settings = doq_settings(true);
        client_settings.verify_peer = false;
        let _connection = tokio::time::timeout(
            TEST_TIMEOUT,
            connect_with_config(
                Socket::try_from(client_socket).unwrap(),
                Some("localhost"),
                &ConnectionParams::new_client(
                    client_settings,
                    None,
                    Hooks::default(),
                ),
                client,
            ),
        )
        .await
        .expect("client connection should complete")
        .unwrap();

        tokio::time::timeout(TEST_TIMEOUT, upstream.started.notified())
            .await
            .expect("upstream resolve should start");
        // Close the client connection so driver teardown closes the real
        // responder and cancels the pending upstream future.
        control.close();

        tokio::time::timeout(TEST_TIMEOUT, upstream.dropped.notified())
            .await
            .expect("upstream future should be dropped before its deadline");
        assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
        tokio::time::timeout(TEST_TIMEOUT, server_task)
            .await
            .expect("server task should stop after the client closes")
            .unwrap();
    }
}
