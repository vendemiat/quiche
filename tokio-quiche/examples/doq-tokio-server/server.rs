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
                    query.failed_reponse(Rcode::REFUSED, vec![
                        ExtendedErrorCode::from_int(26).into(),
                    ]),
                ));
                continue;
            }

            if query.is_xfr() {
                // The proxy does not forward zone transfers.
                // Answer AXFR and IXFR queries with NOTIMP directly.
                tokio::spawn(send_terminal(
                    responder,
                    query.failed_reponse(Rcode::NOTIMP, vec![]),
                ));
                continue;
            }

            let upstream = Arc::clone(&upstream);
            let config = config.clone();
            tokio::spawn(async move {
                let request =
                    match Request::start(&config, query, upstream.as_ref()) {
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
                        // Attach EDE 23 only to deadline and network errors,
                        let ede = matches!(
                            error,
                            UpstreamError::DeadlineExceeded(_) |
                                UpstreamError::Network(_)
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

/// Send a final DNS response or reset the DoQ stream if delivery fails.
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
    use std::collections::HashMap;
    use std::future;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use domain::base::iana::Opcode;
    use domain::base::iana::OptRcode;
    use domain::base::iana::Rtype;
    use domain::base::MessageBuilder;
    use futures::StreamExt;
    use tokio::net::UdpSocket;
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;
    use tokio::task::JoinSet;
    use tokio::time::Instant;
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

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// BoringSSL `ssl_early_data_accepted`: the server accepted 0-RTT.
    const EARLY_DATA_ACCEPTED: u32 = 2;

    /// BoringSSL `ssl_early_data_unsupported_for_session`: the resumed
    /// session does not allow 0-RTT.
    const EARLY_DATA_UNSUPPORTED_FOR_SESSION: u32 = 7;

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
            let query = query(0, Rtype::A);
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

    /// Return a network error for every lookup and count the calls.
    #[derive(Default)]
    struct NetworkUpstream {
        calls: AtomicUsize,
    }

    impl Upstream for NetworkUpstream {
        fn resolve<'a>(
            &'a self, _query: &'a Message<Bytes>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResponseSequence, UpstreamError>>
                    + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Err(UpstreamError::Network(std::io::Error::other(
                    "test network failure",
                )))
            })
        }
    }

    /// Return malformed DNS bytes or a response to another question.
    struct InvalidUpstream {
        /// Select a valid response to a different question when true.
        mismatched: bool,
    }

    impl Upstream for InvalidUpstream {
        fn resolve<'a>(
            &'a self, query: &'a Message<Bytes>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResponseSequence, UpstreamError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let response = if self.mismatched {
                    let other = Message::from_octets(crate::dns::query(
                        query.header().id(),
                        Rtype::AAAA,
                    ))
                    .unwrap();
                    MessageBuilder::new_bytes()
                        .start_answer(&other, Rcode::NOERROR)?
                        .additional()
                        .into_message()
                        .into_octets()
                } else {
                    Bytes::from_static(b"invalid")
                };
                let (mut sender, sequence) = ResponseSequence::channel(1);
                sender.send(response, true).await?;
                Ok(sequence)
            })
        }
    }

    /// Return one response with an OPT record and the configured full RCODE.
    struct OptRcodeUpstream {
        rcode: OptRcode,
    }

    impl Upstream for OptRcodeUpstream {
        fn resolve<'a>(
            &'a self, query: &'a Message<Bytes>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResponseSequence, UpstreamError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let mut additional = MessageBuilder::new_bytes()
                    .start_answer(query, self.rcode.rcode())?
                    .additional();
                additional.opt(|opt| {
                    opt.set_rcode(self.rcode);
                    opt.padding(8)?;
                    Ok(())
                })?;
                let response = additional.into_message().into_octets();
                let (mut sender, sequence) = ResponseSequence::channel(1);
                sender.send(response, true).await?;
                Ok(sequence)
            })
        }
    }

    /// Answer every query with NOERROR and count the calls.
    ///
    /// When `hold` is set, the answer to a query of that type waits until the
    /// test calls `release.notify_one()`.
    #[derive(Default)]
    struct AnswerUpstream {
        /// Count resolver invocations for the test assertion.
        calls: AtomicUsize,
        hold: Option<Rtype>,
        /// Notify the test after a held query starts executing.
        held_started: Notify,
        /// Release the held answer.
        release: Notify,
    }

    impl Upstream for AnswerUpstream {
        fn resolve<'a>(
            &'a self, query: &'a Message<Bytes>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResponseSequence, UpstreamError>>
                    + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                let qtype = query.sole_question().unwrap().qtype();
                if self.hold == Some(qtype) {
                    self.held_started.notify_one();
                    self.release.notified().await;
                }
                let response = MessageBuilder::new_bytes()
                    .start_answer(query, Rcode::NOERROR)?
                    .additional()
                    .into_message()
                    .into_octets();
                let (mut sender, sequence) = ResponseSequence::channel(1);
                sender.send(response, true).await?;
                Ok(sequence)
            })
        }
    }

    /// Build a DNS query with the requested type, opcode, and EDNS mode.
    fn test_query(qtype: Rtype, opcode: Opcode, edns: bool) -> Bytes {
        let source = Message::from_octets(query(0, qtype)).unwrap();
        let mut builder = MessageBuilder::new_bytes();
        builder.header_mut().set_opcode(opcode);
        let mut questions = builder.question();
        for question in source.question() {
            questions.push(question.unwrap()).unwrap();
        }
        if edns {
            let mut additional = questions.additional();
            additional
                .opt(|opt| {
                    opt.set_udp_payload_size(1232);
                    Ok(())
                })
                .unwrap();
            additional.into_message().into_octets()
        } else {
            questions.into_message().into_octets()
        }
    }

    /// Start a loopback DoQ listener for the requested number of connections.
    async fn start_server<U: Upstream + 'static>(
        upstream: Arc<U>, config: ServerConfig, connections: usize,
    ) -> (SocketAddr, JoinHandle<()>) {
        start_server_with_0rtt(upstream, config, connections, false).await
    }

    /// Start a loopback DoQ listener with the given `--disable-0rtt` setting.
    async fn start_server_with_0rtt<U: Upstream + 'static>(
        upstream: Arc<U>, config: ServerConfig, connections: usize,
        disable_0rtt: bool,
    ) -> (SocketAddr, JoinHandle<()>) {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let settings = doq_settings(disable_0rtt);
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
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            for _ in 0..connections {
                let connection = listener.next().await.unwrap().unwrap();
                let (driver, controller) = DoqServerDriver::new(max_streams_bidi);
                connection.start(driver);
                let upstream = Arc::clone(&upstream);
                let config = config.clone();
                tasks.spawn(serve(controller, upstream, config));
            }
            while let Some(task) = tasks.join_next().await {
                task.unwrap();
            }
        });
        (server_addr, task)
    }

    /// Send every QUIC packet currently queued for the loopback server.
    async fn send_pending_packets(
        socket: &UdpSocket, conn: &mut quiche::Connection,
        server_addr: SocketAddr,
    ) {
        let mut outgoing = [0; 1500];
        loop {
            match conn.send(&mut outgoing) {
                Ok((len, _)) => {
                    socket.send_to(&outgoing[..len], server_addr).await.unwrap();
                },
                Err(quiche::Error::Done) => break,
                Err(error) => panic!("client packet send failed: {error:?}"),
            }
        }
    }

    /// Process one datagram or QUIC timeout before the shared deadline.
    async fn receive_packet(
        socket: &UdpSocket, conn: &mut quiche::Connection, deadline: Instant,
    ) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "client packet should arrive");
        let wait = conn.timeout().unwrap_or(remaining).min(remaining);
        let mut incoming = [0; 65_535];
        match tokio::time::timeout(wait, socket.recv_from(&mut incoming)).await {
            Ok(Ok((len, from))) => {
                conn.recv(&mut incoming[..len], quiche::RecvInfo {
                    from,
                    to: socket.local_addr().unwrap(),
                })
                .unwrap();
            },
            Ok(Err(error)) => panic!("client socket receive failed: {error}"),
            Err(_) => conn.on_timeout(),
        }
    }

    /// Process Retry and return before sending the post-Retry Initial.
    /// Leave the handshake pending so callers can queue 0-RTT data.
    async fn raw_client_after_retry(
        server_addr: SocketAddr, session: Option<&[u8]>, deadline: Instant,
    ) -> (UdpSocket, quiche::Connection, quiche::doq::Connection) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .set_application_protos(&[quiche::doq::DOQ_ALPN])
            .unwrap();
        config.verify_peer(false);
        config.enable_early_data();
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(65_535);
        config.set_initial_max_stream_data_bidi_remote(65_535);
        config.set_initial_max_streams_bidi(10);
        let scid = quiche::ConnectionId::from_ref(&[7; quiche::MAX_CONN_ID_LEN]);
        let mut conn = quiche::connect(
            Some("localhost"),
            &scid,
            local_addr,
            server_addr,
            &mut config,
        )
        .unwrap();
        if let Some(session) = session {
            conn.set_session(session).unwrap();
        }
        let doq = quiche::doq::Connection::with_transport(&conn).unwrap();
        let mut outgoing = [0; 1500];
        let (len, _) = conn.send(&mut outgoing).unwrap();
        socket.send_to(&outgoing[..len], server_addr).await.unwrap();
        let mut incoming = [0; 65_535];
        let (len, from) =
            tokio::time::timeout_at(deadline, socket.recv_from(&mut incoming))
                .await
                .expect("server Retry should arrive")
                .unwrap();
        let mut retry = incoming[..len].to_vec();
        assert_eq!(
            quiche::Header::from_slice(&mut retry, quiche::MAX_CONN_ID_LEN)
                .unwrap()
                .ty,
            quiche::Type::Retry
        );
        conn.recv(&mut incoming[..len], quiche::RecvInfo {
            from,
            to: local_addr,
        })
        .unwrap();
        (socket, conn, doq)
    }

    /// Complete a fresh client's handshake after Retry.
    async fn raw_established_client(
        server_addr: SocketAddr, deadline: Instant,
    ) -> (UdpSocket, quiche::Connection, quiche::doq::Connection) {
        let (socket, mut conn, doq) =
            raw_client_after_retry(server_addr, None, deadline).await;
        send_pending_packets(&socket, &mut conn, server_addr).await;
        while !conn.is_established() {
            receive_packet(&socket, &mut conn, deadline).await;
            send_pending_packets(&socket, &mut conn, server_addr).await;
        }
        (socket, conn, doq)
    }

    /// Collect DoQ events per stream until `stream_id` reaches stream FIN.
    async fn collect_until_finished(
        socket: &UdpSocket, conn: &mut quiche::Connection,
        doq: &mut quiche::doq::Connection, server_addr: SocketAddr,
        deadline: Instant, events: &mut HashMap<u64, Vec<quiche::doq::Event>>,
        stream_id: u64,
    ) {
        while !events
            .get(&stream_id)
            .is_some_and(|events| events.contains(&quiche::doq::Event::Finished))
        {
            receive_packet(socket, conn, deadline).await;
            loop {
                match doq.poll(conn) {
                    Ok((id, event)) => events.entry(id).or_default().push(event),
                    Err(quiche::doq::Error::Done) => break,
                    Err(error) => panic!("unexpected DoQ error: {error:?}"),
                }
            }
            // Flush tracked streams when QUIC makes room for query bytes.
            for id in conn.writable().collect::<Vec<_>>() {
                doq.flush_query(conn, id).unwrap();
            }
            send_pending_packets(socket, conn, server_addr).await;
        }
    }

    /// Collect DoQ events through stream FIN and close the client.
    async fn collect_response(
        socket: &UdpSocket, conn: &mut quiche::Connection,
        doq: &mut quiche::doq::Connection, server_addr: SocketAddr,
        deadline: Instant, stream_id: u64,
    ) -> Vec<quiche::doq::Event> {
        let mut events = HashMap::new();
        collect_until_finished(
            socket,
            conn,
            doq,
            server_addr,
            deadline,
            &mut events,
            stream_id,
        )
        .await;
        conn.close(false, 0, b"test complete").unwrap();
        send_pending_packets(socket, conn, server_addr).await;
        let events_stream_ids = events.keys().copied().collect::<Vec<_>>();
        assert_eq!(events_stream_ids, [stream_id]);
        events.remove(&stream_id).unwrap()
    }

    /// Send a query after a fresh handshake and wait for the server to close
    /// the connection.
    async fn send_raw_query_until_closed(
        server_addr: SocketAddr, query: &[u8],
    ) -> quiche::ConnectionError {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let (socket, mut conn, mut doq) =
            raw_established_client(server_addr, deadline).await;
        doq.send_query(&mut conn, query).unwrap();
        send_pending_packets(&socket, &mut conn, server_addr).await;
        while conn.peer_error().is_none() {
            receive_packet(&socket, &mut conn, deadline).await;
            send_pending_packets(&socket, &mut conn, server_addr).await;
        }
        conn.peer_error().unwrap().clone()
    }

    /// Send a query after a fresh handshake and collect its DoQ events.
    async fn send_raw_query(
        server_addr: SocketAddr, query: &Bytes,
    ) -> Vec<quiche::doq::Event> {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let (socket, mut conn, mut doq) =
            raw_established_client(server_addr, deadline).await;
        let stream_id = doq.send_query(&mut conn, query).unwrap();
        send_pending_packets(&socket, &mut conn, server_addr).await;
        collect_response(
            &socket,
            &mut conn,
            &mut doq,
            server_addr,
            deadline,
            stream_id,
        )
        .await
    }

    /// Collect a session ticket without creating upstream DNS work.
    async fn acquire_session(server_addr: SocketAddr) -> Vec<u8> {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let (socket, mut conn, _doq) =
            raw_established_client(server_addr, deadline).await;
        while conn.session().is_none() {
            receive_packet(&socket, &mut conn, deadline).await;
            send_pending_packets(&socket, &mut conn, server_addr).await;
        }
        let session = conn.session().unwrap().to_vec();
        conn.close(false, 0, b"test complete").unwrap();
        send_pending_packets(&socket, &mut conn, server_addr).await;
        session
    }

    /// Check DNS response fields and EDE against the expected values.
    fn assert_dns_response(
        event: quiche::doq::Event, query: &Bytes, rcode: Rcode,
        ede: Option<ExtendedErrorCode>,
    ) {
        let quiche::doq::Event::Response { data } = event else {
            panic!("expected DoQ response, got {event:?}");
        };
        let response = Message::from_octets(Bytes::from(data)).unwrap();
        let query = Message::from_octets(query.clone()).unwrap();
        assert_eq!(response.header().id(), 0);
        assert!(response.header().qr());
        assert_eq!(response.header().rcode(), rcode);
        assert!(response.is_answer(&query));
        if query.opt().is_none() {
            assert!(response.opt().is_none());
        }
        let actual_ede = response
            .opt()
            .and_then(|opt| opt.opt().extended_error())
            .map(|error| error.code());
        assert_eq!(actual_ede, ede);
    }

    /// Send a resumed query after Retry and collect its events.
    ///
    /// Queue the query before the handshake completes. With `early_data`, the
    /// client must send it in 0-RTT. Without it, the client must lack 0-RTT
    /// keys and sends the query once the handshake completes.
    ///
    /// Returns the events and the client's BoringSSL early data reason.
    async fn send_raw_resumed_query(
        server_addr: SocketAddr, session: &[u8], query: &Bytes, early_data: bool,
    ) -> (Vec<quiche::doq::Event>, u32) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let (socket, mut conn, mut doq) =
            raw_client_after_retry(server_addr, Some(session), deadline).await;
        let mut outgoing = [0; 1500];
        // Hold the post-Retry Initial until the query is queued.
        let (len, _) = conn.send(&mut outgoing).unwrap();
        let resumed_initial = outgoing[..len].to_vec();
        assert_eq!(conn.is_in_early_data(), early_data);
        assert!(!conn.is_established());
        let stream_id = doq.send_query(&mut conn, query).unwrap();
        assert_eq!(stream_id, 0);
        socket.send_to(&resumed_initial, server_addr).await.unwrap();
        send_pending_packets(&socket, &mut conn, server_addr).await;
        let events = collect_response(
            &socket,
            &mut conn,
            &mut doq,
            server_addr,
            deadline,
            stream_id,
        )
        .await;
        (events, conn.early_data_reason())
    }

    #[tokio::test]
    async fn network_failure_sends_terminal_servfail_with_conditional_ede() {
        for edns in [false, true] {
            let upstream = Arc::new(NetworkUpstream::default());
            let (server_addr, server_task) =
                start_server(Arc::clone(&upstream), ServerConfig::default(), 1)
                    .await;
            let query = test_query(Rtype::A, Opcode::QUERY, edns);
            let mut events = send_raw_query(server_addr, &query).await;
            assert_eq!(events.len(), 2);
            assert_dns_response(
                events.remove(0),
                &query,
                Rcode::SERVFAIL,
                edns.then_some(ExtendedErrorCode::NETWORK_ERROR),
            );
            assert_eq!(events.remove(0), quiche::doq::Event::Finished);
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);

            tokio::time::timeout(TEST_TIMEOUT, server_task)
                .await
                .expect("server should stop after client closes")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn deadline_sends_terminal_servfail_with_conditional_ede() {
        for edns in [false, true] {
            let upstream = Arc::new(PendingUpstream::default());
            let (server_addr, server_task) = start_server(
                Arc::clone(&upstream),
                ServerConfig {
                    transaction_timeout: Duration::from_millis(100),
                },
                1,
            )
            .await;
            let query = test_query(Rtype::A, Opcode::QUERY, edns);
            let mut events = send_raw_query(server_addr, &query).await;
            assert_eq!(events.len(), 2);
            assert_dns_response(
                events.remove(0),
                &query,
                Rcode::SERVFAIL,
                edns.then_some(ExtendedErrorCode::NETWORK_ERROR),
            );
            assert_eq!(events.remove(0), quiche::doq::Event::Finished);
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);

            tokio::time::timeout(TEST_TIMEOUT, server_task)
                .await
                .expect("server should stop after client closes")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_upstream_responses_send_servfail_without_ede() {
        for mismatched in [false, true] {
            let (server_addr, server_task) = start_server(
                Arc::new(InvalidUpstream { mismatched }),
                ServerConfig::default(),
                1,
            )
            .await;
            let query = test_query(Rtype::A, Opcode::QUERY, true);
            let mut events = send_raw_query(server_addr, &query).await;
            assert_eq!(events.len(), 2);
            assert_dns_response(events.remove(0), &query, Rcode::SERVFAIL, None);
            assert_eq!(events.remove(0), quiche::doq::Event::Finished);

            tokio::time::timeout(TEST_TIMEOUT, server_task)
                .await
                .expect("server should stop after client closes")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn upstream_opt_follows_client_edns_support() {
        // Each case lists: client sends OPT, upstream full RCODE, and the
        // expected full RCODE in the DoQ response.
        let cases = [
            (false, OptRcode::NOERROR, OptRcode::NOERROR),
            (false, OptRcode::BADVERS, OptRcode::SERVFAIL),
            (true, OptRcode::NOERROR, OptRcode::NOERROR),
            (true, OptRcode::BADVERS, OptRcode::BADVERS),
        ];
        for (edns, upstream_rcode, expected_rcode) in cases {
            let (server_addr, server_task) = start_server(
                Arc::new(OptRcodeUpstream {
                    rcode: upstream_rcode,
                }),
                ServerConfig::default(),
                1,
            )
            .await;
            let query = test_query(Rtype::A, Opcode::QUERY, edns);
            let mut events = send_raw_query(server_addr, &query).await;
            assert_eq!(events.len(), 2);
            let quiche::doq::Event::Response { data } = events.remove(0) else {
                panic!("expected DoQ response");
            };
            let response = Message::from_octets(Bytes::from(data)).unwrap();
            let query = Message::from_octets(query).unwrap();
            assert_eq!(response.header().id(), 0);
            assert!(response.is_answer(&query));
            assert_eq!(response.opt_rcode(), expected_rcode);
            assert_eq!(response.opt().is_some(), edns);
            assert_eq!(events.remove(0), quiche::doq::Event::Finished);

            tokio::time::timeout(TEST_TIMEOUT, server_task)
                .await
                .expect("server should stop after client closes")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn zone_transfer_is_answered_with_notimp_without_upstream_work() {
        for qtype in [Rtype::AXFR, Rtype::IXFR] {
            for edns in [false, true] {
                let upstream = Arc::new(NetworkUpstream::default());
                let (server_addr, server_task) = start_server(
                    Arc::clone(&upstream),
                    ServerConfig::default(),
                    1,
                )
                .await;
                let query = test_query(qtype, Opcode::QUERY, edns);
                let mut events = send_raw_query(server_addr, &query).await;
                assert_eq!(events.len(), 2);
                assert_dns_response(
                    events.remove(0),
                    &query,
                    Rcode::NOTIMP,
                    None,
                );
                assert_eq!(events.remove(0), quiche::doq::Event::Finished);
                assert_eq!(upstream.calls.load(Ordering::Relaxed), 0);

                tokio::time::timeout(TEST_TIMEOUT, server_task)
                    .await
                    .expect("server should stop after client closes")
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn non_replayable_zero_rtt_query_is_refused_without_upstream_work() {
        for edns in [false, true] {
            let upstream = Arc::new(NetworkUpstream::default());
            let (server_addr, server_task) =
                start_server(Arc::clone(&upstream), ServerConfig::default(), 2)
                    .await;

            let session = acquire_session(server_addr).await;

            let query = test_query(Rtype::A, Opcode::UPDATE, edns);
            let (mut events, early_data_reason) =
                send_raw_resumed_query(server_addr, &session, &query, true).await;
            assert_eq!(early_data_reason, EARLY_DATA_ACCEPTED);
            assert_eq!(events.len(), 2);
            assert_dns_response(
                events.remove(0),
                &query,
                Rcode::REFUSED,
                edns.then_some(ExtendedErrorCode::from_int(26)),
            );
            assert_eq!(events.remove(0), quiche::doq::Event::Finished);
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 0);

            // End the listener after checking the ticket and resumed response.
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn replayable_zero_rtt_query_is_forwarded() {
        for edns in [false, true] {
            let upstream = Arc::new(AnswerUpstream::default());
            let (server_addr, server_task) =
                start_server(Arc::clone(&upstream), ServerConfig::default(), 2)
                    .await;

            let session = acquire_session(server_addr).await;

            let query = test_query(Rtype::A, Opcode::QUERY, edns);
            let (mut events, early_data_reason) =
                send_raw_resumed_query(server_addr, &session, &query, true).await;
            assert_eq!(early_data_reason, EARLY_DATA_ACCEPTED);
            assert_eq!(events.len(), 2);
            assert_dns_response(events.remove(0), &query, Rcode::NOERROR, None);
            assert_eq!(events.remove(0), quiche::doq::Event::Finished);
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);

            // End the listener after checking the ticket and resumed response.
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn disabled_zero_rtt_forwards_resumed_non_replayable_query() {
        for edns in [false, true] {
            let upstream = Arc::new(AnswerUpstream::default());
            let (server_addr, server_task) = start_server_with_0rtt(
                Arc::clone(&upstream),
                ServerConfig::default(),
                2,
                true,
            )
            .await;

            let session = acquire_session(server_addr).await;

            // The session ticket does not allow 0-RTT, so the client sends the
            // query in 1-RTT and the server forwards it instead of refusing it.
            let query = test_query(Rtype::A, Opcode::UPDATE, edns);
            let (mut events, early_data_reason) =
                send_raw_resumed_query(server_addr, &session, &query, false)
                    .await;
            assert_eq!(early_data_reason, EARLY_DATA_UNSUPPORTED_FOR_SESSION);
            assert_eq!(events.len(), 2);
            assert_dns_response(events.remove(0), &query, Rcode::NOERROR, None);
            assert_eq!(events.remove(0), quiche::doq::Event::Finished);
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);

            // End the listener after checking the ticket and resumed response.
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn invalid_query_closes_connection_without_upstream_work() {
        let mut malformed_qname = query(0, Rtype::A).to_vec();
        // Byte 12 is the first QNAME label length. A length of 64 exceeds
        // DNS's 63-octet label limit, making the QNAME malformed.
        malformed_qname[12] = 64;
        let mut response_form = query(0, Rtype::A).to_vec();
        // Set the QR flag in the header's third byte to make this a response.
        response_form[2] |= 0x80;
        let cases = [
            vec![0; 11],
            malformed_qname,
            response_form,
            query(1, Rtype::A).to_vec(),
        ];
        for invalid in cases {
            let upstream = Arc::new(NetworkUpstream::default());
            let (server_addr, server_task) =
                start_server(Arc::clone(&upstream), ServerConfig::default(), 1)
                    .await;
            let error = send_raw_query_until_closed(server_addr, &invalid).await;
            assert!(error.is_app);
            assert_eq!(error.error_code, DoqError::ProtocolError.to_wire());
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 0);

            tokio::time::timeout(TEST_TIMEOUT, server_task)
                .await
                .expect("server should stop after closing the connection")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn concurrent_queries_are_answered_out_of_order() {
        let upstream = Arc::new(AnswerUpstream {
            hold: Some(Rtype::A),
            ..Default::default()
        });
        let (server_addr, server_task) =
            start_server(Arc::clone(&upstream), ServerConfig::default(), 1).await;
        let deadline = Instant::now() + TEST_TIMEOUT;
        let (socket, mut conn, mut doq) =
            raw_established_client(server_addr, deadline).await;
        let held_query = test_query(Rtype::A, Opcode::QUERY, false);
        let other_query = test_query(Rtype::AAAA, Opcode::QUERY, false);
        let held_id = doq.send_query(&mut conn, &held_query).unwrap();
        let other_id = doq.send_query(&mut conn, &other_query).unwrap();
        send_pending_packets(&socket, &mut conn, server_addr).await;

        // Collect the second answer while the upstream holds the first one.
        let mut events = HashMap::new();
        collect_until_finished(
            &socket,
            &mut conn,
            &mut doq,
            server_addr,
            deadline,
            &mut events,
            other_id,
        )
        .await;
        tokio::time::timeout_at(deadline, upstream.held_started.notified())
            .await
            .expect("held upstream query should start");
        assert!(!events.contains_key(&held_id));
        assert_eq!(upstream.calls.load(Ordering::Relaxed), 2);

        upstream.release.notify_one();
        collect_until_finished(
            &socket,
            &mut conn,
            &mut doq,
            server_addr,
            deadline,
            &mut events,
            held_id,
        )
        .await;
        conn.close(false, 0, b"test complete").unwrap();
        send_pending_packets(&socket, &mut conn, server_addr).await;

        assert_eq!(events.len(), 2);
        for (id, query) in [(held_id, &held_query), (other_id, &other_query)] {
            let mut stream_events = events.remove(&id).unwrap();
            assert_eq!(stream_events.len(), 2);
            assert_dns_response(
                stream_events.remove(0),
                query,
                Rcode::NOERROR,
                None,
            );
            assert_eq!(stream_events.remove(0), quiche::doq::Event::Finished);
        }

        tokio::time::timeout(TEST_TIMEOUT, server_task)
            .await
            .expect("server should stop after client closes")
            .unwrap();
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
