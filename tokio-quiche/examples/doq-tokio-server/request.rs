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
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Per-query deadline, cancellation, and response forwarding state.

use bytes::Bytes;
use domain::base::iana::Rcode;
use domain::base::opt::exterr::ExtendedError;
use domain::base::Message;
use tokio::time::Instant;
use tokio_quiche::doq::DoqResponder;

use crate::config::ServerConfig;
use crate::dns::DnsError;
use crate::dns::DoqDnsQuery;
use crate::dns::DoqDnsResponse;
use crate::upstream::ResponseItem;
use crate::upstream::ResponseSequence;
use crate::upstream::Upstream;
use crate::upstream::UpstreamError;

/// State shared by the controller while one DNS request is in flight.
pub(crate) struct Request {
    deadline: Instant,
    /// Keep the original DoQ query for terminal responses.
    client_query: DoqDnsQuery<Bytes>,
    upstream_query: Message<Bytes>,
}

impl Request {
    /// Start a request for `upstream` using the monotonic Tokio clock.
    pub(crate) fn start(
        config: &ServerConfig, query: DoqDnsQuery<Bytes>, upstream: &dyn Upstream,
    ) -> Result<Self, DnsError> {
        let started_at = Instant::now();
        let deadline = started_at + config.transaction_timeout;
        let upstream_query = upstream.prepare_query(&query)?;
        Ok(Self {
            deadline,
            client_query: query,
            upstream_query,
        })
    }

    /// Return the absolute deadline for this request.
    #[cfg(test)]
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Return whether the request has reached its deadline.
    #[cfg(test)]
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    /// Resolve the request before its absolute deadline.
    pub(crate) async fn resolve(
        &self, upstream: &dyn Upstream, responder: &DoqResponder,
    ) -> Result<ResponseSequence, UpstreamError> {
        tokio::select! {
            result = tokio::time::timeout_at(
                self.deadline,
                upstream.resolve(&self.upstream_query),
            ) => {
                Ok(result??)
            },
            _ = responder.closed() => Err(UpstreamError::Cancelled),
        }
    }

    /// Resolve and forward all upstream responses for this request.
    pub(crate) async fn respond(
        &self, upstream: &dyn Upstream, responder: &DoqResponder,
    ) -> Result<(), UpstreamError> {
        let mut responses = self.resolve(upstream, responder).await?;
        loop {
            let response = tokio::select! {
                result = tokio::time::timeout_at(self.deadline, responses.next()) => {
                result??
            },
            _ = responder.closed() => return Err(UpstreamError::Cancelled),
            };
            let (data, fin) = match response {
                ResponseItem::More(data) => (data, false),
                ResponseItem::Final(data) => (data, true),
            };
            if !self.upstream_query.is_xfr() && !fin {
                return Err(UpstreamError::InvalidResponseSequence(
                    DnsError::InvalidResponse,
                ));
            }
            let data = self.validate_upstream_response(data, upstream)?;

            tokio::select! {
                result = responder.send(data.into_bytes(), fin) => {
                    if result.is_err() {
                        return Ok(());
                    }
                },
            _ = responder.closed() => return Err(UpstreamError::Cancelled),
            }
            if fin {
                return Ok(());
            }
        }
    }

    /// Build a terminal DNS response from the original DoQ query.
    pub(crate) fn failed_reponse(
        &self, rcode: Rcode, ede: Vec<ExtendedError<Bytes>>,
    ) -> Result<DoqDnsResponse<Bytes>, DnsError> {
        self.client_query.failed_reponse(rcode, ede)
    }

    fn validate_upstream_response(
        &self, data: Bytes, upstream: &dyn Upstream,
    ) -> Result<DoqDnsResponse<Bytes>, UpstreamError> {
        let response =
            DoqDnsResponse::from_upstream_bytes(data, &self.upstream_query)?;
        if response.is_truncated() && upstream.should_retry_tc() {
            return Err(UpstreamError::TcpRetryRequired);
        }
        Ok(response.prepare_client_response(&self.client_query)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::UdpUpstream;
    use domain::base::iana::Rtype;
    use domain::base::Message;
    use domain::base::MessageBuilder;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    fn query() -> DoqDnsQuery<Bytes> {
        Message::from_octets(crate::dns::query(0, Rtype::A))
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// Return a UDP upstream that the tests never contact.
    fn upstream() -> UdpUpstream {
        UdpUpstream::new("192.0.2.1:53".parse().unwrap())
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_based_on_configured_timeout() {
        let config = ServerConfig {
            transaction_timeout: Duration::from_secs(5),
            ..ServerConfig::default()
        };
        let request = Request::start(&config, query(), &upstream()).unwrap();
        assert!(!request.is_expired(Instant::now()));
        tokio::time::advance(config.transaction_timeout).await;
        assert!(request.is_expired(request.deadline()));
    }

    #[tokio::test]
    async fn udp_truncated_response_requires_tcp_retry() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = UdpUpstream::new(socket.local_addr().unwrap());
        let request =
            Request::start(&ServerConfig::default(), query(), &upstream).unwrap();
        let response_task = tokio::spawn(async move {
            let mut buffer = [0; 1400];
            let (len, peer) = tokio::time::timeout(
                Duration::from_secs(5),
                socket.recv_from(&mut buffer),
            )
            .await
            .expect("UDP upstream should receive the query")
            .unwrap();
            let received =
                Message::from_octets(Bytes::copy_from_slice(&buffer[..len]))
                    .unwrap();
            let mut response = MessageBuilder::new_bytes()
                .start_answer(&received, Rcode::NOERROR)
                .unwrap();
            response.header_mut().set_tc(true);
            let response = response.additional().into_message().into_octets();
            tokio::time::timeout(
                Duration::from_secs(5),
                socket.send_to(&response, peer),
            )
            .await
            .expect("UDP upstream should send the response")
            .unwrap();
        });

        let mut responses = tokio::time::timeout(
            Duration::from_secs(5),
            upstream.resolve(&request.upstream_query),
        )
        .await
        .expect("UDP adapter should receive the response")
        .unwrap();
        let ResponseItem::Final(response) = responses.next().await.unwrap()
        else {
            panic!("UDP adapter should return a final response");
        };
        assert!(matches!(
            request.validate_upstream_response(response, &upstream),
            Err(UpstreamError::TcpRetryRequired)
        ));
        tokio::time::timeout(Duration::from_secs(5), response_task)
            .await
            .expect("UDP response task should finish")
            .unwrap();
    }
}
