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
use crate::dns::build_failed_response;
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
    upstream_query: Message<Bytes>,
}

impl Request {
    /// Start a request using the monotonic Tokio clock.
    pub(crate) fn start(
        config: &ServerConfig, query: DoqDnsQuery<Bytes>,
    ) -> Result<Self, DnsError> {
        let started_at = Instant::now();
        let deadline = started_at + config.transaction_timeout;
        Ok(Self {
            deadline,
            upstream_query: query.prepare_upstream_query()?,
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
    pub(crate) async fn resolve<U: Upstream>(
        &self, upstream: &U, responder: &DoqResponder,
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
    pub(crate) async fn respond<U: Upstream>(
        &self, upstream: &U, responder: &DoqResponder,
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
            let data =
                DoqDnsResponse::from_upstream_bytes(data, &self.upstream_query)?;

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

    /// Build a terminal DNS response for this request.
    pub(crate) fn failed_reponse(
        &self, rcode: Rcode, ede: Vec<ExtendedError<Bytes>>,
    ) -> Result<DoqDnsResponse<Bytes>, DnsError> {
        build_failed_response(&self.upstream_query, rcode, ede)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::base::iana::Rtype;
    use domain::base::Message;
    use std::time::Duration;

    fn query() -> DoqDnsQuery<Bytes> {
        Message::from_octets(crate::dns::query(0, Rtype::A))
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_based_on_configured_timeout() {
        let config = ServerConfig {
            transaction_timeout: Duration::from_secs(5),
        };
        let request = Request::start(&config, query()).unwrap();
        assert!(!request.is_expired(Instant::now()));
        tokio::time::advance(config.transaction_timeout).await;
        assert!(request.is_expired(request.deadline()));
    }
}
