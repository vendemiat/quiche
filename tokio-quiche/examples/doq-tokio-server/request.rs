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
use tokio::time::Instant;

use crate::config::ServerConfig;
use crate::upstream::ResponseSequence;
use crate::upstream::Upstream;
use crate::upstream::UpstreamError;

/// State shared by the controller while one DNS request is in flight.
#[derive(Debug)]
pub(crate) struct Request {
    deadline: Instant,
}

impl Request {
    /// Start a request using the monotonic Tokio clock.
    pub(crate) fn start(config: &ServerConfig) -> Self {
        let started_at = Instant::now();
        let deadline = started_at + config.transaction_timeout;
        Self { deadline }
    }

    /// Return the absolute deadline for this request.
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Return whether the request has reached its deadline.
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    /// Resolve the request before its absolute deadline.
    pub(crate) async fn resolve<U: Upstream>(
        &self, upstream: &U, query: Bytes,
    ) -> Result<ResponseSequence, UpstreamError> {
        tokio::time::timeout_at(self.deadline, upstream.resolve(query))
            .await
            .map_err(|_| UpstreamError::DeadlineExceeded)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    use crate::upstream::ResponseItem;

    struct TestUpstream;

    impl Upstream for TestUpstream {
        fn resolve(
            &self, _query: Bytes,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResponseSequence, UpstreamError>>
                    + Send,
            >,
        > {
            Box::pin(async {
                let (sender, sequence) = ResponseSequence::channel(1);
                sender
                    .send(Bytes::from_static(b"response"), true)
                    .await
                    .unwrap();
                Ok(sequence)
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_based_on_configured_timeout() {
        let config = ServerConfig {
            transaction_timeout: Duration::from_secs(5),
        };
        let request = Request::start(&config);
        assert!(!request.is_expired(Instant::now()));
        tokio::time::advance(config.transaction_timeout).await;
        assert!(request.is_expired(request.deadline()));
    }

    #[tokio::test]
    async fn resolves_before_transaction_deadline() {
        let request = Request::start(&ServerConfig::default());
        let mut response = request
            .resolve(&TestUpstream, Bytes::from_static(b"query"))
            .await
            .unwrap();
        assert_eq!(
            response.next().await.unwrap(),
            ResponseItem::Final(Bytes::from_static(b"response"))
        );
    }
}
