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

//! Incremental upstream response abstractions.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use domain::base::iana::Rcode;
use domain::base::Message;
use domain::base::MessageBuilder;
use tokio::sync::mpsc;

/// One DNS response in an upstream sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResponseItem {
    /// Send this response while keeping the DoQ stream open.
    More(Bytes),
    /// Send this response and finish the DoQ stream.
    Final(Bytes),
}

/// Producer for an ordered upstream response sequence.
pub(crate) struct ResponseStreamSender {
    sender: mpsc::Sender<ResponseItem>,
}

impl ResponseStreamSender {
    /// Send a response, optionally marking it as final.
    pub(crate) async fn send(
        &self, data: Bytes, fin: bool,
    ) -> Result<(), UpstreamError> {
        self.sender
            .send(if fin {
                ResponseItem::Final(data)
            } else {
                ResponseItem::More(data)
            })
            .await
            .map_err(|_| UpstreamError::ReceiverClosed)
    }
}

/// Responses produced in order as the upstream resolves them.
pub(crate) struct ResponseSequence {
    receiver: mpsc::Receiver<ResponseItem>,
}

impl ResponseSequence {
    /// Create a producer and its response sequence.
    pub(crate) fn channel(capacity: usize) -> (ResponseStreamSender, Self) {
        let (sender, receiver) = mpsc::channel(capacity);
        (ResponseStreamSender { sender }, Self { receiver })
    }

    /// Receive the next response or report premature stream closure.
    pub(crate) async fn next(&mut self) -> Result<ResponseItem, UpstreamError> {
        match self.receiver.recv().await {
            Some(item) => Ok(item),
            None => Err(UpstreamError::InvalidResponseSequence),
        }
    }
}

/// Internal errors returned by an upstream resolver or response sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpstreamError {
    /// The response stream ended before a terminal response.
    InvalidResponseSequence,
    /// The request exceeded its absolute deadline.
    DeadlineExceeded,
    /// The response consumer closed before a response was sent.
    ReceiverClosed,
    /// The fake upstream could not parse the DNS query.
    InvalidQuery,
}

/// The resolver interface used by the transaction layer.
pub(crate) trait Upstream: Send + Sync {
    /// Start resolving one DNS request.
    fn resolve(
        &self, query: Bytes,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResponseSequence, UpstreamError>> + Send>,
    >;
}

/// A deterministic upstream that returns an empty successful DNS response.
pub(crate) struct FakeUpstream;

impl Upstream for FakeUpstream {
    fn resolve(
        &self, query: Bytes,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResponseSequence, UpstreamError>> + Send>,
    > {
        Box::pin(async move {
            let query = Message::from_octets(query.to_vec())
                .map_err(|_| UpstreamError::InvalidQuery)?;
            let response = MessageBuilder::new_vec()
                .start_answer(&query, Rcode::NOERROR)
                .map_err(|_| UpstreamError::InvalidQuery)?
                .additional()
                .finish();
            let (sender, sequence) = ResponseSequence::channel(1);
            sender.send(Bytes::from(response), true).await?;
            Ok(sequence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn response_sequence_yields_incrementally_and_requires_fin() {
        let (sender, mut sequence) = ResponseSequence::channel(1);
        sender
            .send(Bytes::from_static(b"response"), false)
            .await
            .unwrap();
        assert_eq!(
            sequence.next().await.unwrap(),
            ResponseItem::More(Bytes::from_static(b"response"))
        );
        sender
            .send(Bytes::from_static(b"response"), true)
            .await
            .unwrap();
        assert_eq!(
            sequence.next().await.unwrap(),
            ResponseItem::Final(Bytes::from_static(b"response"))
        );
    }

    #[tokio::test]
    async fn response_sequence_rejects_close_before_fin() {
        let (sender, mut sequence) = ResponseSequence::channel(1);
        sender
            .send(Bytes::from_static(b"response"), false)
            .await
            .unwrap();
        assert_eq!(
            sequence.next().await.unwrap(),
            ResponseItem::More(Bytes::from_static(b"response"))
        );
        drop(sender);
        assert_eq!(
            sequence.next().await,
            Err(UpstreamError::InvalidResponseSequence)
        );
    }

    #[tokio::test]
    async fn fake_upstream_returns_a_terminal_dns_response() {
        let query = Bytes::from_static(
            b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01",
        );
        let mut responses = FakeUpstream.resolve(query).await.unwrap();

        let ResponseItem::Final(response) = responses.next().await.unwrap()
        else {
            panic!("fake upstream response must finish the DoQ stream");
        };

        assert_eq!(&response[..2], &[0, 0]);
        assert_ne!(response[2] & 0x80, 0);
    }
}
