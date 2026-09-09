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
use std::net::SocketAddr;
use std::pin::Pin;

use bytes::Bytes;
use domain::base::message_builder::PushError;
use domain::base::Message;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::error::Elapsed;

use crate::dns::DnsError;
use crate::dns::MAX_DNS_UDP_BUFFER_SIZE;

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
    finished: bool,
}

impl ResponseStreamSender {
    /// Send a response, optionally marking it as final.
    pub(crate) async fn send(
        &mut self, data: Bytes, fin: bool,
    ) -> Result<(), UpstreamError> {
        if self.finished {
            return Err(UpstreamError::InvalidResponseSequence(
                DnsError::InvalidResponse,
            ));
        }

        self.sender
            .send(if fin {
                ResponseItem::Final(data)
            } else {
                ResponseItem::More(data)
            })
            .await?;
        self.finished = fin;
        Ok(())
    }
}

/// Responses produced in order as the upstream resolves them.
pub(crate) struct ResponseSequence {
    receiver: mpsc::Receiver<ResponseItem>,
    finished: bool,
}

impl ResponseSequence {
    /// Create a producer and its response sequence.
    pub(crate) fn channel(capacity: usize) -> (ResponseStreamSender, Self) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            ResponseStreamSender {
                sender,
                finished: false,
            },
            Self {
                receiver,
                finished: false,
            },
        )
    }

    /// Receive the next response or report premature stream closure.
    pub(crate) async fn next(&mut self) -> Result<ResponseItem, UpstreamError> {
        match self.receiver.recv().await {
            Some(_) if self.finished => Err(
                UpstreamError::InvalidResponseSequence(DnsError::InvalidResponse),
            ),
            Some(ResponseItem::Final(data)) => {
                self.finished = true;
                Ok(ResponseItem::Final(data))
            },
            Some(item) => Ok(item),
            None => Err(UpstreamError::InvalidResponseSequence(
                DnsError::InvalidResponse,
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamError {
    #[error("invalid upstream response sequence")]
    InvalidResponseSequence(#[from] DnsError),

    #[error("request deadline exceeded")]
    DeadlineExceeded(#[from] Elapsed),

    #[error("response consumer closed")]
    ReceiverClosed(#[from] mpsc::error::SendError<ResponseItem>),

    #[error("upstream failed")]
    Failed(#[from] PushError),

    #[error("upstream network error")]
    Network(#[from] std::io::Error),

    #[error("upstream response requires TCP retry")]
    TcpRetryRequired,

    #[error("downstream request cancelled")]
    Cancelled,
}

/// The resolver interface used by the transaction layer.
pub(crate) trait Upstream: Send + Sync {
    /// Start resolving one DNS request.
    fn resolve<'a>(
        &'a self, query: &'a Message<Bytes>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ResponseSequence, UpstreamError>>
                + Send
                + 'a,
        >,
    >;
}

/// A conventional UDP DNS upstream resolver.
pub(crate) struct UdpUpstream {
    address: SocketAddr,
}

impl UdpUpstream {
    /// Create an upstream resolver for the provided address.
    pub(crate) fn new(address: SocketAddr) -> Self {
        Self { address }
    }
}

impl Upstream for UdpUpstream {
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
            let bind_address = match self.address {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };
            let socket = UdpSocket::bind(bind_address).await?;
            socket.connect(self.address).await?;
            socket.send(query.as_slice()).await?;

            let mut response = vec![0; usize::from(MAX_DNS_UDP_BUFFER_SIZE)];
            let response_len = socket.recv(&mut response).await?;
            response.truncate(response_len);

            let (mut sender, sequence) = ResponseSequence::channel(1);
            sender.send(Bytes::from(response), true).await?;
            Ok(sequence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::base::iana::Rcode;
    use domain::base::iana::Rtype;
    use domain::base::MessageBuilder;
    use tokio::net::UdpSocket;

    /// A deterministic upstream that returns an empty successful DNS response.
    struct FakeUpstream;

    impl Upstream for FakeUpstream {
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

    #[tokio::test]
    async fn response_sequence_yields_incrementally_and_requires_fin() {
        let (mut sender, mut sequence) = ResponseSequence::channel(1);
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
        let (mut sender, mut sequence) = ResponseSequence::channel(1);
        sender
            .send(Bytes::from_static(b"response"), false)
            .await
            .unwrap();
        assert_eq!(
            sequence.next().await.unwrap(),
            ResponseItem::More(Bytes::from_static(b"response"))
        );
        drop(sender);
        assert!(matches!(
            sequence.next().await,
            Err(UpstreamError::InvalidResponseSequence(
                DnsError::InvalidResponse
            ))
        ));
    }

    #[tokio::test]
    async fn response_sequence_rejects_messages_after_final() {
        let (mut sender, _sequence) = ResponseSequence::channel(1);
        sender
            .send(Bytes::from_static(b"response"), true)
            .await
            .unwrap();
        assert!(matches!(
            sender.send(Bytes::from_static(b"response"), false).await,
            Err(UpstreamError::InvalidResponseSequence(
                DnsError::InvalidResponse
            ))
        ));
    }

    #[tokio::test]
    async fn fake_upstream_returns_a_terminal_dns_response() {
        let query = crate::dns::query(0, Rtype::A);
        let query = Message::from_octets(query).unwrap();
        let mut responses = FakeUpstream.resolve(&query).await.unwrap();

        let ResponseItem::Final(response) = responses.next().await.unwrap()
        else {
            panic!("fake upstream response must finish the DoQ stream");
        };

        assert_eq!(&response[..2], &[0, 0]);
        assert_ne!(response[2] & 0x80, 0);
    }

    #[tokio::test]
    async fn udp_upstream_forwards_query_and_returns_terminal_response() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let query = crate::dns::query(0, Rtype::A);
        let query_message = crate::dns::DoqDnsQuery::try_from(
            Message::from_octets(query).unwrap(),
        )
        .unwrap()
        .prepare_upstream_query()
        .unwrap();
        let response = MessageBuilder::new_bytes()
            .start_answer(&query_message, Rcode::NOERROR)
            .unwrap()
            .additional()
            .into_message()
            .into_octets();
        let expected_query = query_message.as_slice().to_vec();
        let expected_response = response.clone();

        let response_task = tokio::spawn(async move {
            let mut received = vec![0; usize::from(MAX_DNS_UDP_BUFFER_SIZE)];
            let (received_len, peer) =
                upstream.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..received_len], expected_query.as_slice());
            upstream.send_to(&expected_response, peer).await.unwrap();
        });

        let mut responses = UdpUpstream::new(upstream_address)
            .resolve(&query_message)
            .await
            .unwrap();
        assert_eq!(
            responses.next().await.unwrap(),
            ResponseItem::Final(response)
        );
        response_task.await.unwrap();
    }
}
