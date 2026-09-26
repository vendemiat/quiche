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

//! Ordinary DNS-over-TCP upstream transactions.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use bytes::Bytes;
use domain::base::Message;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::ResponseSequence;
use super::Upstream;
use super::UpstreamError;

/// A DNS-over-TCP resolver with one connection per query.
pub(crate) struct TcpUpstream {
    address: SocketAddr,
}

impl TcpUpstream {
    /// Create an upstream resolver for the provided address.
    pub(crate) fn new(address: SocketAddr) -> Self {
        Self { address }
    }
}

impl Upstream for TcpUpstream {
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
            let Ok(length) = u16::try_from(query.as_slice().len()) else {
                return Err(UpstreamError::QueryTooLarge);
            };
            let mut framed = Vec::with_capacity(2 + query.as_slice().len());
            framed.extend_from_slice(&length.to_be_bytes());
            framed.extend_from_slice(query.as_slice());

            let mut stream = TcpStream::connect(self.address).await?;
            stream.write_all(&framed).await?;

            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).await?;
            let mut response = vec![0; usize::from(u16::from_be_bytes(prefix))];
            stream.read_exact(&mut response).await?;

            let (mut sender, sequence) = ResponseSequence::channel(1);
            sender.send(Bytes::from(response), true).await?;
            Ok(sequence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::query;
    use crate::dns::DoqDnsQuery;
    use crate::upstream::ResponseItem;
    use domain::base::iana::Rcode;
    use domain::base::iana::Rtype;
    use domain::base::MessageBuilder;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn upstream_query(upstream: &TcpUpstream) -> Message<Bytes> {
        let client_query = DoqDnsQuery::try_from(
            Message::from_octets(query(0, Rtype::A)).unwrap(),
        )
        .unwrap();
        upstream.prepare_query(&client_query).unwrap()
    }

    #[tokio::test]
    async fn frames_query_and_reads_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpUpstream::new(listener.local_addr().unwrap());
        let query = upstream_query(&upstream);
        let expected_query = query.as_slice().to_vec();
        let response = MessageBuilder::new_bytes()
            .start_answer(&query, Rcode::NOERROR)
            .unwrap()
            .additional()
            .into_message()
            .into_octets();
        let expected_response = response.clone();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).await.unwrap();
            assert_eq!(
                usize::from(u16::from_be_bytes(prefix)),
                expected_query.len()
            );
            let mut received = vec![0; expected_query.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_query);

            let prefix = u16::try_from(expected_response.len())
                .unwrap()
                .to_be_bytes();
            let mut framed = prefix.to_vec();
            framed.extend_from_slice(&expected_response);
            stream.write_all(&framed).await.unwrap();
        });

        let mut responses = timeout(TEST_TIMEOUT, upstream.resolve(&query))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            responses.next().await.unwrap(),
            ResponseItem::Final(response)
        );
        timeout(TEST_TIMEOUT, peer).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn early_eof_in_prefix_or_body_is_network_error() {
        for body in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream = TcpUpstream::new(listener.local_addr().unwrap());
            let query = upstream_query(&upstream);
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut prefix = [0; 2];
                stream.read_exact(&mut prefix).await.unwrap();
                let mut received =
                    vec![0; usize::from(u16::from_be_bytes(prefix))];
                stream.read_exact(&mut received).await.unwrap();
                if body {
                    stream.write_all(&[0, 4, 1]).await.unwrap();
                } else {
                    stream.write_all(&[0]).await.unwrap();
                }
            });
            assert!(matches!(
                timeout(TEST_TIMEOUT, upstream.resolve(&query))
                    .await
                    .unwrap(),
                Err(UpstreamError::Network(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof
            ));
            timeout(TEST_TIMEOUT, peer).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_oversized_query_before_connecting() {
        let query = Message::from_octets(Bytes::from(vec![0; 65536])).unwrap();
        let upstream = TcpUpstream::new("192.0.2.1:53".parse().unwrap());
        assert!(matches!(
            upstream.resolve(&query).await,
            Err(UpstreamError::QueryTooLarge)
        ));
    }

    #[tokio::test]
    async fn cancelling_pending_resolution_closes_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpUpstream::new(listener.local_addr().unwrap());
        let query = upstream_query(&upstream);
        let (ready_tx, ready_rx) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut received = vec![0; usize::from(u16::from_be_bytes(prefix))];
            stream.read_exact(&mut received).await.unwrap();
            ready_tx.send(()).unwrap();
            let mut byte = [0; 1];
            assert_eq!(
                timeout(TEST_TIMEOUT, stream.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        });

        let resolution =
            tokio::spawn(async move { upstream.resolve(&query).await });
        timeout(TEST_TIMEOUT, ready_rx).await.unwrap().unwrap();
        resolution.abort();
        assert!(matches!(resolution.await, Err(error) if error.is_cancelled()));
        timeout(TEST_TIMEOUT, peer).await.unwrap().unwrap();
    }
}
