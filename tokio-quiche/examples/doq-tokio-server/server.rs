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
