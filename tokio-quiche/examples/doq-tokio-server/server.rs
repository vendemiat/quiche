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

use tokio_quiche::doq::DoqController;
use tokio_quiche::doq::DoqError;
use tokio_quiche::doq::DoqEvent;

use crate::config::ServerConfig;
use crate::request::Request;
use crate::upstream::Upstream;

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
            data, responder, ..
        } = event
        {
            let upstream = Arc::clone(&upstream);
            let config = config.clone();
            tokio::spawn(async move {
                let request = Request::start(&config);
                if request
                    .respond(upstream.as_ref(), data, &responder)
                    .await
                    .is_err()
                {
                    let _ = responder.reset(DoqError::InternalError).await;
                }
            });
        }
    }
}
