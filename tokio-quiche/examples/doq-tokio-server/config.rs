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

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

const DEFAULT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_MAX_CONCURRENT_TRANSACTIONS: usize = 1024;

/// Configuration for DoQ transaction processing.
#[derive(Clone, Debug)]
pub(crate) struct ServerConfig {
    /// Time allowed for upstream resolution and response reads.
    pub(crate) transaction_timeout: Duration,
    /// Shared capacity for concurrent upstream transactions.
    pub(crate) concurrent_transactions: Arc<Semaphore>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            transaction_timeout: DEFAULT_TRANSACTION_TIMEOUT,
            concurrent_transactions: Arc::new(Semaphore::new(
                DEFAULT_MAX_CONCURRENT_TRANSACTIONS,
            )),
        }
    }
}
