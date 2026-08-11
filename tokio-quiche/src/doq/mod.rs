// Copyright (C) 2025, Cloudflare, Inc.
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

//! DNS over QUIC (DoQ) driver for `tokio-quiche`.
//!
//! This module provides an
//! [`ApplicationOverQuic`](crate::ApplicationOverQuic) implementation,
//! `DoqServerDriver`, that speaks DNS over QUIC as specified in
//! [RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250). It mirrors the
//! [`H3Driver`](crate::http3::driver::H3Driver) / controller split: the driver
//! owns the QUIC side and runs inside the connection's IO worker task, while
//! the async application logic (forwarding to a resolver, etc.) lives in a
//! consumer task that drains the paired `DoqController`'s event channel.
//!
//! ```text
//!   client bidi stream -> DoqServerDriver --DoqEvent::Query{responder}--> app
//!                              ^                                           |
//!                              +------------ DoqResponder::send -----------+
//! ```
//!
//! Unlike [`H3Driver`](crate::http3::driver::H3Driver), `DoqServerDriver`
//! does **not** parse or frame DNS messages itself: all per-stream
//! reassembly, DoQ's 2-octet length-prefix framing, and the
//! [RFC 9250 §4.3.3](https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3)
//! protocol-error matrix live in [`quiche::doq::Connection`], a synchronous,
//! IO-less object shared with the blocking-mio DoQ examples. This driver is a
//! thin pump over that `Connection`.
//!
//! Each [`DoqEvent::Query`] carries a dedicated [`DoqResponder`] bound to that
//! query's stream; the consumer replies through it and never handles a raw
//! `stream_id`. DoQ maps **exactly one query per client-initiated
//! bidirectional stream** (RFC 9250
//! [§4.2](https://datatracker.ietf.org/doc/html/rfc9250#section-4.2)), but a
//! single query may receive **one or more** responses (zone transfers, RFC
//! 9250
//! [§5.7](https://datatracker.ietf.org/doc/html/rfc9250#section-5.7)); the
//! consumer calls [`DoqResponder::send`] once per response message, marking
//! the last one with `fin = true`.
//!
//! The wire-format primitives (`DoqError`, `read_dns_message`,
//! `write_dns_message`, `is_replayable_opcode`, `DOQ_ALPN`, `DOQ_PORT`) live in
//! [`quiche::doq`] and are re-exported here for convenience.

use std::fmt;

use bytes::Bytes;
use tokio::sync::mpsc;

mod driver;
#[cfg(test)]
pub mod test_utils;
#[cfg(test)]
mod tests;

pub use driver::DoqController;
pub use driver::DoqServerDriver;

// Re-export the quiche wire-format primitives so consumers only need to depend
// on `tokio_quiche::doq`.
#[doc(no_inline)]
pub use quiche::doq::is_replayable_opcode;
#[doc(no_inline)]
pub use quiche::doq::read_dns_message;
#[doc(no_inline)]
pub use quiche::doq::write_dns_message;
#[doc(no_inline)]
pub use quiche::doq::DnsWireError;
#[doc(no_inline)]
pub use quiche::doq::DoqError;
#[doc(no_inline)]
pub use quiche::doq::DOQ_ALPN;
#[doc(no_inline)]
pub use quiche::doq::DOQ_PORT;

/// A response action queued on a [`DoqResponder`] for its paired
/// `DoqServerDriver` to apply to the query's stream.
#[derive(Debug)]
pub(crate) enum ResponderMessage {
    /// Send one framed DNS response message; `fin` closes the stream after it.
    Response {
        /// The raw DNS response message (no length prefix).
        data: Bytes,
        /// Whether this is the last response for the transaction.
        fin: bool,
    },

    /// Abandon the transaction with `RESET_STREAM` carrying this DoQ error.
    Reset {
        /// The DoQ error code to signal.
        error: DoqError,
    },
}

/// Error returned by [`DoqResponder`] operations when the transaction is no
/// longer live.
///
/// The peer cancelled the stream (`STOP_SENDING` / `RESET_STREAM`) or the
/// connection closed, so the driver dropped the receiving end of the
/// responder's channel. This is a normal race, not a bug: the consumer should
/// stop working on the query. It is the same condition [`DoqResponder::closed`]
/// reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamClosed;

impl fmt::Display for StreamClosed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DoQ transaction stream is closed")
    }
}

impl std::error::Error for StreamClosed {}

/// The consumer's handle for answering a single [`DoqEvent::Query`].
///
/// A `DoqResponder` is created fresh per query and is structurally bound to
/// that query's stream, so a consumer cannot misdeliver a response to the
/// wrong stream. Responses flow to the `DoqServerDriver` over a bounded
/// channel, which provides automatic per-query backpressure: [`send`] awaits
/// channel capacity when the driver is behind.
///
/// [`send`]: DoqResponder::send
#[derive(Debug)]
pub struct DoqResponder {
    tx: mpsc::Sender<ResponderMessage>,
}

impl DoqResponder {
    /// Wraps the sending end of a per-query channel. The driver owns the
    /// paired receiver and chooses the channel's bound.
    pub(crate) fn new(tx: mpsc::Sender<ResponderMessage>) -> Self {
        DoqResponder { tx }
    }

    /// Queues one DNS response message for the query; the driver frames it
    /// with the 2-octet length prefix before sending.
    ///
    /// `data` is the raw DNS message *without* the length prefix and is sent
    /// verbatim (no padding or other mutation). `fin` marks the last response
    /// of the transaction: a single-response query sends one call with
    /// `fin = true`, while a zone transfer (RFC 9250
    /// [§5.7](https://datatracker.ietf.org/doc/html/rfc9250#section-5.7)) sends
    /// one or more `fin = false` calls followed by a final `fin = true`.
    ///
    /// Awaits channel capacity, applying backpressure to a producer that
    /// outruns the driver. Returns [`StreamClosed`] if the transaction is no
    /// longer live (see [`closed`](Self::closed)); the response is dropped.
    pub async fn send(&self, data: Bytes, fin: bool) -> Result<(), StreamClosed> {
        self.tx
            .send(ResponderMessage::Response { data, fin })
            .await
            .map_err(|_| StreamClosed)
    }

    /// Abandons the transaction, asking the driver to send `RESET_STREAM` with
    /// the given DoQ error code (RFC 9250
    /// [§4.3.2](https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.2),
    /// typically [`DoqError::InternalError`]).
    ///
    /// Returns [`StreamClosed`] if the transaction is no longer live.
    pub async fn reset(&self, error: DoqError) -> Result<(), StreamClosed> {
        self.tx
            .send(ResponderMessage::Reset { error })
            .await
            .map_err(|_| StreamClosed)
    }

    /// Resolves when the transaction stops being live: the peer sent
    /// `STOP_SENDING` / `RESET_STREAM`, or the connection closed. A consumer
    /// can `select!` on this to cancel in-progress work for the query.
    ///
    /// After this resolves, [`send`](Self::send) and [`reset`](Self::reset)
    /// return [`StreamClosed`].
    pub async fn closed(&self) {
        self.tx.closed().await
    }
}

/// An event emitted by a `DoqServerDriver` to its paired `DoqController`.
#[derive(Debug)]
#[non_exhaustive]
pub enum DoqEvent {
    /// A complete DNS query was received on a client-initiated bidirectional
    /// stream.
    ///
    /// The consumer answers by calling [`DoqResponder::send`] on the attached
    /// `responder` one or more times.
    Query {
        /// The raw DNS message bytes, with the 2-octet length prefix already
        /// stripped. Not parsed or validated: DNS content is the consumer's
        /// responsibility, not the transport's.
        data: Bytes,

        /// Whether the query was received in 0-RTT (early data).
        ///
        /// Per RFC 9250
        /// [§4.5](https://datatracker.ietf.org/doc/html/rfc9250#section-4.5), a
        /// non-replayable transaction received in 0-RTT MUST NOT be processed
        /// immediately. The driver does not parse opcodes itself; it surfaces
        /// this flag so the consumer can enforce the replay rules (see
        /// [`is_replayable_opcode`]).
        is_0rtt: bool,

        /// The per-query handle used to send the response(s); bound to this
        /// query's stream.
        responder: DoqResponder,
    },

    /// The QUIC handshake has been confirmed (the connection is no longer only
    /// in early data).
    ///
    /// Per RFC 9250
    /// [§4.5](https://datatracker.ietf.org/doc/html/rfc9250#section-4.5), a
    /// consumer that deferred non-replayable 0-RTT queries (rather than
    /// rejecting them outright) can use this event as the signal to process
    /// its queue.
    HandshakeConfirmed,

    /// The QUIC connection has closed. No further events will be emitted and
    /// commands sent after this are ignored.
    ConnectionClosed,
}

/// A command sent from a `DoqController` to its paired `DoqServerDriver`.
///
/// Per-query operations (sending responses, resetting a single transaction,
/// observing peer cancellation) are **not** here; they live on the per-query
/// [`DoqResponder`]. `DoqCommand` carries connection-level operations only.
#[derive(Debug)]
#[non_exhaustive]
pub enum DoqCommand {
    /// Close the whole connection with a DoQ error code and reason.
    ///
    /// Used for fatal protocol violations (RFC 9250
    /// [§4.3.3](https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3))
    /// and for normal shutdown ([`DoqError::NoError`]).
    ///
    /// `reason` is an opaque byte string (the QUIC CONNECTION_CLOSE reason
    /// phrase, RFC 9000 §19.19). It matches the byte-oriented
    /// [`quiche::Connection::close`] API and the crate's existing
    /// [`ConnectionShutdownBehaviour`](crate::quic::ConnectionShutdownBehaviour)
    /// `reason` field.
    CloseConnection {
        /// The DoQ error code (wire-encoded via [`DoqError::to_wire`]).
        error: DoqError,
        /// A human-readable reason phrase sent in the `CONNECTION_CLOSE` frame.
        reason: Vec<u8>,
    },
}
