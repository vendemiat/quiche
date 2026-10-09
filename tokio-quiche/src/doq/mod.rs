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

//! Build a DNS over QUIC (DoQ) server with Tokio.
//!
//! Enable the `doq` feature to use this module. Application code accepts QUIC
//! connections and uses [`DoqController`] to receive events and request
//! connection closure. Query handlers send responses through [`DoqResponder`].
//! The connection's IO worker moves packets and drives DoQ through
//! [`DoqServerDriver`].
//!
//! # Configure the listener
//!
//! Begin with [`QuicSettings`](crate::settings::QuicSettings). Set
//! [`DOQ_ALPN`], choose flow-control and stream limits, and choose an idle
//! timeout. This example selects limits and disables early data. The values
//! are application choices:
//!
//! ```
//! use tokio_quiche::doq::DOQ_ALPN;
//! use tokio_quiche::settings::QuicSettings;
//!
//! let mut settings = QuicSettings::default();
//! settings.alpn = vec![DOQ_ALPN.to_vec()];
//! settings.enable_dgram = false;
//! settings.enable_early_data = false;
//! settings.initial_max_data = 1_048_576;
//! settings.initial_max_stream_data_bidi_local = 65_537;
//! settings.initial_max_stream_data_bidi_remote = 65_537;
//! settings.initial_max_streams_bidi = 16;
//! settings.initial_max_streams_uni = 0;
//! ```
//!
//! Pass the settings and TLS credentials to
//! [`ConnectionParams::new_server`](crate::settings::ConnectionParams::new_server),
//! then create a listener with [`listen`](crate::listen). See the
//! [`doq-tokio-server` example] for socket, certificate, and listener setup.
//!
//! # Start each accepted connection
//!
//! For each accepted connection, call [`DoqServerDriver::new`] to create a
//! driver and its paired [`DoqController`]. Choose a positive event capacity;
//! all query and connection events share this queue. Then pass the driver to
//! [`InitialQuicConnection::start`](crate::InitialQuicConnection::start).
//! This helper starts an accepted connection from a UDP listener and returns
//! the controller to application code:
//!
//! ```no_run
//! use tokio::net::UdpSocket;
//! use tokio_quiche::doq::DoqController;
//! use tokio_quiche::doq::DoqServerDriver;
//! use tokio_quiche::metrics::DefaultMetrics;
//! use tokio_quiche::InitialQuicConnection;
//! use tokio_quiche::QuicResult;
//!
//! fn start_connection(
//!     connection: InitialQuicConnection<UdpSocket, DefaultMetrics>,
//!     event_capacity: usize,
//! ) -> QuicResult<DoqController> {
//!     let (driver, controller) = DoqServerDriver::new(event_capacity)?;
//!     connection.start(driver);
//!     Ok(controller)
//! }
//! ```
//!
//! The IO worker owns the QUIC connection and driver. It handles packet input,
//! timers, and packet output. The driver calls the synchronous
//! [`quiche::doq::Connection`] to join message fragments, frame responses, and
//! enforce the [RFC 9250, Section 4.3.3] protocol-error rules. Application code
//! drives the controller's event receiver while the worker runs.
//!
//! ```text
//! UDP socket <--> [Connection IO worker: QUIC + DoqServerDriver]
//!                                              |
//!                                              | events (bounded)
//!                                              v
//!                                Application event-loop task
//!                                DoqController + event receiver
//!                                              |
//!                                              | query + responder
//!                                              v
//!                                      Query handler task
//!                                      DoqResponder
//!
//! DoqController -- close commands (unbounded) --> DoqServerDriver
//! DoqResponder -- response/reset (bounded per query) --> DoqServerDriver
//! ```
//!
//! Events use one bounded queue per connection. Responses and reset requests
//! use a separate bounded queue per query. Close commands use an unbounded
//! connection queue. The controller and responder are application handles;
//! the worker performs the corresponding QUIC operations.
//!
//! See [`DoqServerDriver::new`] for the event queue and its capacity,
//! [`DoqResponder::send`] and [`DoqResponder::reset`] for the query queue,
//! and [`DoqController::close_connection`] for the close-command queue.
//!
//! # Receive and dispatch queries
//!
//! Run an application task that owns the controller. Take its event receiver
//! once with [`DoqController::take_event_receiver`] and keep receiving events
//! while query handlers run. Each [`DoqEvent::Query`] contains the DNS message
//! without a length prefix, an `is_0rtt` flag, and a [`DoqResponder`] for that
//! query. The query uses its own bidirectional stream
//! ([RFC 9250, Section 4.2]); the responder keeps replies on that stream.
//!
//! This event loop passes queries to an application-supplied `dispatch`
//! function. That function must admit and schedule query work without waiting
//! for the response. Choose a separate limit for active query tasks and an
//! overload policy. Event capacity limits queued events; it does not bound
//! active tasks or total response memory.
//!
//! ```no_run
//! use bytes::Bytes;
//! use tokio_quiche::doq::DoqController;
//! use tokio_quiche::doq::DoqEvent;
//! use tokio_quiche::doq::DoqResponder;
//!
//! async fn receive_queries(
//!     mut controller: DoqController,
//!     mut dispatch: impl FnMut(Bytes, bool, DoqResponder),
//! ) {
//!     let Some(mut events) = controller.take_event_receiver() else {
//!         return;
//!     };
//!     while let Some(event) = events.recv().await {
//!         match event {
//!             DoqEvent::Query {
//!                 data,
//!                 is_0rtt,
//!                 responder,
//!             } => {
//!                 dispatch(data, is_0rtt, responder);
//!             },
//!             DoqEvent::ConnectionClosed => break,
//!             _ => {},
//!         }
//!     }
//! }
//! ```
//!
//! This snippet shows query dispatch. In the event loop, also handle peer
//! cancellation events and handshake confirmation as application policy
//! requires.
//! Parse and validate DNS in the query handler, then choose how to answer.
//! If early data is enabled, use `is_0rtt` to apply the DNS replay policy.
//! The driver does not select forwarding, transfer, padding, or replay policy.
//!
//! # Send the response from a query task
//!
//! Prepare a DNS response without a length prefix and call
//! [`DoqResponder::send`]. For one response, set `fin = true`:
//!
//! ```
//! use bytes::Bytes;
//! use tokio_quiche::doq::DoqResponder;
//! use tokio_quiche::doq::StreamClosed;
//!
//! async fn answer_query(
//!     responder: DoqResponder, response: Bytes,
//! ) -> Result<(), StreamClosed> {
//!     responder.send(response, true).await
//! }
//! ```
//!
//! For several responses, call `send` with `fin = false` for each earlier
//! message and `fin = true` for the final message. This supports the
//! multi-response stream used by zone transfers ([RFC 9250, Section 5.7]);
//! application code determines when the DNS transaction is complete.
//!
//! A DNS message, including its header, can contain at most 65,535 bytes.
//! The driver adds the two-byte DoQ prefix and preserves the message bytes.
//! `send` waits for space in the query's response queue. Success means the
//! queue accepted the response. The driver must still pass it to QUIC and
//! the worker must send packets. Success does not mean the peer received or
//! acknowledged the response.
//!
//! Keep the event loop running during response production. A full event queue
//! pauses the driver's application reads and writes. Response data remains
//! in responder queues and core DoQ buffers until event capacity is available.
//! Waiting for response sends in the event loop can therefore stop progress.
//! The driver flushes partial response writes when QUIC becomes writable;
//! the query task only needs to await `send`.
//!
//! # Stop a query or close the connection
//!
//! To abandon a query, await [`DoqResponder::reset`]. This queues a reset after
//! responses already in that query's queue. If application code drops the
//! responder without a final response or reset, the driver processes queued
//! responses and then resets the unfinished stream when it observes channel
//! closure.
//!
//! Use [`DoqResponder::closed`] to stop application work when its response
//! channel closes. It also resolves after the driver passes the final response
//! and FIN to QUIC, so it does not identify peer cancellation by itself.
//! Correlate [`DoqEvent::PeerStopped`] and [`DoqEvent::PeerReset`] with
//! [`DoqResponder::stream_id`] when the raw peer code is needed. Stops are
//! observed on response writes or flushes. A reset after the complete query
//! and FIN have been read can be suppressed by the transport; see
//! [`DoqResponder::closed`] for these visibility limits.
//!
//! Keep the event receiver alive while serving the connection. Dropping it
//! makes the driver initiate connection close. To request a close explicitly,
//! call [`DoqController::close_connection`] with a DoQ error and reason. It
//! queues a command without waiting for transport close. After taking the
//! receiver, application code can keep it in one task and retain the controller
//! elsewhere for close commands.
//!
//! Stop query work when the connection ends. Delivery of
//! [`DoqEvent::ConnectionClosed`] is best effort; responder cleanup does not
//! depend on that event. Driver failures use [`DoqConnectionError`]; the
//! controller does not retain the worker's terminal error. See the
//! [`doq-tokio-server` example] for a controller loop and concurrent handlers
//! with DNS validation, cancellation, and an application concurrency limit.
//!
//! [RFC 9250, Section 4]: https://datatracker.ietf.org/doc/html/rfc9250#section-4
//! [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
//! [RFC 9250, Section 4.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
//! [RFC 9250, Section 5.7]: https://datatracker.ietf.org/doc/html/rfc9250#section-5.7
//! [`doq-tokio-server` example]: ../../src/doq_tokio_server/main.rs.html

use std::fmt;

use bytes::Bytes;
use tokio::sync::mpsc;

mod driver;
#[cfg(test)]
pub mod test_utils;
#[cfg(test)]
mod tests;

pub use driver::DoqConnectionError;
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
/// The driver closed the responder channel after response completion,
/// local reset, observed cancellation, or connection closure. The consumer
/// should stop working on the query. This is also the condition
/// [`DoqResponder::closed`] reports; it does not carry a peer error code.
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
/// Complete the transaction by queuing a final [`send`](Self::send) call or
/// [`reset`](Self::reset). If the consumer drops the handle without queuing
/// either, the driver processes queued messages, then resets the unfinished
/// stream with [`DoqError::InternalError`] when it observes channel closure.
/// Observation can wait for buffered response writes or event capacity.
///
/// [`send`]: DoqResponder::send
#[derive(Debug)]
pub struct DoqResponder {
    stream_id: u64,
    tx: mpsc::Sender<ResponderMessage>,
}

impl DoqResponder {
    /// Wraps the sending end of a per-query channel. The driver owns the
    /// paired receiver and chooses the channel's bound.
    pub(crate) fn new(
        stream_id: u64, tx: mpsc::Sender<ResponderMessage>,
    ) -> Self {
        DoqResponder { stream_id, tx }
    }

    /// Returns the stream ID used to correlate peer cancellation events.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Queues one DNS response message for the query; the driver frames it
    /// with the 2-octet length prefix before sending.
    ///
    /// `data` is the raw DNS message *without* the length prefix and is sent
    /// verbatim (no padding or other mutation). `fin` marks the last response
    /// of the transaction: a single-response query sends one call with
    /// `fin = true`, while a zone transfer per [RFC 9250, Section 5.7] sends
    /// one or more `fin = false` calls followed by a final `fin = true`.
    ///
    /// Awaits channel capacity, applying backpressure to a producer that
    /// outruns the driver. Returns [`StreamClosed`] if the transaction is no
    /// longer live (see [`closed`](Self::closed)); the response is dropped.
    ///
    /// Success means the response entered the bounded channel. It does not
    /// mean the driver wrote it to QUIC or the peer received or acknowledged
    /// it. A final response closes the responder channel after the driver
    /// passes all response bytes and FIN to the transport, without waiting
    /// for a peer acknowledgement.
    ///
    /// `data` must be at most 65,535 bytes.
    /// [`quiche::doq::MAX_DOQ_MESSAGE_LEN`] includes the two-byte prefix.
    /// The channel accepts an oversized message; when the driver processes
    /// it, it resets the stream with [`DoqError::InternalError`] and closes
    /// the responder channel.
    ///
    /// [RFC 9250, Section 5.7]: https://datatracker.ietf.org/doc/html/rfc9250#section-5.7
    pub async fn send(&self, data: Bytes, fin: bool) -> Result<(), StreamClosed> {
        self.tx
            .send(ResponderMessage::Response { data, fin })
            .await
            .map_err(|_| StreamClosed)
    }

    /// Abandons the transaction, asking the driver to send `RESET_STREAM` with
    /// the given DoQ error code ([RFC 9250, Section 4.3.2]), typically
    /// [`DoqError::InternalError`].
    ///
    /// Uses the same bounded channel as [`send`](Self::send). It waits for
    /// capacity and follows responses already queued on that channel.
    /// Success means the reset was queued, not that it was applied or received
    /// by the peer. Returns [`StreamClosed`] if the transaction is no longer
    /// live.
    ///
    /// [RFC 9250, Section 4.3.2]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.2
    pub async fn reset(&self, error: DoqError) -> Result<(), StreamClosed> {
        self.tx
            .send(ResponderMessage::Reset { error })
            .await
            .map_err(|_| StreamClosed)
    }

    /// Resolves after response completion, local reset, observed peer
    /// cancellation, or connection cleanup. A consumer can `select!` on this
    /// to stop query work.
    ///
    /// Peer codes are available only in [`DoqEvent::PeerStopped`] and
    /// [`DoqEvent::PeerReset`]. A stop is observed on a response write or
    /// flush; it can remain unobserved while the application has no
    /// response data. A reset after the complete query and FIN have been
    /// read can be suppressed by the transport and does not close this
    /// channel.
    ///
    /// After this resolves, [`send`](Self::send) and [`reset`](Self::reset)
    /// return [`StreamClosed`].
    pub async fn closed(&self) {
        self.tx.closed().await
    }
}

/// An event emitted by a `DoqServerDriver` to its paired `DoqController`.
///
/// At most one event is emitted for each observed cancellation direction on
/// a stream. Peer codes are stored only in these events. Queue saturation
/// pauses application work; receiver drop or connection shutdown can prevent
/// delivery. See [`DoqServerDriver::new`] for the backpressure policy.
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
        /// [RFC 9250, Section 4.5] requires that a non-replayable transaction
        /// received in 0-RTT MUST NOT be processed
        /// immediately. The driver does not parse opcodes itself; it surfaces
        /// this flag so the consumer can enforce the replay rules (see
        /// [`is_replayable_opcode`]).
        ///
        /// [RFC 9250, Section 4.5]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
        is_0rtt: bool,

        /// The per-query handle used to send the response(s); bound to this
        /// query's stream.
        responder: DoqResponder,
    },

    /// The QUIC handshake has been confirmed (the connection is no longer only
    /// in early data).
    ///
    /// [RFC 9250, Section 4.5] allows a consumer that deferred non-replayable
    /// 0-RTT queries (rather than
    /// rejecting them outright) can use this event as the signal to process
    /// its queue.
    ///
    /// [RFC 9250, Section 4.5]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.5
    HandshakeConfirmed,

    /// The QUIC connection has closed. Delivery is best effort, including
    /// when the event queue is full. Query cleanup does not depend on delivery.
    ConnectionClosed,

    /// The peer's `STOP_SENDING` was observed on a response write or flush.
    ///
    /// The responder channel is closed before this event is queued. No extra
    /// checks are made while a query is waiting for application response data.
    PeerStopped {
        /// The query's stream ID, also available on its responder.
        stream_id: u64,
        /// The raw peer application error code, including unknown codes.
        code: u64,
    },

    /// The transport exposed a peer `RESET_STREAM`.
    ///
    /// This can occur without a preceding `Query` event. A reset after the
    /// complete query and FIN have been read can be suppressed by the
    /// transport. Any tracked responder channel is closed before this event
    /// is queued.
    PeerReset {
        /// The reset stream ID.
        stream_id: u64,
        /// The raw peer application error code, including unknown codes.
        code: u64,
    },
}

/// A command sent from a `DoqController` to its paired `DoqServerDriver`.
///
/// Per-query operations use [`DoqResponder`]. Peer cancellation codes use
/// [`DoqEvent`]. `DoqCommand` carries connection-level operations only.
#[derive(Debug)]
#[non_exhaustive]
pub enum DoqCommand {
    /// Close the whole connection with a DoQ error code and reason.
    ///
    /// Used for fatal protocol violations ([RFC 9250, Section 4.3.3]) and for
    /// normal shutdown ([`DoqError::NoError`]).
    ///
    /// `reason` is an opaque byte string (the QUIC CONNECTION_CLOSE reason
    /// phrase, [RFC 9000, Section 19.19]). It matches the byte-oriented
    /// [`quiche::Connection::close`] API and the crate's existing
    /// [`ConnectionShutdownBehaviour`](crate::quic::ConnectionShutdownBehaviour)
    /// `reason` field.
    ///
    /// [RFC 9250, Section 4.3.3]: https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.3
    /// [RFC 9000, Section 19.19]: https://datatracker.ietf.org/doc/html/rfc9000#section-19.19
    CloseConnection {
        /// The DoQ error code (wire-encoded via [`DoqError::to_wire`]).
        error: DoqError,
        /// A human-readable reason phrase sent in the `CONNECTION_CLOSE` frame.
        reason: Vec<u8>,
    },
}
