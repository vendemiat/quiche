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

//! Unit tests for [`DoqServerDriver`](super::DoqServerDriver).
//!
//! Framing/protocol-error edge cases (split length prefix, truncated FIN,
//! second query, partial-write reassembly) are covered at the
//! `quiche::doq::Connection` level (`quiche/src/doq/connection.rs`); these
//! tests only exercise driver-level concerns that sit above `Connection`.
//!
//! `process_reads` always runs before `process_writes` within one
//! `work_loop_iter`/`advance_and_run_loop` round, and `process_writes`
//! sends `DoqEvent::HandshakeConfirmed` on its first call ever. So a
//! `Query` sent to the peer before that first round is always enqueued
//! ahead of `HandshakeConfirmed`, but tests that don't expect a `Query` in
//! their first round must still account for that leftover
//! `HandshakeConfirmed` sitting in the channel afterwards.

use std::future::Future as _;
use std::task::Context;
use std::task::Poll;

use bytes::Bytes;
use futures::FutureExt as _;
use quiche::doq;
use quiche::doq::DoqError;
use tokio::sync::mpsc::error::TryRecvError;

use super::test_utils::DoqDriverTestHelper;
use super::StreamClosed;
use crate::ApplicationOverQuic as _;

#[tokio::test]
async fn query_event_and_response_roundtrip() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_id = helper.peer_send_query(b"hello").unwrap();
    helper.advance_and_run_loop().unwrap();

    let (data, is_0rtt, responder) = helper.expect_query_event();
    assert_eq!(data, Bytes::from_static(b"hello"));
    assert!(!is_0rtt);

    responder
        .send(Bytes::from_static(b"world"), true)
        .await
        .unwrap();
    helper.advance_and_run_loop().unwrap();

    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_id, doq::Event::Response {
            data: b"world".to_vec()
        }))
    );
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_id, doq::Event::Finished))
    );
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Err(doq::Error::Done)
    );
}

#[tokio::test]
async fn multi_response_zone_transfer() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_id = helper.peer_send_query(b"axfr").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (_, _, responder) = helper.expect_query_event();

    for chunk in [&b"r1"[..], &b"r2"[..], &b"r3"[..]] {
        let fin = chunk == b"r3";
        responder
            .send(Bytes::copy_from_slice(chunk), fin)
            .await
            .unwrap();
        helper.advance_and_run_loop().unwrap();
    }

    for chunk in [&b"r1"[..], &b"r2"[..], &b"r3"[..]] {
        assert_eq!(
            helper.peer.poll(&mut helper.pipe.client),
            Ok((stream_id, doq::Event::Response {
                data: chunk.to_vec()
            }))
        );
    }
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_id, doq::Event::Finished))
    );
}

/// Per-query backpressure: with the test-only responder channel capacity
/// of 1, a second `send()` on the same responder blocks until the driver
/// drains the first message, then completes once it does.
///
/// Polled manually (rather than via `tokio::spawn` + a real/virtual
/// timeout) so the assertion is deterministic: a `Future` that hasn't
/// resolved is directly observable as `Poll::Pending`, with no dependency
/// on the runtime actually scheduling a second task.
#[tokio::test]
async fn backpressure_blocks_second_send_until_drained() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    helper.peer_send_query(b"axfr").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (_, _, responder) = helper.expect_query_event();

    responder
        .send(Bytes::from_static(b"r1"), false)
        .await
        .unwrap();

    let mut second_send =
        Box::pin(responder.send(Bytes::from_static(b"r2"), true));
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert_eq!(second_send.as_mut().poll(&mut cx), Poll::Pending);

    // Drains "r1", freeing the one slot in the bounded channel.
    helper.work_loop_iter().unwrap();

    assert_eq!(second_send.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
}

#[tokio::test]
async fn concurrent_out_of_order_responses() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_a = helper.peer_send_query(b"q1").unwrap();
    let stream_b = helper.peer_send_query(b"q2").unwrap();
    helper.advance_and_run_loop().unwrap();

    let (data_first, _, responder_first) = helper.expect_query_event();
    let (_, _, responder_second) = helper.expect_query_event();

    let (stream_q1, responder_q1, stream_q2, responder_q2) =
        if data_first == Bytes::from_static(b"q1") {
            (stream_a, responder_first, stream_b, responder_second)
        } else {
            (stream_a, responder_second, stream_b, responder_first)
        };

    // Answer the second query first.
    responder_q2
        .send(Bytes::from_static(b"resp-q2"), true)
        .await
        .unwrap();
    helper.advance_and_run_loop().unwrap();

    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_q2, doq::Event::Response {
            data: b"resp-q2".to_vec()
        }))
    );
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_q2, doq::Event::Finished))
    );

    responder_q1
        .send(Bytes::from_static(b"resp-q1"), true)
        .await
        .unwrap();
    helper.advance_and_run_loop().unwrap();

    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_q1, doq::Event::Response {
            data: b"resp-q1".to_vec()
        }))
    );
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_q1, doq::Event::Finished))
    );
}

#[tokio::test]
async fn stop_sending_does_not_release_peer_bidi_stream_credit() {
    let mut config = super::test_utils::default_quiche_config();
    config.set_initial_max_streams_bidi(2);
    let mut helper = DoqDriverTestHelper::with_pipe(
        quiche::test_utils::Pipe::with_config_and_buf(&mut config).unwrap(),
    )
    .unwrap();
    let credits = helper.pipe.client.peer_streams_left_bidi();

    for _ in 0..credits {
        let stream_id = helper.peer_send_query(b"q").unwrap();
        helper.advance_and_run_loop().unwrap();
        helper
            .pipe
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
    }

    assert_eq!(
        helper.peer_send_query(b"q").unwrap_err().downcast_ref(),
        Some(&quiche::Error::StreamLimit)
    );
}

#[tokio::test]
async fn handshake_confirmed_emitted_once() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    helper.work_loop_iter().unwrap();
    assert!(matches!(
        helper.try_recv_event(),
        Ok(super::DoqEvent::HandshakeConfirmed)
    ));

    helper.work_loop_iter().unwrap();
    assert!(matches!(helper.try_recv_event(), Err(TryRecvError::Empty)));
}

/// A client that resets a stream before finishing its query never gets a
/// responder created for it, so there's nothing to clean up on the
/// driver's side, and the connection keeps working normally afterwards.
#[tokio::test]
async fn client_reset_before_query_completes_is_noop() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let abandoned = helper.next_stream_id();
    helper
        .pipe
        .client
        .stream_send(abandoned, b"partial", false)
        .unwrap();
    helper
        .pipe
        .client
        .stream_shutdown(abandoned, quiche::Shutdown::Write, 42)
        .unwrap();
    helper.advance_and_run_loop().unwrap();

    // RFC 9250, Section 4.3.1 requires the server to echo the client's
    // RESET_STREAM; the raw client-role peer connection observes it here.
    // https://datatracker.ietf.org/doc/html/rfc9250#section-4.3.1
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((abandoned, doq::Event::Reset(42)))
    );

    // No `Query` was ever emitted for the abandoned stream; the only event
    // in the channel is the `HandshakeConfirmed` from this first round.
    assert!(matches!(
        helper.try_recv_event(),
        Ok(super::DoqEvent::HandshakeConfirmed)
    ));
    assert!(matches!(helper.try_recv_event(), Err(TryRecvError::Empty)));

    // The connection is otherwise unaffected: a fresh query still works.
    let stream_id = helper.peer_send_query(b"still works").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (data, _, responder) = helper.expect_query_event();
    assert_eq!(data, Bytes::from_static(b"still works"));

    responder
        .send(Bytes::from_static(b"ok"), true)
        .await
        .unwrap();
    helper.advance_and_run_loop().unwrap();
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((stream_id, doq::Event::Response {
            data: b"ok".to_vec()
        }))
    );
}

/// A client `STOP_SENDING` on the response direction surfaces to
/// `send_response` as `Error::TransportError(StreamStopped)`, which
/// `handle_write_error` treats as a benign per-stream close: the
/// responder's `closed()` resolves and further `send`/`reset` calls
/// return `StreamClosed`.
#[tokio::test]
async fn client_stop_sending_resolves_responder_closed() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_id = helper.peer_send_query(b"q").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (_, _, responder) = helper.expect_query_event();

    helper
        .pipe
        .client
        .stream_shutdown(stream_id, quiche::Shutdown::Read, 7)
        .unwrap();
    helper.pipe.advance().unwrap();

    responder
        .send(Bytes::from_static(b"resp"), true)
        .await
        .unwrap();
    helper.work_loop_iter().unwrap();

    assert!(responder.closed().now_or_never().is_some());
    assert_eq!(
        responder.send(Bytes::from_static(b"too-late"), true).await,
        Err(StreamClosed)
    );
}

/// A response too large to frame (`Error::MessageTooLarge`, only possible
/// from `send_response`) abandons just that one transaction via
/// `reset_stream`, without affecting the rest of the connection.
#[tokio::test]
async fn message_too_large_resets_stream() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_id = helper.peer_send_query(b"q").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (_, _, responder) = helper.expect_query_event();

    let oversized = Bytes::from(vec![0u8; 65536]);
    responder.send(oversized, true).await.unwrap();
    helper.advance_and_run_loop().unwrap();

    // The driver maps `MessageTooLarge` to a stream reset with the wire
    // error `DoqError::InternalError`, which the peer observes here.
    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((
            stream_id,
            doq::Event::Reset(DoqError::InternalError.to_wire())
        ))
    );
    assert!(responder.closed().now_or_never().is_some());
}

/// Dropping the whole `DoqController` (both halves: the command sender and
/// the event receiver) makes `wait_for_data` close the connection via the
/// `event_sender.closed()` branch, and a second call afterwards must not
/// panic.
#[tokio::test]
async fn controller_drop_closes_connection_without_panicking() {
    // Destructured (rather than `drop(helper.controller)`) so dropping one
    // field doesn't leave `helper` partially moved and unusable for the
    // `driver`/`pipe` calls below.
    let helper = DoqDriverTestHelper::new().unwrap();
    let DoqDriverTestHelper {
        mut pipe,
        mut driver,
        controller,
        ..
    } = helper;
    drop(controller);

    driver.process_reads(&mut pipe.server).unwrap();
    driver.process_writes(&mut pipe.server).unwrap();
    tokio::task::unconstrained(driver.wait_for_data(&mut pipe.server))
        .now_or_never()
        .unwrap_or(Ok(()))
        .unwrap();

    let err = pipe
        .server
        .local_error()
        .expect("driver should have closed the connection");
    assert!(err.is_app);
    assert_eq!(err.error_code, DoqError::NoError.to_wire());

    // A second round must not panic.
    driver.process_reads(&mut pipe.server).unwrap();
    driver.process_writes(&mut pipe.server).unwrap();
    tokio::task::unconstrained(driver.wait_for_data(&mut pipe.server))
        .now_or_never()
        .unwrap_or(Ok(()))
        .unwrap();
}

#[tokio::test]
async fn close_connection_command() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    helper
        .controller
        .close_connection(DoqError::ProtocolError, b"bye".to_vec());
    helper.work_loop_iter().unwrap();

    let err = helper
        .pipe
        .server
        .local_error()
        .expect("CloseConnection command should close the connection");
    assert!(err.is_app);
    assert_eq!(err.error_code, DoqError::ProtocolError.to_wire());
    assert_eq!(err.reason, b"bye");
}

/// A fatal protocol violation detected by `quiche::doq::Connection::poll`
/// (here: a truncated STREAM FIN) makes `process_reads` close the whole
/// connection with `DoqError::ProtocolError`, not just fail the one stream.
#[tokio::test]
async fn protocol_error_closes_connection() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_id = helper.next_stream_id();
    let mut wire = Vec::new();
    doq::write_dns_message(&mut wire, b"hello").unwrap();
    // Send everything but the last byte, with FIN: a truncated message.
    helper
        .pipe
        .client
        .stream_send(stream_id, &wire[..wire.len() - 1], true)
        .unwrap();
    helper.advance_and_run_loop().unwrap();

    let err = helper
        .pipe
        .server
        .local_error()
        .expect("truncated FIN should be a fatal protocol error");
    assert!(err.is_app);
    assert_eq!(err.error_code, DoqError::ProtocolError.to_wire());
    assert_eq!(err.reason, b"DoQ protocol error");
}

/// Exercise the driver's partial-write path. Limit the server's response
/// stream window to 20 bytes and send a 200-byte response, so
/// `send_response` can write only the prefix and must retain the remainder.
/// Each `advance_and_run_loop` then provides the peer's window update and
/// gives `flush_stream` a chance to send more bytes. The peer must receive
/// one complete response followed by `Finished`, rather than a truncated or
/// duplicated response.
#[tokio::test]
async fn partial_write_parks_and_flushes_on_writable() {
    let mut config = super::test_utils::default_quiche_config();
    config.set_initial_max_stream_data_bidi_local(20);

    let mut helper = DoqDriverTestHelper::with_pipe(
        quiche::test_utils::Pipe::with_config_and_buf(&mut config).unwrap(),
    )
    .unwrap();

    let stream_id = helper.peer_send_query(b"q").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (_, _, responder) = helper.expect_query_event();

    let large = Bytes::from(vec![b'x'; 200]);
    responder.send(large.clone(), true).await.unwrap();

    let mut got_response = None;
    let mut got_finished = false;
    for _ in 0..50 {
        helper.advance_and_run_loop().unwrap();

        loop {
            match helper.peer.poll(&mut helper.pipe.client) {
                Ok((id, doq::Event::Response { data })) => {
                    assert_eq!(id, stream_id);
                    assert!(
                        got_response.is_none(),
                        "expected exactly one Response"
                    );
                    got_response = Some(data);
                },
                Ok((id, doq::Event::Finished)) => {
                    assert_eq!(id, stream_id);
                    // Finished is emitted once, after all response bytes drain.
                    got_finished = true;
                },
                Err(doq::Error::Done) => break,
                other => panic!("unexpected event: {other:?}"),
            }
        }

        if got_finished {
            break;
        }
    }

    assert!(got_finished, "did not receive Finished within 50 rounds");
    assert_eq!(got_response, Some(large.to_vec()));
}

/// `DoqResponder::reset` abandons the transaction with `RESET_STREAM`
/// carrying the given error code, and resolves the responder's `closed()`.
#[tokio::test]
async fn responder_reset_sends_reset_stream() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_id = helper.peer_send_query(b"q").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (_, _, responder) = helper.expect_query_event();

    responder.reset(DoqError::RequestCancelled).await.unwrap();
    helper.advance_and_run_loop().unwrap();

    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((
            stream_id,
            doq::Event::Reset(DoqError::RequestCancelled.to_wire())
        ))
    );
    assert!(responder.closed().now_or_never().is_some());
}

/// A consumer that drops its `DoqResponder` without a final `send`/`reset`
/// call abandons the transaction: the driver resets the stream with
/// `DoqError::InternalError` rather than leaving it open indefinitely.
#[tokio::test]
async fn dropped_responder_without_final_call_resets_stream() {
    let mut helper = DoqDriverTestHelper::new().unwrap();

    let stream_id = helper.peer_send_query(b"q").unwrap();
    helper.advance_and_run_loop().unwrap();
    let (_, _, responder) = helper.expect_query_event();

    drop(responder);
    helper.advance_and_run_loop().unwrap();

    assert_eq!(
        helper.peer.poll(&mut helper.pipe.client),
        Ok((
            stream_id,
            doq::Event::Reset(DoqError::InternalError.to_wire())
        ))
    );
}
