//! Bidirectional pump through two wire directions.
//!
//! Each direction runs as its own pump future: a blocked guest-bound write
//! never stalls the reading of upstream bytes, and the other way around. The
//! request pump talks to the response pump over one FIFO channel (protocol
//! replies, framing facts, and the request direction's terminal intent —
//! ordering inside the channel replaces any select priority), and the
//! response pump ends the request pump through a oneshot completion signal.

use std::io::{Error as IoError, ErrorKind};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, split};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::Error;
use crate::transports::engine::{Hit, Rewritten, Wire};

/// Guest-bound work and terminal intent, request pump → response pump.
/// FIFO order is the contract: replies and framing facts queued before a
/// terminal message are applied before it is honored.
enum ToResponse {
  /// Guest-bound protocol reply (Postgres negotiation refusals).
  Reply(Vec<u8>),
  /// Framing fact from the request machine (HEAD requests suppress bodies).
  PeerNote(usize),
  /// The request direction failed or failed closed: end the relay now.
  RequestsEnded,
}

/// Bidirectional relay through the two directions' wire formats. Guest FIN
/// flushes the downstream direction, then upstream shutdown while still
/// draining upstream→guest; upstream close flushes the upstream direction
/// and ends the relay.
pub(crate) async fn relay_guarded<G, S, M>(guest: G, server: S, downstream: &mut M, upstream: &mut M, first: &[u8]) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let (guest_read, guest_write) = split(guest);
  let (server_read, server_write) = split(server);
  let (to_responses_tx, to_responses_rx) = mpsc::unbounded_channel();
  let (responses_done_tx, responses_done_rx) = oneshot::channel();
  let (requests, responses) = tokio::join!(
    pump_requests(guest_read, server_write, downstream, to_responses_tx, responses_done_rx, first),
    pump_responses(server_read, guest_write, upstream, to_responses_rx, responses_done_tx),
  );
  requests.or(responses)
}

/// Tell the response pump the request direction ended the relay. A closed
/// channel means it already ended itself; the relay is closing either way.
fn end_requests(responses: &mpsc::UnboundedSender<ToResponse>) {
  let _ = responses.send(ToResponse::RequestsEnded);
}

/// Guest→upstream direction: read the guest, feed the downstream machine,
/// carry rewritten bytes upstream, hand replies and framing facts to the
/// response pump.
async fn pump_requests<R, W, M>(
  mut guest: R,
  mut server: W,
  downstream: &mut M,
  responses: mpsc::UnboundedSender<ToResponse>,
  mut responses_done: oneshot::Receiver<()>,
  first: &[u8],
) -> Result<(), Error>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
  M: Wire,
{
  if !first.is_empty() && !pump_first(&mut server, downstream, &responses, &mut responses_done, first).await? {
    return Ok(());
  }
  let mut buf = vec![0u8; 32 * 1024];
  loop {
    tokio::select! {
      _ = &mut responses_done => return Ok(()),
      result = guest.read(&mut buf) => {
        // rustls surfaces a peer FIN without close_notify as UnexpectedEof;
        // for a relay that is a normal end-of-stream, not an error.
        let result = match result {
          Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
          other => other,
        };
        match result {
          Ok(0) => {
            let (rewritten, hits) = downstream.feed(&[]).await;
            hand_over(&responses, downstream);
            log_hits(&hits);
            if let Rewritten::Emit(flushed) = rewritten {
              write_or_stopped(
                &mut server,
                &flushed,
                &mut responses_done,
                |source| request_flush_error(&responses, source),
              )
              .await?;
            }
            // Upstream may already have closed its write side; a failed
            // shutdown must not abort the relay — keep draining the
            // response direction.
            let _ = server.shutdown().await;
            return Ok(());
          }
          Ok(n) => {
            let (rewritten, hits) = downstream.feed(&buf[..n]).await;
            hand_over(&responses, downstream);
            log_hits(&hits);
            match rewritten {
              Rewritten::Close => {
                end_requests(&responses);
                return Ok(());
              }
              Rewritten::Hold => {}
              Rewritten::Emit(out) => {
                write_or_stopped(&mut server, &out, &mut responses_done, |source| {
                  request_chunk_error(&responses, source)
                })
                .await?;
              }
            }
          }
          Err(err) => {
            end_requests(&responses);
            return Err(Error::GuestRead { source: err });
          }
        }
      }
    }
  }
}

/// Feed the replayed first bytes downstream and carry the first chunk
/// upstream. Returns `false` when the downstream direction already ended the
/// relay.
async fn pump_first<W, M>(
  server: &mut W,
  downstream: &mut M,
  responses: &mpsc::UnboundedSender<ToResponse>,
  responses_done: &mut oneshot::Receiver<()>,
  first: &[u8],
) -> Result<bool, Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  let (rewritten, hits) = downstream.feed(first).await;
  hand_over(responses, downstream);
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => {
      end_requests(responses);
      Ok(false)
    }
    Rewritten::Hold => Ok(true),
    Rewritten::Emit(out) => {
      write_or_stopped(server, &out, responses_done, |source| request_head_error(responses, source)).await?;
      server.flush().await.map_err(|source| Error::RequestHeadFlush { source })?;
      Ok(true)
    }
  }
}

/// Upstream→guest direction: read the upstream, feed the upstream machine,
/// carry rewritten bytes to the guest, apply what the request pump queued.
async fn pump_responses<R, W, M>(
  mut server: R,
  mut guest: W,
  upstream: &mut M,
  mut requests: mpsc::UnboundedReceiver<ToResponse>,
  responses_done: oneshot::Sender<()>,
) -> Result<(), Error>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
  M: Wire,
{
  let mut buf = vec![0u8; 32 * 1024];
  let mut requests_open = true;
  let outcome = loop {
    tokio::select! {
      msg = requests.recv(), if requests_open => match msg {
        Some(ToResponse::RequestsEnded) => break Ok(()),
        Some(msg) => apply_message(&mut guest, upstream, msg).await?,
        None => requests_open = false,
      },
      result = server.read(&mut buf) => {
        // rustls surfaces a peer FIN without close_notify as UnexpectedEof;
        // for a relay that is a normal end-of-stream, not an error.
        let result = match result {
          Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
          other => other,
        };
        match result {
          Ok(0) => {
            // Replies queued before the request direction shut down must
            // reach the guest before the relay ends.
            if drain_requests(&mut guest, upstream, &mut requests).await? {
              break Ok(());
            }
            let (rewritten, hits) = upstream.feed(&[]).await;
            log_hits(&hits);
            break match rewritten {
              Rewritten::Close | Rewritten::Hold => Ok(()),
              Rewritten::Emit(flushed) => {
                guest.write_all(&flushed).await.map_err(|source| Error::ResponseFlushToGuest { source })?;
                Ok(())
              }
            };
          }
          Ok(n) => {
            // Replies and framing facts queue before the upstream bytes that
            // answer them; drain the channel before handling upstream data.
            if drain_requests(&mut guest, upstream, &mut requests).await? {
              break Ok(());
            }
            let (rewritten, hits) = upstream.feed(&buf[..n]).await;
            log_hits(&hits);
            match rewritten {
              Rewritten::Close => {
                // Scan-only path hit a needle it could not rewrite: drop the
                // chunk and the connection rather than leak the real value.
                break Ok(());
              }
              Rewritten::Hold => {}
              Rewritten::Emit(out) => {
                guest.write_all(&out).await.map_err(|source| Error::ResponseChunkToGuest { source })?;
                guest.flush().await.map_err(|source| Error::GuestFlush { source })?;
              }
            }
          }
          Err(err) => break Err(Error::UpstreamRead { source: err }),
        }
      }
    }
  };
  let _ = responses_done.send(());
  match outcome {
    Ok(()) => {
      guest.flush().await.map_err(|source| Error::FinalGuestFlush { source })?;
      let _ = guest.shutdown().await;
      Ok(())
    }
    Err(err) => Err(err),
  }
}

/// Apply one queued message from the request pump: a guest-bound protocol
/// reply or a framing fact into the response machine.
async fn apply_message<W, M>(guest: &mut W, upstream: &mut M, msg: ToResponse) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  match msg {
    ToResponse::Reply(reply) => {
      guest
        .write_all(&reply)
        .await
        .map_err(|source| Error::ProtocolReplyToGuest { source })?;
      guest.flush().await.map_err(|source| Error::ProtocolReplyFlush { source })?;
    }
    ToResponse::PeerNote(n) => upstream.apply_peer_note(n),
    ToResponse::RequestsEnded => {}
  }
  Ok(())
}

/// Apply everything the request pump queued. Returns `true` when the request
/// direction's terminal intent arrived: end the relay before upstream data.
async fn drain_requests<W, M>(guest: &mut W, upstream: &mut M, requests: &mut mpsc::UnboundedReceiver<ToResponse>) -> Result<bool, Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  while let Ok(msg) = requests.try_recv() {
    if matches!(msg, ToResponse::RequestsEnded) {
      return Ok(true);
    }
    apply_message(guest, upstream, msg).await?;
  }
  Ok(false)
}

/// Hand the response pump a queued protocol reply and any framing fact. A
/// closed channel means the response direction already ended; the relay is
/// closing, so dropping the reply is correct.
fn hand_over<M: Wire>(responses: &mpsc::UnboundedSender<ToResponse>, downstream: &mut M) {
  if let Some(reply) = downstream.take_reply() {
    let _ = responses.send(ToResponse::Reply(reply));
  }
  let pending = downstream.take_peer_note();
  if pending > 0 {
    let _ = responses.send(ToResponse::PeerNote(pending));
  }
}

/// Write that abandons the direction when the response direction ended: a
/// half-finished write is fine, the connection is closing anyway. `None`
/// means stopped before completion.
async fn write_or_stopped<W, F>(
  sink: &mut W,
  bytes: &[u8],
  responses_done: &mut oneshot::Receiver<()>,
  into_error: F,
) -> Result<Option<()>, Error>
where
  W: AsyncWrite + Unpin,
  F: FnOnce(IoError) -> Error,
{
  tokio::select! {
    result = sink.write_all(bytes) => match result {
      Ok(()) => Ok(Some(())),
      Err(source) => Err(into_error(source)),
    },
    _ = &mut *responses_done => Ok(None),
  }
}

/// Terminal intent rides with the error: the response pump must learn the
/// relay ended even when the request pump unwinds early.
fn request_flush_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestFlushToUpstream { source }
}

/// Terminal intent rides with the error: the response pump must learn the
/// relay ended even when the request pump unwinds early.
fn request_chunk_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestChunkToUpstream { source }
}

/// Terminal intent rides with the error: the response pump must learn the
/// relay ended even when the request pump unwinds early.
fn request_head_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestHeadToUpstream { source }
}

pub(crate) fn log_hits(hits: &[Hit]) {
  for hit in hits {
    tracing::debug!(label = %hit.label, location = ?hit.location, "substituted");
  }
}
