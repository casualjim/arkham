//! Cleartext SMTP opening, then the shared relay.
//!
//! The greeting, `EHLO` / `HELO`, an `AUTH` that still precedes `STARTTLS`,
//! and `STARTTLS` plus its acceptance run lockstep. The acceptance reader
//! stops on the final reply line, so the following handshake bytes stay
//! unread. After the upgrade, or when the guest sends anything else, both
//! sockets go to [`relay_guarded`]. Implicit TLS skips the opening. A
//! session that never upgrades relays with swapping off, and the decoy
//! passes through.

use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use arkham_config::grants::{Grant, SmtpScope};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use super::SmtpTransport;
use super::machine::{MAX_COMMAND, Smtp};
use crate::Error;
use crate::relay::{log_hits, relay_guarded};
use crate::transports::TlsHalves;
use crate::transports::engine::{Direction, Rewritten, Wire};

/// Guest socket, cleartext or terminated TLS.
pub(super) enum GuestLeg<G> {
  /// Bytes still in the clear.
  Plain(G),
  /// TLS terminated with a leaf minted for the grant host.
  Tls(Box<ServerTlsStream<G>>),
}

/// Upstream socket, cleartext or TLS.
pub(super) enum ServerLeg {
  /// Bytes still in the clear.
  Plain(TcpStream),
  /// TLS to the real server.
  Tls(Box<ClientTlsStream<TcpStream>>),
}

impl<G> GuestLeg<G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  fn is_plain(&self) -> bool {
    matches!(self, Self::Plain(_))
  }
}

impl<G> AsyncRead for GuestLeg<G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
    }
  }
}

impl<G> AsyncWrite for GuestLeg<G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
    }
  }
}

impl ServerLeg {
  fn is_plain(&self) -> bool {
    matches!(self, Self::Plain(_))
  }
}

impl AsyncRead for ServerLeg {
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for ServerLeg {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
    }
  }
}

/// One SMTP dialogue: both sockets, the grant that keys the swap, and
/// the handshake budget.
pub(super) struct Dialogue<'a, G> {
  /// Transport that mints the guest leaf and dials upstream TLS.
  pub(super) transport: &'a SmtpTransport,
  /// Both legs of the matched rule.
  pub(super) scope: &'a SmtpScope,
  /// Guest socket, cleartext or already terminated.
  pub(super) guest: GuestLeg<G>,
  /// Upstream socket, cleartext or already encrypted.
  pub(super) server: ServerLeg,
  /// Grants the framing machines may swap.
  pub(super) grants: &'a [Grant],
  /// Host the leaf is minted for and the swap is keyed on.
  pub(super) host: &'a str,
  /// Port the swap is keyed on.
  pub(super) port: u16,
  /// Budget for a mid-stream TLS handshake.
  pub(super) budget: Duration,
}

/// Run the dialogue. Implicit TLS is already settled and goes straight to
/// the relay. A cleartext guest reads the opening, then relays.
///
/// # Errors
///
/// Returns an error when a leg cannot be read, written, or upgraded.
/// A framing machine that closes, or a peer that hangs up, ends quietly.
pub(super) async fn run<G>(dialogue: Dialogue<'_, G>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let Dialogue {
    transport,
    scope,
    guest,
    server,
    grants,
    host,
    port,
    budget,
  } = dialogue;
  let mut down = Smtp::new(grants, host, port, Direction::Downstream);
  // Swap only when the upstream writer is already TLS (`smtps://`). A
  // cleartext `smtp://` session forwards the decoy until STARTTLS completes.
  down.set_protected(scope.is_upstream_tls);
  let mut up = Smtp::new(grants, host, port, Direction::Upstream);
  if !guest.is_plain() {
    return relay_guarded(guest, server, &mut down, &mut up, &[]).await;
  }
  Opening {
    transport,
    scope,
    guest,
    server,
    down: &mut down,
    up: &mut up,
    leaf: host,
    budget,
  }
  .run()
  .await
}

/// Cleartext sockets plus the machines they hand to the relay.
struct Opening<'a, G> {
  transport: &'a SmtpTransport,
  scope: &'a SmtpScope,
  guest: GuestLeg<G>,
  server: ServerLeg,
  down: &'a mut Smtp,
  up: &'a mut Smtp,
  leaf: &'a str,
  budget: Duration,
}

impl<G> Opening<'_, G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  /// Greeting, then pre-transaction commands, until `STARTTLS` or a command
  /// the relay should own. `AUTH` stays here so a refusal before the upgrade
  /// can still be followed by `STARTTLS` on the same sockets.
  async fn run(mut self) -> Result<(), Error> {
    let Some(greeting) = acceptance_reply(&mut self.server)
      .await
      .map_err(|source| Error::UpstreamRead { source })?
    else {
      return Ok(());
    };
    write_guest(&mut self.guest, &greeting).await?;
    loop {
      let Some(line) = guest_line(&mut self.guest).await.map_err(|source| Error::GuestRead { source })? else {
        return Ok(());
      };
      if verb_is(&line, b"STARTTLS") {
        return self.starttls(&line).await;
      }
      if self.down.awaiting_auth_payload() || is_opening_command(&line) {
        match forward_down(self.down, &mut self.server, &line).await? {
          Forwarded::Stop => return Ok(()),
          Forwarded::Held => return relay_guarded(self.guest, self.server, self.down, self.up, &[]).await,
          Forwarded::Sent => {}
        }
        let Some(reply) = acceptance_reply(&mut self.server)
          .await
          .map_err(|source| Error::UpstreamRead { source })?
        else {
          return Ok(());
        };
        write_guest(&mut self.guest, &reply).await?;
        continue;
      }
      return relay_guarded(self.guest, self.server, self.down, self.up, &line).await;
    }
  }

  /// Forward `STARTTLS` when the upstream leg is still clear, or answer it
  /// locally when that leg is already TLS. Either way the sockets then relay.
  async fn starttls(mut self, line: &[u8]) -> Result<(), Error> {
    if self.server.is_plain() {
      write_server(&mut self.server, line).await?;
      let Some(reply) = acceptance_reply(&mut self.server)
        .await
        .map_err(|source| Error::UpstreamRead { source })?
      else {
        return Ok(());
      };
      write_guest(&mut self.guest, &reply).await?;
      if is_220(&reply) {
        let guest = upgrade_guest(self.transport, self.scope, self.guest, self.leaf, self.budget).await?;
        let server = upgrade_server(self.transport, self.scope, self.server, self.budget).await?;
        self.down.set_protected(true);
        return relay_guarded(guest, server, self.down, self.up, &[]).await;
      }
    } else if self.guest.is_plain() {
      self.down.queue_starttls_ready();
      if let Some(reply) = self.down.take_reply() {
        write_guest(&mut self.guest, &reply).await?;
      }
      let guest = upgrade_guest(self.transport, self.scope, self.guest, self.leaf, self.budget).await?;
      self.down.set_protected(true);
      return relay_guarded(guest, self.server, self.down, self.up, &[]).await;
    }
    relay_guarded(self.guest, self.server, self.down, self.up, &[]).await
  }
}

/// What one downstream feed did with a complete opening line.
enum Forwarded {
  /// The line was written upstream.
  Sent,
  /// The machine kept the line. The relay continues from there.
  Held,
  /// The machine closed the connection.
  Stop,
}

async fn forward_down(down: &mut Smtp, server: &mut ServerLeg, line: &[u8]) -> Result<Forwarded, Error> {
  let (rewritten, hits) = down.feed(line).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => Ok(Forwarded::Stop),
    Rewritten::Hold => Ok(Forwarded::Held),
    Rewritten::Emit(bytes) => {
      if !bytes.is_empty() {
        write_server(server, &bytes).await?;
      }
      Ok(Forwarded::Sent)
    }
  }
}

async fn upgrade_guest<G>(
  transport: &SmtpTransport,
  scope: &SmtpScope,
  guest: GuestLeg<G>,
  leaf: &str,
  budget: Duration,
) -> Result<GuestLeg<G>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let plain = match guest {
    GuestLeg::Plain(stream) => stream,
    GuestLeg::Tls(_) => return Err(Error::SmtpLegAlreadyTls),
  };
  let tls = handshake(budget, transport.accept_guest(leaf, plain, scope.guest_tls)).await?;
  Ok(GuestLeg::Tls(Box::new(tls)))
}

async fn upgrade_server(transport: &SmtpTransport, scope: &SmtpScope, server: ServerLeg, budget: Duration) -> Result<ServerLeg, Error> {
  let plain = match server {
    ServerLeg::Plain(stream) => stream,
    ServerLeg::Tls(_) => return Err(Error::SmtpLegAlreadyTls),
  };
  let name = scope.upstream.host.as_str();
  let tls = handshake(budget, transport.connect_server(scope, name, plain)).await?;
  Ok(ServerLeg::Tls(Box::new(tls)))
}

async fn handshake<T>(budget: Duration, handshake: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  match tokio::time::timeout(budget, handshake).await {
    Ok(result) => result,
    Err(_elapsed) => Err(Error::SmtpHandshakeTimeout),
  }
}

async fn write_guest<G>(guest: &mut GuestLeg<G>, bytes: &[u8]) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  guest
    .write_all(bytes)
    .await
    .map_err(|source| Error::ResponseChunkToGuest { source })?;
  guest.flush().await.map_err(|source| Error::ResponseChunkToGuest { source })?;
  Ok(())
}

async fn write_server(server: &mut ServerLeg, bytes: &[u8]) -> Result<(), Error> {
  server
    .write_all(bytes)
    .await
    .map_err(|source| Error::RequestChunkToUpstream { source })?;
  server.flush().await.map_err(|source| Error::RequestChunkToUpstream { source })?;
  Ok(())
}

/// One guest command, stopping at the newline so the following payload or
/// handshake stays unread. A line that reaches the AUTH cap is returned
/// as-is; the machine closes if it is still incomplete.
async fn guest_line<R>(reader: &mut R) -> Result<Option<Vec<u8>>, std::io::Error>
where
  R: AsyncRead + Unpin,
{
  let mut line = Vec::new();
  let mut byte = [0u8; 1];
  loop {
    match reader.read(&mut byte).await {
      Ok(0) => {
        if line.is_empty() {
          return Ok(None);
        }
        return Ok(Some(line));
      }
      Ok(_) => {
        let Some(next) = byte.first().copied() else {
          return Err(std::io::Error::other("empty read"));
        };
        line.push(next);
        if next == b'\n' || line.len() >= MAX_COMMAND {
          return Ok(Some(line));
        }
      }
      Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
        if line.is_empty() {
          return Ok(None);
        }
        return Ok(Some(line));
      }
      Err(err) => return Err(err),
    }
  }
}

/// One SMTP reply, including a multiline (`250-` … `250 `) continuation.
/// Stops on the final line. Bytes after it, including a handshake record,
/// stay in `reader`.
async fn acceptance_reply<R>(reader: &mut R) -> Result<Option<Vec<u8>>, std::io::Error>
where
  R: AsyncRead + Unpin,
{
  let mut all = Vec::new();
  let mut line = Vec::new();
  let mut byte = [0u8; 1];
  loop {
    match reader.read(&mut byte).await {
      Ok(0) => {
        if all.is_empty() && line.is_empty() {
          return Ok(None);
        }
        all.extend_from_slice(&line);
        return Ok(Some(all));
      }
      Ok(_) => {
        let Some(next) = byte.first().copied() else {
          return Err(std::io::Error::other("empty read"));
        };
        line.push(next);
        if next != b'\n' && line.len() < MAX_COMMAND {
          continue;
        }
        let finished = is_final_line(&line) || !line.ends_with(b"\n");
        all.extend_from_slice(&line);
        line.clear();
        if finished {
          return Ok(Some(all));
        }
      }
      Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
        if all.is_empty() && line.is_empty() {
          return Ok(None);
        }
        all.extend_from_slice(&line);
        return Ok(Some(all));
      }
      Err(err) => return Err(err),
    }
  }
}

fn is_opening_command(line: &[u8]) -> bool {
  const VERBS: &[&[u8]] = &[b"EHLO", b"HELO", b"NOOP", b"RSET", b"AUTH", b"QUIT"];
  VERBS.iter().any(|verb| verb_is(line, verb))
}

fn verb_is(line: &[u8], verb: &[u8]) -> bool {
  let body = strip_crlf(line);
  body
    .split(|byte| *byte == b' ' || *byte == b'\t')
    .find(|part| !part.is_empty())
    .is_some_and(|word| word.eq_ignore_ascii_case(verb))
}

fn is_final_line(line: &[u8]) -> bool {
  strip_crlf(line).get(3) != Some(&b'-')
}

fn is_220(buf: &[u8]) -> bool {
  let Some(line) = buf.rsplit(|byte| *byte == b'\n').find(|line| !line.is_empty()) else {
    return false;
  };
  let line = line.strip_suffix(b"\r").unwrap_or(line);
  line.get(..3) == Some(b"220".as_slice())
}

fn strip_crlf(line: &[u8]) -> &[u8] {
  line
    .strip_suffix(b"\r\n")
    .or_else(|| line.strip_suffix(b"\n"))
    .or_else(|| line.strip_suffix(b"\r"))
    .unwrap_or(line)
}

/// Cleartext guest leg.
pub(super) fn plain_guest<G>(stream: G) -> GuestLeg<G> {
  GuestLeg::Plain(stream)
}

/// Guest leg whose TLS is already terminated.
pub(super) fn tls_guest<G>(stream: ServerTlsStream<G>) -> GuestLeg<G> {
  GuestLeg::Tls(Box::new(stream))
}

/// Cleartext upstream leg.
pub(super) fn plain_server(stream: TcpStream) -> ServerLeg {
  ServerLeg::Plain(stream)
}

/// Upstream leg whose TLS handshake already finished.
pub(super) fn tls_server(stream: ClientTlsStream<TcpStream>) -> ServerLeg {
  ServerLeg::Tls(Box::new(stream))
}

#[cfg(test)]
mod tests {
  /// The acceptance line is the whole reply. The next bytes are a
  /// handshake record; consuming them as another SMTP line fails it.
  #[tokio::test]
  async fn acceptance_line_leaves_the_handshake_bytes() {
    let banner = b"220-wait\r\n220 2.0.0 Ready to start TLS\r\n";
    let mut payload = banner.to_vec();
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut cursor = std::io::Cursor::new(payload);
    let reply = super::acceptance_reply(&mut cursor).await.unwrap().unwrap();
    assert_eq!(reply, banner);
    let at = usize::try_from(cursor.position()).unwrap();
    assert_eq!(cursor.get_ref().get(at..), Some(&[0x16, 0x03, 0x01][..]));
  }
}
