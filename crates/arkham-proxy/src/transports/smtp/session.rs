//! Cleartext SMTP opening, then the shared relay.
//!
//! The greeting, `EHLO` / `HELO`, `HELP` / `VRFY` / `EXPN`, an `AUTH` that
//! still precedes `STARTTLS`, and `STARTTLS` plus its acceptance run
//! lockstep. Reply bytes are redacted as they arrive. The hold-back flushes
//! on newline or EOF, and the reader stops on the final line, so the
//! following handshake bytes stay unread. A non-`220` answer to `STARTTLS`
//! returns to that loop. After the upgrade, or when the guest sends anything
//! else, both sockets go to [`relay_guarded`]. Implicit TLS skips the
//! opening. A session that never upgrades relays with swapping off, and the
//! decoy passes through.

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
use super::machine::{MAX_COMMAND, Smtp, is_opening_command, is_starttls};
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
  Smtp::share_data_gate(&down, &mut up);
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
    if acceptance_reply(&mut self.server, self.up, &mut self.guest).await?.is_none() {
      return Ok(());
    }
    loop {
      let Some(line) = guest_line(&mut self.guest).await.map_err(|source| Error::GuestRead { source })? else {
        return Ok(());
      };
      if is_starttls(&line) {
        match self.forward_starttls(&line).await? {
          StarttlsStep::Continue => continue,
          StarttlsStep::Closed => return Ok(()),
          StarttlsStep::Upgrade => {
            let guest = upgrade_guest(self.transport, self.scope, self.guest, self.leaf, self.budget).await?;
            let server = upgrade_server(self.transport, self.scope, self.server, self.budget).await?;
            self.down.set_protected(true);
            return relay_guarded(guest, server, self.down, self.up, &[]).await;
          }
          StarttlsStep::Local => {
            self.down.queue_starttls_ready();
            if let Some(reply) = self.down.take_reply() {
              write_guest(&mut self.guest, &reply).await?;
            }
            let guest = upgrade_guest(self.transport, self.scope, self.guest, self.leaf, self.budget).await?;
            self.down.set_protected(true);
            return relay_guarded(guest, self.server, self.down, self.up, &[]).await;
          }
          StarttlsStep::Relay => return relay_guarded(self.guest, self.server, self.down, self.up, &[]).await,
        }
      }
      if self.down.awaiting_auth_payload() || is_opening_command(&line) {
        match forward_down(self.down, &mut self.server, &line).await? {
          Forwarded::Stop => return Ok(()),
          Forwarded::Held => return relay_guarded(self.guest, self.server, self.down, self.up, &[]).await,
          Forwarded::Sent => {}
        }
        if acceptance_reply(&mut self.server, self.up, &mut self.guest).await?.is_none() {
          return Ok(());
        }
        continue;
      }
      return relay_guarded(self.guest, self.server, self.down, self.up, &line).await;
    }
  }

  /// Forward `STARTTLS` when the upstream leg is still clear. A non-`220`
  /// reply leaves the opening loop in place so a later `STARTTLS` can
  /// upgrade. A `220`, or an upstream leg that is already TLS, ends the
  /// opening.
  async fn forward_starttls(&mut self, line: &[u8]) -> Result<StarttlsStep, Error> {
    if self.server.is_plain() {
      match forward_down(self.down, &mut self.server, line).await? {
        Forwarded::Stop => return Ok(StarttlsStep::Closed),
        Forwarded::Held => return Ok(StarttlsStep::Relay),
        Forwarded::Sent => {}
      }
      let Some(code) = acceptance_reply(&mut self.server, self.up, &mut self.guest).await? else {
        return Ok(StarttlsStep::Closed);
      };
      if is_220(code) {
        Ok(StarttlsStep::Upgrade)
      } else {
        Ok(StarttlsStep::Continue)
      }
    } else if self.guest.is_plain() {
      Ok(StarttlsStep::Local)
    } else {
      Ok(StarttlsStep::Relay)
    }
  }
}

/// What `STARTTLS` did to the opening loop.
enum StarttlsStep {
  /// The server refused. The next guest command is still an opening command.
  Continue,
  /// The peer closed before the upgrade.
  Closed,
  /// Cleartext upstream accepted. Upgrade both legs, then relay.
  Upgrade,
  /// Upstream is already TLS. Answer locally and upgrade the guest.
  Local,
  /// Hand the sockets to the relay without an upgrade.
  Relay,
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
/// Each byte is fed to the upstream machine as it arrives. `feed(&[])`
/// runs only on newline or EOF, so a password split across reads stays
/// inside the needle hold-back. The first four bytes decide whether the
/// line is final; the line itself is not kept. The returned code is that
/// final line's status, for the `220` check. Bytes after the final line,
/// including a handshake record, stay in `reader`.
async fn acceptance_reply<R, G>(reader: &mut R, up: &mut Smtp, guest: &mut GuestLeg<G>) -> Result<Option<[u8; 3]>, Error>
where
  R: AsyncRead + Unpin,
  G: AsyncRead + AsyncWrite + Unpin,
{
  let mut head = ReplyHead::default();
  let mut saw = false;
  let mut byte = [0u8; 1];
  loop {
    match reader.read(&mut byte).await {
      Ok(0) => return end_reply(up, guest, saw, &head).await,
      Ok(_) => {
        let Some(next) = byte.first().copied() else {
          return Err(Error::UpstreamRead {
            source: std::io::Error::other("empty read"),
          });
        };
        saw = true;
        write_fed(up, guest, &byte).await?;
        if next == b'\n' {
          write_fed(up, guest, &[]).await?;
          if head.is_final() {
            return Ok(Some(head.code));
          }
          head = ReplyHead::default();
        } else {
          head.observe(next);
        }
      }
      Err(err) if err.kind() == ErrorKind::UnexpectedEof => return end_reply(up, guest, saw, &head).await,
      Err(source) => return Err(Error::UpstreamRead { source }),
    }
  }
}

/// Status and separator of the reply line being read. Four bytes decide
/// the line. Nothing here retains the text.
#[derive(Default)]
struct ReplyHead {
  /// `0..3` collect the status code. `3` is the separator. `4` is the rest.
  at: u8,
  code: [u8; 3],
  /// The separator was `-`, so another line follows.
  continues: bool,
}

impl ReplyHead {
  fn observe(&mut self, byte: u8) {
    if self.at >= 4 {
      return;
    }
    if self.at < 3 {
      if let Some(slot) = self.code.get_mut(usize::from(self.at)) {
        *slot = byte;
      }
    } else {
      self.continues = byte == b'-';
    }
    self.at = self.at.saturating_add(1);
  }

  /// Newline or EOF ended a line that is not a continuation.
  fn is_final(&self) -> bool {
    self.at > 0 && !self.continues
  }
}

/// Flush the hold-back when the peer closes, and return the status when
/// that partial line was already final.
async fn end_reply<G>(up: &mut Smtp, guest: &mut GuestLeg<G>, saw: bool, head: &ReplyHead) -> Result<Option<[u8; 3]>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  if !saw {
    return Ok(None);
  }
  write_fed(up, guest, &[]).await?;
  if head.is_final() { Ok(Some(head.code)) } else { Ok(None) }
}

/// Feed one arrival to the upstream machine and write what it emits.
/// An empty chunk flushes the hold-back; the caller does that on newline
/// or EOF only.
async fn write_fed<G>(up: &mut Smtp, guest: &mut GuestLeg<G>, bytes: &[u8]) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let (rewritten, hits) = up.feed(bytes).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Emit(emitted) if !emitted.is_empty() => write_guest(guest, &emitted).await,
    Rewritten::Emit(_) | Rewritten::Hold | Rewritten::Close => Ok(()),
  }
}

fn is_220(code: [u8; 3]) -> bool {
  code == *b"220"
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
  use arkham_config::grants::{Credential, GuestTlsMode, SmtpLeg, SmtpScope};
  use secrecy::SecretString;

  use super::{Direction, Smtp, Wire};

  const FAKE_PASS: &str = "fake-smtp-pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-smtp-pass"; // betterleaks:allow

  /// Feed one complete reply and flush the hold-back, the way a newline does.
  async fn redact_reply(up: &mut Smtp, reply: &[u8]) -> Vec<u8> {
    let (rewritten, _) = up.feed(reply).await;
    let mut out = match rewritten {
      super::Rewritten::Emit(bytes) => bytes.into_owned(),
      super::Rewritten::Hold | super::Rewritten::Close => Vec::new(),
    };
    let (flushed, _) = up.feed(&[]).await;
    if let super::Rewritten::Emit(bytes) = flushed {
      out.extend(bytes.into_owned());
    }
    out
  }

  fn upstream() -> Smtp {
    let scope = SmtpScope {
      downstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(FAKE_PASS),
      },
      is_downstream_tls: false,
      upstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(REAL_PASS),
      },
      is_upstream_tls: true,
      starttls_required: false,
      root_cert: None,
      client_cert: None,
      client_key: None,
      guest_tls: GuestTlsMode::default(),
    };
    let grant = arkham_config::grants::Grant::Smtp {
      credential: Credential {
        label: "smtp".into(),
        fake: FAKE_PASS.into(),
        value: SecretString::from(REAL_PASS),
      },
      scope: Box::new(scope),
    };
    Smtp::new(std::slice::from_ref(&grant), "mail", 587, Direction::Upstream)
  }

  /// The opening writes the machine's output, so a reply that echoes the
  /// real password reaches the guest as the decoy.
  #[tokio::test]
  async fn opening_reply_redacts_the_real_password() {
    let mut up = upstream();
    let reply = format!("535 5.7.8 authentication failed for {REAL_PASS}\r\n");
    let out = redact_reply(&mut up, reply.as_bytes()).await;
    assert_eq!(out, format!("535 5.7.8 authentication failed for {FAKE_PASS}\r\n").into_bytes());
    assert!(!out.windows(REAL_PASS.len()).any(|window| window == REAL_PASS.as_bytes()));
  }

  /// Each reply line is written as it finishes. The next bytes are a
  /// handshake record; consuming them as another SMTP line fails it.
  #[tokio::test]
  async fn acceptance_line_leaves_the_handshake_bytes() {
    let banner = b"220-wait\r\n220 2.0.0 Ready to start TLS\r\n";
    let mut payload = banner.to_vec();
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut cursor = std::io::Cursor::new(payload);
    let mut guest = super::plain_guest(std::io::Cursor::new(Vec::new()));
    let mut up = upstream();
    let reply = super::acceptance_reply(&mut cursor, &mut up, &mut guest).await.unwrap().unwrap();
    assert_eq!(reply, *b"220");
    assert!(super::is_220(reply));
    let super::GuestLeg::Plain(writer) = guest else {
      unreachable!("the guest leg is the cursor");
    };
    assert_eq!(writer.into_inner(), banner);
    let at = usize::try_from(cursor.position()).unwrap();
    assert_eq!(cursor.get_ref().get(at..), Some(&[0x16, 0x03, 0x01][..]));
  }

  /// A reply that echoes a real password longer than the decoy is written
  /// with the decoy. The status code stays the server's.
  #[tokio::test]
  async fn opening_reply_redacts_a_longer_real_password() {
    const LONG_REAL: &str = "real-smtp-pass-extended"; // betterleaks:allow
    let scope = SmtpScope {
      downstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(FAKE_PASS),
      },
      is_downstream_tls: false,
      upstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(LONG_REAL),
      },
      is_upstream_tls: true,
      starttls_required: false,
      root_cert: None,
      client_cert: None,
      client_key: None,
      guest_tls: GuestTlsMode::default(),
    };
    let grant = arkham_config::grants::Grant::Smtp {
      credential: Credential {
        label: "smtp".into(),
        fake: FAKE_PASS.into(),
        value: SecretString::from(LONG_REAL),
      },
      scope: Box::new(scope),
    };
    let mut up = Smtp::new(std::slice::from_ref(&grant), "mail", 587, Direction::Upstream);
    let reply = format!("535 5.7.8 authentication failed for {LONG_REAL}\r\n");
    let out = redact_reply(&mut up, reply.as_bytes()).await;
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("535 "), "{text}");
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(LONG_REAL), "{text}");
  }

  /// A real password that crosses the old 16 KiB cut is one reply. The
  /// guest sees the decoy, and the bytes after the newline stay unread.
  #[tokio::test]
  async fn long_reply_redacts_a_password_across_the_old_cut() {
    const LONG_REAL: &str = "real-smtp-pass-extended"; // betterleaks:allow
    let scope = SmtpScope {
      downstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(FAKE_PASS),
      },
      is_downstream_tls: false,
      upstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(LONG_REAL),
      },
      is_upstream_tls: true,
      starttls_required: false,
      root_cert: None,
      client_cert: None,
      client_key: None,
      guest_tls: GuestTlsMode::default(),
    };
    let grant = arkham_config::grants::Grant::Smtp {
      credential: Credential {
        label: "smtp".into(),
        fake: FAKE_PASS.into(),
        value: SecretString::from(LONG_REAL),
      },
      scope: Box::new(scope),
    };
    let pass = LONG_REAL.as_bytes();
    let start = super::MAX_COMMAND.saturating_sub(4);
    let lead = b"535 ";
    assert!(start > lead.len());
    let mut line = Vec::new();
    line.extend_from_slice(lead);
    line.resize(start, b'x');
    line.extend_from_slice(pass);
    line.extend_from_slice(b"\r\n");
    let reply_len = line.len();
    let mut payload = line;
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut cursor = std::io::Cursor::new(payload);
    let mut guest = super::plain_guest(std::io::Cursor::new(Vec::new()));
    let mut up = Smtp::new(std::slice::from_ref(&grant), "mail", 587, Direction::Upstream);
    let code = super::acceptance_reply(&mut cursor, &mut up, &mut guest).await.unwrap().unwrap();
    assert_eq!(code, *b"535");
    let super::GuestLeg::Plain(writer) = guest else {
      unreachable!("the guest leg is the cursor");
    };
    let text = String::from_utf8(writer.into_inner()).unwrap();
    assert!(text.starts_with("535 "), "{text}");
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(LONG_REAL), "{text}");
    let at = usize::try_from(cursor.position()).unwrap();
    assert_eq!(at, reply_len);
    assert_eq!(cursor.get_ref().get(at..), Some(&[0x16, 0x03, 0x01][..]));
  }
}
