//! SMTP dialogue: the server greeting, then one command and one reply,
//! with `STARTTLS` upgrading both sockets in place.
//!
//! The same framing machines run before and after the upgrade. The reader
//! stops at the acceptance line, because the next guest bytes are a
//! `ClientHello`. `DATA` is spliced until the terminating dot, and `BDAT n`
//! splices the next `n` octets, so a payload is never held while the
//! session waits for a reply the server will not send yet.

use std::io::ErrorKind;
use std::time::Duration;

use crate::transports::TlsHalves;
use crate::transports::engine::Wire;
use arkham_config::grants::{Grant, SmtpScope};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use super::SmtpTransport;
use super::machine::Smtp;
use crate::Error;
use crate::relay::log_hits;
use crate::transports::engine::{Direction, Rewritten};

/// Cap for one buffered line. Matches the framing machine.
const MAX_LINE: usize = 16 * 1024;

/// Local reply when the upstream leg is already TLS and the guest asks
/// for `STARTTLS`. The command is not forwarded into the encrypted leg.
const STARTTLS_READY: &[u8] = b"220 2.0.0 Ready to start TLS\r\n";

/// What one machine feed produced.
enum Forward {
  /// Bytes to write on the other leg. Empty when the machine held a
  /// partial line.
  Bytes(Vec<u8>),
  /// The machine closed the connection. The session ends quietly.
  Stop,
}

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

  fn into_plain(self) -> Result<G, Error> {
    match self {
      Self::Plain(stream) => Ok(stream),
      Self::Tls(_) => Err(Error::SmtpLegAlreadyTls),
    }
  }

  async fn read_line(&mut self) -> Result<Option<Vec<u8>>, std::io::Error> {
    match self {
      Self::Plain(stream) => read_line(stream).await,
      Self::Tls(stream) => read_line(stream.as_mut()).await,
    }
  }

  async fn read_byte(&mut self) -> Result<Option<u8>, std::io::Error> {
    match self {
      Self::Plain(stream) => read_byte(stream).await,
      Self::Tls(stream) => read_byte(stream.as_mut()).await,
    }
  }

  async fn read_some(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    match self {
      Self::Plain(stream) => read_some(stream, buf).await,
      Self::Tls(stream) => read_some(stream.as_mut(), buf).await,
    }
  }

  async fn write_flush(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
    match self {
      Self::Plain(stream) => write_flush(stream, bytes).await,
      Self::Tls(stream) => write_flush(stream.as_mut(), bytes).await,
    }
  }
}

impl ServerLeg {
  fn is_plain(&self) -> bool {
    matches!(self, Self::Plain(_))
  }

  fn into_plain(self) -> Result<TcpStream, Error> {
    match self {
      Self::Plain(stream) => Ok(stream),
      Self::Tls(_) => Err(Error::SmtpLegAlreadyTls),
    }
  }

  async fn read_response(&mut self) -> Result<Option<Vec<u8>>, std::io::Error> {
    match self {
      Self::Plain(stream) => read_response(stream).await,
      Self::Tls(stream) => read_response(stream.as_mut()).await,
    }
  }

  async fn write_flush(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
    match self {
      Self::Plain(stream) => write_flush(stream, bytes).await,
      Self::Tls(stream) => write_flush(stream.as_mut(), bytes).await,
    }
  }
}

/// One SMTP session. The legs sit in `Option` so a TLS upgrade can take
/// the socket out, handshake it, and put it back.
struct Session<'a, G> {
  transport: &'a SmtpTransport,
  scope: &'a SmtpScope,
  guest: Option<GuestLeg<G>>,
  server: Option<ServerLeg>,
  down: Smtp,
  up: Smtp,
  budget: Duration,
  leaf_name: &'a str,
}

impl<G> Session<'_, G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  async fn pump(mut self) -> Result<(), Error> {
    let Some(greeting) = self.read_server().await? else {
      return Ok(());
    };
    if !self.write_guest_redacted(&greeting).await? {
      return Ok(());
    }
    loop {
      let Some(line) = self.read_guest_line().await? else {
        self.flush_downstream().await?;
        return Ok(());
      };
      if self.answer_starttls_locally(&line).await? {
        continue;
      }
      let data = is_command(&line, b"DATA");
      let starttls = is_command(&line, b"STARTTLS");
      let bdat = bdat_octets(&line);
      if !self.forward_downstream(&line).await? {
        return Ok(());
      }
      // `BDAT n` is followed by n octets before the server replies.
      // Reading the reply first deadlocks until the budget expires.
      if let Some(octets) = bdat {
        self.splice_octets(octets).await?;
      }
      let Some(response) = self.read_server().await? else {
        return Ok(());
      };
      let code = reply_code(&response);
      if !self.write_guest_redacted(&response).await? {
        return Ok(());
      }
      if data && code == Some(354) {
        self.splice_body().await?;
        let Some(final_response) = self.read_server().await? else {
          return Ok(());
        };
        if !self.write_guest_redacted(&final_response).await? {
          return Ok(());
        }
      }
      if starttls && code == Some(220) {
        self.upgrade_plain_legs().await?;
      }
    }
  }

  /// The upstream leg is already encrypted. Answer `STARTTLS` here and
  /// upgrade only the guest, so the command is not written into TLS.
  async fn answer_starttls_locally(&mut self, line: &[u8]) -> Result<bool, Error> {
    let guest_plain = self.guest.as_ref().is_some_and(GuestLeg::is_plain);
    let server_plain = self.server.as_ref().is_some_and(ServerLeg::is_plain);
    if !is_command(line, b"STARTTLS") || !guest_plain || server_plain {
      return Ok(false);
    }
    self.write_guest(STARTTLS_READY).await?;
    self.upgrade_guest().await?;
    self.sync_protected();
    Ok(true)
  }

  async fn upgrade_plain_legs(&mut self) -> Result<(), Error> {
    if self.guest.as_ref().is_some_and(GuestLeg::is_plain) {
      self.upgrade_guest().await?;
    }
    if self.server.as_ref().is_some_and(ServerLeg::is_plain) {
      self.upgrade_server().await?;
    }
    self.sync_protected();
    Ok(())
  }

  async fn upgrade_guest(&mut self) -> Result<(), Error> {
    let Some(leg) = self.guest.take() else {
      return Err(Error::SmtpLegAlreadyTls);
    };
    let plain = leg.into_plain()?;
    let mode = self.scope.guest_tls;
    let tls = handshake(self.budget, self.transport.accept_guest(self.leaf_name, plain, mode)).await?;
    self.guest = Some(GuestLeg::Tls(Box::new(tls)));
    Ok(())
  }

  async fn upgrade_server(&mut self) -> Result<(), Error> {
    let Some(leg) = self.server.take() else {
      return Err(Error::SmtpLegAlreadyTls);
    };
    let plain = leg.into_plain()?;
    let name = self.scope.upstream.host.as_str();
    let tls = handshake(self.budget, self.transport.connect_server(self.scope, name, plain)).await?;
    self.server = Some(ServerLeg::Tls(Box::new(tls)));
    Ok(())
  }

  /// Real credentials stay off a cleartext upstream. AUTH is rewritten
  /// only once this leg is TLS.
  fn sync_protected(&mut self) {
    let encrypted = self.server.as_ref().is_some_and(|leg| !leg.is_plain());
    self.down.set_protected(encrypted);
  }

  async fn forward_downstream(&mut self, line: &[u8]) -> Result<bool, Error> {
    match feed(&mut self.down, line).await {
      Forward::Stop => Ok(false),
      Forward::Bytes(bytes) => {
        if !bytes.is_empty() {
          self.write_server(&bytes).await?;
        }
        Ok(true)
      }
    }
  }

  async fn flush_downstream(&mut self) -> Result<(), Error> {
    if let Forward::Bytes(bytes) = feed(&mut self.down, &[]).await
      && !bytes.is_empty()
    {
      self.write_server(&bytes).await?;
    }
    Ok(())
  }

  /// `false` when the response machine closed the session.
  async fn write_guest_redacted(&mut self, response: &[u8]) -> Result<bool, Error> {
    match feed(&mut self.up, response).await {
      Forward::Stop => return Ok(false),
      Forward::Bytes(bytes) if !bytes.is_empty() => self.write_guest(&bytes).await?,
      Forward::Bytes(_) if !response.ends_with(b"\n") => {
        if let Forward::Bytes(rest) = feed(&mut self.up, &[]).await
          && !rest.is_empty()
        {
          self.write_guest(&rest).await?;
        }
      }
      Forward::Bytes(_) => {}
    }
    Ok(true)
  }

  /// Copy `octets` of a `BDAT` chunk unchanged. The count is the size on
  /// the command line; the bytes are not a line and are not rewritten.
  async fn splice_octets(&mut self, mut remaining: u64) -> Result<(), Error> {
    let mut buf = [0u8; 8192];
    while remaining > 0 {
      let want = usize::try_from(remaining).unwrap_or(buf.len()).min(buf.len());
      let got = self.read_guest_some(&mut buf[..want]).await?;
      if got == 0 {
        return Ok(());
      }
      let Some(chunk) = buf.get(..got) else {
        return Err(Error::GuestRead {
          source: std::io::Error::other("read length past buffer"),
        });
      };
      self.write_server(chunk).await?;
      let Some(advance) = u64::try_from(got).ok() else {
        return Err(Error::GuestRead {
          source: std::io::Error::other("read length does not fit"),
        });
      };
      remaining = remaining.saturating_sub(advance);
    }
    Ok(())
  }

  /// Copy the message body unchanged until the terminating dot line.
  async fn splice_body(&mut self) -> Result<(), Error> {
    let mut buf = Vec::new();
    loop {
      let Some(byte) = self.read_guest_byte().await? else {
        if !buf.is_empty() {
          self.write_server(&buf).await?;
        }
        return Ok(());
      };
      buf.push(byte);
      if byte != b'\n' && buf.len() < MAX_LINE {
        continue;
      }
      let ended = is_dot(&buf);
      self.write_server(&buf).await?;
      buf.clear();
      if ended {
        return Ok(());
      }
    }
  }

  async fn read_guest_line(&mut self) -> Result<Option<Vec<u8>>, Error> {
    let guest = self.guest.as_mut().ok_or(Error::SmtpLegAlreadyTls)?;
    guest.read_line().await.map_err(|source| Error::GuestRead { source })
  }

  async fn read_guest_byte(&mut self) -> Result<Option<u8>, Error> {
    let guest = self.guest.as_mut().ok_or(Error::SmtpLegAlreadyTls)?;
    guest.read_byte().await.map_err(|source| Error::GuestRead { source })
  }

  async fn read_guest_some(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
    let guest = self.guest.as_mut().ok_or(Error::SmtpLegAlreadyTls)?;
    guest.read_some(buf).await.map_err(|source| Error::GuestRead { source })
  }

  async fn read_server(&mut self) -> Result<Option<Vec<u8>>, Error> {
    let server = self.server.as_mut().ok_or(Error::SmtpLegAlreadyTls)?;
    server.read_response().await.map_err(|source| Error::UpstreamRead { source })
  }

  async fn write_guest(&mut self, bytes: &[u8]) -> Result<(), Error> {
    let guest = self.guest.as_mut().ok_or(Error::SmtpLegAlreadyTls)?;
    guest
      .write_flush(bytes)
      .await
      .map_err(|source| Error::ResponseChunkToGuest { source })
  }

  async fn write_server(&mut self, bytes: &[u8]) -> Result<(), Error> {
    let server = self.server.as_mut().ok_or(Error::SmtpLegAlreadyTls)?;
    server
      .write_flush(bytes)
      .await
      .map_err(|source| Error::RequestChunkToUpstream { source })
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

/// Run the dialogue. Implicit TLS is already settled on whichever leg
/// asked for it; `STARTTLS` is the only upgrade that happens here.
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
  let session = Session {
    transport,
    scope,
    guest: Some(guest),
    server: Some(server),
    down,
    up: Smtp::new(grants, host, port, Direction::Upstream),
    budget,
    leaf_name: host,
  };
  session.pump().await
}

async fn feed(machine: &mut Smtp, chunk: &[u8]) -> Forward {
  let (rewritten, hits) = machine.feed(chunk).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => Forward::Stop,
    Rewritten::Hold => Forward::Bytes(Vec::new()),
    Rewritten::Emit(bytes) => Forward::Bytes(bytes.into_owned()),
  }
}

async fn handshake<T>(budget: Duration, handshake: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  match tokio::time::timeout(budget, handshake).await {
    Ok(result) => result,
    Err(_elapsed) => Err(Error::SmtpHandshakeTimeout),
  }
}

async fn read_byte<R>(reader: &mut R) -> Result<Option<u8>, std::io::Error>
where
  R: AsyncRead + Unpin,
{
  let mut buf = [0u8; 1];
  match read_some(reader, &mut buf).await? {
    0 => Ok(None),
    _ => Ok(buf.first().copied()),
  }
}

async fn read_some<R>(reader: &mut R, buf: &mut [u8]) -> Result<usize, std::io::Error>
where
  R: AsyncRead + Unpin,
{
  if buf.is_empty() {
    return Ok(0);
  }
  match reader.read(buf).await {
    Ok(0) => Ok(0),
    Ok(n) => Ok(n),
    Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
    Err(err) => Err(err),
  }
}

async fn read_line<R>(reader: &mut R) -> Result<Option<Vec<u8>>, std::io::Error>
where
  R: AsyncRead + Unpin,
{
  let mut buf = Vec::new();
  loop {
    match read_byte(reader).await? {
      None if buf.is_empty() => return Ok(None),
      None => return Ok(Some(buf)),
      Some(byte) => {
        buf.push(byte);
        if byte == b'\n' || buf.len() >= MAX_LINE {
          return Ok(Some(buf));
        }
      }
    }
  }
}

/// One SMTP reply, including a multiline (`250-` … `250 `) continuation.
async fn read_response<R>(reader: &mut R) -> Result<Option<Vec<u8>>, std::io::Error>
where
  R: AsyncRead + Unpin,
{
  let mut all = Vec::new();
  loop {
    let Some(line) = read_line(reader).await? else {
      if all.is_empty() {
        return Ok(None);
      }
      return Ok(Some(all));
    };
    let finished = is_final_reply(&line) || !line.ends_with(b"\n");
    all.extend_from_slice(&line);
    if finished {
      return Ok(Some(all));
    }
  }
}

async fn write_flush<W>(writer: &mut W, bytes: &[u8]) -> Result<(), std::io::Error>
where
  W: AsyncWrite + Unpin,
{
  writer.write_all(bytes).await?;
  writer.flush().await?;
  Ok(())
}

/// Size on `BDAT <n> [LAST]`. Missing or non-numeric sizes are `None`:
/// the command is still forwarded, and the server rejects it with no payload.
fn bdat_octets(line: &[u8]) -> Option<u64> {
  let body = strip_crlf(line);
  let mut parts = body.split(|byte| *byte == b' ' || *byte == b'\t').filter(|part| !part.is_empty());
  let verb = parts.next()?;
  if !verb.eq_ignore_ascii_case(b"BDAT") {
    return None;
  }
  let size = parts.next()?;
  if size.is_empty() || !size.iter().all(u8::is_ascii_digit) {
    return None;
  }
  std::str::from_utf8(size).ok()?.parse().ok()
}

fn is_command(line: &[u8], verb: &[u8]) -> bool {
  let body = strip_crlf(line);
  body
    .split(|byte| *byte == b' ' || *byte == b'\t')
    .find(|part| !part.is_empty())
    .is_some_and(|word| word.eq_ignore_ascii_case(verb))
}

fn is_dot(line: &[u8]) -> bool {
  strip_crlf(line) == b"."
}

fn is_final_reply(line: &[u8]) -> bool {
  strip_crlf(line).get(3) != Some(&b'-')
}

/// Status code on the last line of a reply.
fn reply_code(buf: &[u8]) -> Option<u16> {
  let line = buf.rsplit(|byte| *byte == b'\n').find(|line| !line.is_empty())?;
  let line = line.strip_suffix(b"\r").unwrap_or(line);
  let digits = line.get(..3)?;
  if !digits.iter().all(u8::is_ascii_digit) {
    return None;
  }
  std::str::from_utf8(digits).ok()?.parse().ok()
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
  use super::bdat_octets;

  #[test]
  fn bdat_size_is_the_octet_count() {
    assert_eq!(bdat_octets(b"BDAT 5\r\n"), Some(5));
    assert_eq!(bdat_octets(b"bdat 0 LAST\r\n"), Some(0));
    assert_eq!(bdat_octets(b"BDAT\r\n"), None);
    assert_eq!(bdat_octets(b"BDAT LAST\r\n"), None);
    assert_eq!(bdat_octets(b"DATA\r\n"), None);
  }

  /// The acceptance line is the whole reply. The next bytes are a
  /// handshake record; consuming them as another SMTP line fails it.
  #[tokio::test]
  async fn acceptance_line_leaves_the_handshake_bytes() {
    let banner = b"220-wait\r\n220 2.0.0 Ready to start TLS\r\n";
    let mut payload = banner.to_vec();
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut cursor = std::io::Cursor::new(payload);
    let reply = super::read_response(&mut cursor).await.unwrap().unwrap();
    assert_eq!(reply, banner);
    let at = usize::try_from(cursor.position()).unwrap();
    assert_eq!(cursor.get_ref().get(at..), Some(&[0x16, 0x03, 0x01][..]));
  }
}
