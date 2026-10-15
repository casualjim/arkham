//! NATS vertical: transport halves, the INFO-first opening, and the framer.
//!
//! The server speaks first. On `nats://` and `tls://` the proxy forwards one
//! cleartext INFO line. A `tls://` server leg then upgrades before CONNECT,
//! with the bytes read past INFO replayed into its handshake. A guest whose
//! next byte opens a TLS record is terminated here. With `handshake_first`
//! both legs settle TLS before any protocol byte. CONNECT carries the real
//! values only when the server leg is TLS.

pub(crate) mod machine;

use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rama::tls::client::ClientAuth;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{Grant, GuestTlsMode, NatsScope, NatsTlsOrder, NatsTrust, NatsUpstream, RootCert};
use arkham_pki::ca::CertAuthority;

use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::mint::MintBucket;
use crate::relay::{log_hits, relay_guarded};
use crate::transports::engine::{Rewritten, Wire};
use crate::transports::tls::{cached_leaf, cached_leaf_mtls, cached_roots};
use machine::Nats;

/// First byte of a TLS record carrying a handshake.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// Read window for INFO and for the guest's first bytes.
const OPENING_READ: usize = 4096;

/// NATS transport.
#[derive(Debug)]
pub(crate) struct NatsTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl NatsTransport {
  /// Build both halves over the CA that signs guest-facing leaves.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA cannot be read back from its own PEM.
  pub(crate) fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      leaves: DashMap::new(),
      roots: DashMap::new(),
    })
  }
}

impl TlsHalves for NatsTransport {
  type Scope = NatsTrust;

  /// Accept the guest's TLS, minting the leaf for `name` on first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  async fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let config = match guest_tls {
      GuestTlsMode::Tls => cached_leaf(&self.ca, &self.leaves, name, None)?,
      GuestTlsMode::Mtls => cached_leaf_mtls(&self.ca, &self.leaves, name, None)?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|source| Error::GuestNatsTls { source })
  }

  /// Handshake the server under the trust a `tls://` string states. Chain
  /// and host name are always verified.
  ///
  /// # Errors
  ///
  /// Returns an error when the trust anchor or client identity cannot be
  /// read, when the server name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &NatsTrust, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let roots = cached_roots(&self.roots, &scope.root_cert)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match &scope.identity {
      Some(identity) => {
        let ClientAuth::Single(data) = client_identity(&identity.cert, &identity.key)? else {
          return Err(Error::EmptyClientIdentity {
            path: identity.cert.clone(),
          });
        };
        builder
          .with_client_auth_cert(data.cert_chain.clone(), data.private_key.clone_key())
          .map_err(|source| Error::ClientIdentity {
            path: identity.cert.clone(),
            source,
          })?
      }
      None => builder.with_no_client_auth(),
    };
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::NatsServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|source| Error::ServerNatsTls { source })
  }
}

impl Transport for NatsTransport {
  type Scope = NatsScope;

  /// The `nats://` / `tls://` arm. The real string alone decides the server
  /// leg; the guest picks its own TLS.
  async fn serve<G>(&self, ServeStream { guest, params, scope }: ServeStream<'_, G, NatsScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      host,
      port,
      initial,
      ..
    } = params;
    let open = Open {
      scope,
      grants: &snapshot.grants,
      port,
      budget: Duration::from_secs(snapshot.proxy.handshake_timeout_secs),
      mint: &state.mint,
      authority: host.unwrap_or(scope.downstream.host.as_str()),
      fwmark: state.fwmark,
    };
    match &scope.upstream_tls {
      NatsUpstream::Tls {
        order: NatsTlsOrder::HandshakeFirst,
        trust,
      } => self.handshake_first(guest, initial, trust, &open).await,
      NatsUpstream::Tls {
        order: NatsTlsOrder::AfterInfo,
        trust,
      } => self.after_info(guest, initial, Some(trust), &open).await,
      NatsUpstream::Cleartext => self.after_info(guest, initial, None, &open).await,
    }
  }
}

/// Facts every NATS opening shares.
struct Open<'a> {
  scope: &'a NatsScope,
  grants: &'a [Grant],
  port: u16,
  budget: Duration,
  mint: &'a MintBucket,
  /// The name a guest leaf is minted for when its hello has no SNI.
  authority: &'a str,
  fwmark: Option<u32>,
}

impl Open<'_> {
  /// Both directions. Machines key on the grant host, which every
  /// identity this arm serves already matched.
  fn pair(&self, swap: bool) -> (Nats, Nats) {
    nats_pair(self.grants, &self.scope.downstream.host, self.port, swap)
  }
}

/// The server leg once its transport is settled.
struct ServerLeg<S> {
  stream: S,
  /// Server bytes read past INFO, replayed ahead of the stream.
  first: Vec<u8>,
  down: Nats,
  up: Nats,
}

impl NatsTransport {
  /// INFO travels cleartext on both legs. A `tls://` server leg upgrades
  /// right after it; `trust` is `None` on `nats://`, which never upgrades.
  async fn after_info<G>(&self, mut guest: G, initial: &[u8], trust: Option<&NatsTrust>, open: &Open<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    if initial.first() == Some(&TLS_RECORD_HANDSHAKE) {
      tracing::debug!("TLS before INFO on a nats scope without handshake_first; closing");
      return Ok(());
    }
    let upstream = &open.scope.upstream;
    let mut tcp = dial_marked(&upstream.host, upstream.port, open.fwmark).await?;
    let (down, mut up) = open.pair(trust.is_some());
    let Some(rest) = server_info(&mut tcp, &mut up, &mut guest).await? else {
      return Ok(());
    };
    if let Some(trust) = trust {
      let stream = within(open.budget, self.connect_server(trust, &upstream.host, Prefixed::new(rest, tcp))).await?;
      let server = ServerLeg {
        stream,
        first: Vec::new(),
        down,
        up,
      };
      self.relay_guest(guest, initial, server, open).await
    } else {
      let server = ServerLeg {
        stream: tcp,
        first: rest,
        down,
        up,
      };
      self.relay_guest(guest, initial, server, open).await
    }
  }

  /// `handshake_first`: the guest's hello comes before any NATS byte, and
  /// the server leg settles TLS before INFO.
  async fn handshake_first<G>(&self, mut guest: G, initial: &[u8], trust: &NatsTrust, open: &Open<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let Some((hello_buf, identity, _)) = guest_tls_opening(&mut guest, initial, open.budget, Some(open.authority), open.mint).await? else {
      return Ok(());
    };
    let upstream = &open.scope.upstream;
    let tcp = dial_marked(&upstream.host, upstream.port, open.fwmark).await?;
    let server = within(open.budget, self.connect_server(trust, &upstream.host, tcp)).await?;
    let guest = within(
      open.budget,
      self.accept_guest(&identity, Prefixed::new(hello_buf, guest), open.scope.guest_tls),
    )
    .await?;
    let (mut down, mut up) = open.pair(true);
    relay_guarded(guest, server, &mut down, &mut up, &[], &[]).await
  }

  /// After INFO, a guest whose first byte opens a TLS record is terminated
  /// here. Either way the guest leg joins the settled server leg.
  async fn relay_guest<G, S>(&self, mut guest: G, initial: &[u8], server: ServerLeg<S>, open: &Open<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let ServerLeg {
      stream,
      first,
      mut down,
      mut up,
    } = server;
    let Some(head) = guest_head(&mut guest, initial).await? else {
      return Ok(());
    };
    if head.first() != Some(&TLS_RECORD_HANDSHAKE) {
      return relay_guarded(guest, stream, &mut down, &mut up, &head, &first).await;
    }
    let Some((hello_buf, identity, _)) = guest_tls_opening(&mut guest, &head, open.budget, Some(open.authority), open.mint).await? else {
      return Ok(());
    };
    let guest = within(
      open.budget,
      self.accept_guest(&identity, Prefixed::new(hello_buf, guest), open.scope.guest_tls),
    )
    .await?;
    relay_guarded(guest, stream, &mut down, &mut up, &[], &first).await
  }
}

/// Both directions for a NATS scope. `swap` is true only when the server
/// leg is TLS: a cleartext server leg must keep the decoy.
pub(crate) fn nats_pair(grants: &[Grant], host: &str, port: u16, swap: bool) -> (Nats, Nats) {
  (Nats::downstream(grants, host, port, swap), Nats::upstream(grants, host, port))
}

async fn within<T>(budget: Duration, step: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  tokio::time::timeout(budget, step).await.unwrap_or(Err(Error::NatsHandshakeTimeout))
}

/// Forward the server's first line, INFO, through `up` to the guest, and
/// return the bytes read past its LF. On a `tls://` server leg they belong
/// to the server's TLS, not to NATS. `None` when the server closes first or
/// `up` closes the leg.
pub(crate) async fn server_info<S, G>(server: &mut S, up: &mut Nats, guest: &mut G) -> Result<Option<Vec<u8>>, Error>
where
  S: AsyncRead + Unpin,
  G: AsyncWrite + Unpin,
{
  let mut buf = vec![0u8; OPENING_READ];
  loop {
    let n = read_count(server.read(&mut buf).await).map_err(|source| Error::UpstreamRead { source })?;
    let Some(chunk) = buf.get(..n).filter(|chunk| !chunk.is_empty()) else {
      return Ok(None);
    };
    let newline = chunk.iter().position(|byte| *byte == b'\n');
    let cut = newline.map_or(chunk.len(), |at| at.saturating_add(1));
    let Some((line, rest)) = chunk.split_at_checked(cut) else {
      return Ok(None);
    };
    let (rewritten, hits) = up.feed(line).await;
    log_hits(&hits);
    match rewritten {
      Rewritten::Close => return Ok(None),
      Rewritten::Hold => {}
      Rewritten::Emit(bytes) => write_guest(guest, &bytes).await?,
    }
    if newline.is_some() {
      return Ok(Some(rest.to_vec()));
    }
  }
}

/// The guest's first bytes after INFO: the ingress replay, or one read.
/// `None` when the guest closes.
async fn guest_head<G>(guest: &mut G, initial: &[u8]) -> Result<Option<Vec<u8>>, Error>
where
  G: AsyncRead + Unpin,
{
  if !initial.is_empty() {
    return Ok(Some(initial.to_vec()));
  }
  let mut buf = vec![0u8; OPENING_READ];
  let n = read_count(guest.read(&mut buf).await).map_err(|source| Error::GuestRead { source })?;
  if n == 0 {
    return Ok(None);
  }
  buf.truncate(n);
  Ok(Some(buf))
}

fn read_count(result: Result<usize, IoError>) -> Result<usize, IoError> {
  match result {
    Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
    other => other,
  }
}

async fn write_guest<W>(guest: &mut W, bytes: &[u8]) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
{
  guest
    .write_all(bytes)
    .await
    .map_err(|source| Error::ResponseChunkToGuest { source })?;
  guest.flush().await.map_err(|source| Error::GuestFlush { source })
}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use pretty_assertions::assert_eq;

  use super::machine::Nats;
  use super::machine::tests::nats_grants;
  use super::server_info;
  use crate::transports::engine::{Rewritten, Wire};

  #[tokio::test]
  async fn info_reader_leaves_the_bytes_after_the_newline() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",   // betterleaks:allow
      "tls://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let info = b"INFO {\"server_id\":\"N1\",\"tls_required\":true}\r\n";
    let mut wire = info.to_vec();
    wire.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut server = Cursor::new(wire);
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let rest = server_info(&mut server, &mut up, &mut guest).await.unwrap();
    assert_eq!(rest, Some(vec![0x16, 0x03, 0x01]));
    assert_eq!(guest, info);
    let Rewritten::Emit(next) = up.feed(b"+OK\r\n").await.0 else {
      panic!("a line after INFO is emitted");
    };
    assert_eq!(next.as_ref(), b"+OK\r\n");
  }
}
