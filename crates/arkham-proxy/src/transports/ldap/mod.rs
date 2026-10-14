//! LDAP vertical: transport halves, `StartTLS` upgrade, and the BER machine.

pub(crate) mod machine;

use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf, split};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{GuestTlsMode, LdapScope, RootCert};
use arkham_pki::ca::CertAuthority;

use super::PairCtx;
use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::mint::MintBucket;
use crate::relay::{log_hits, relay_guarded};
use crate::transports::engine::{Direction, Ldap, Rewritten, Wire};
use crate::transports::tls::{cached_leaf, cached_leaf_mtls, cached_roots};
use machine::starttls_success;
use rama::tls::client::ClientAuth;

/// First byte of a TLS record carrying a handshake. An `ldaps` guest leg
/// opens with it; a cleartext `ldap` scope never serves it.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// LDAP transport. `ldaps://` settles TLS before the machine runs.
/// `ldap://` stays plaintext until `StartTLS`, then mints the guest leaf
/// for the scope host and opens TLS upstream.
#[derive(Debug)]
pub(crate) struct LdapTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl LdapTransport {
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

impl TlsHalves for LdapTransport {
  type Scope = LdapScope;

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
      .map_err(|err| Error::GuestLdapTls { source: err })
  }

  /// Handshake the server. Chain and host name are always verified.
  ///
  /// # Errors
  ///
  /// Returns an error when the trust anchor cannot be read, when the server
  /// name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &LdapScope, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let root = scope.root_cert.clone().unwrap_or(RootCert::System);
    let roots = cached_roots(&self.roots, &root)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match (&scope.client_cert, &scope.client_key) {
      (Some(cert), Some(key)) => {
        let ClientAuth::Single(data) = client_identity(cert, key)? else {
          return Err(Error::EmptyClientIdentity { path: cert.clone() });
        };
        builder
          .with_client_auth_cert(data.cert_chain.clone(), data.private_key.clone_key())
          .map_err(|err| Error::ClientIdentity {
            path: cert.clone(),
            source: err,
          })?
      }
      _ => builder.with_no_client_auth(),
    };
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::LdapServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|err| Error::ServerLdapTls { source: err })
  }
}

impl Transport for LdapTransport {
  type Scope = LdapScope;

  /// The `ldap://` / `ldaps://` arm. LDAPS settles both legs first. Cleartext
  /// relays until `StartTLS`, then does the same.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, LdapScope>) -> Result<(), Error>
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
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let mut server_name = host.map(ToString::to_string);
    let guest_head = initial.to_vec();
    let mut guest_tls: Option<(Vec<u8>, String)> = None;
    if scope.is_downstream_tls {
      let authority = host.or(Some(scope.downstream.host.as_str()));
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, initial, budget, authority, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    } else if initial.first() == Some(&TLS_RECORD_HANDSHAKE) {
      tracing::debug!("TLS opening on a cleartext ldap scope; closing");
      return Ok(());
    }

    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    let matched_name = server_name
      .as_deref()
      .filter(|name| scope.downstream.host.eq_ignore_ascii_case(name));
    let ctx = PairCtx {
      grants: &snapshot.grants,
      host: matched_name.unwrap_or(scope.downstream.host.as_str()),
      port,
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    let upstream_name = scope.upstream.host.as_str();
    let pump = Pump {
      scope,
      ctx: &ctx,
      budget,
      mint: &state.mint,
      upgrade_upstream: !scope.is_upstream_tls,
    };
    if scope.is_downstream_tls {
      return self
        .relay_settled(
          OpenGuest {
            stream: guest,
            head: guest_head,
            tls: guest_tls,
          },
          upstream,
          &pump,
          upstream_name,
        )
        .await;
    }
    if scope.is_upstream_tls {
      let plain = self.connect_server(scope, upstream_name, upstream).await?;
      self.until_starttls(Prefixed::new(guest_head, guest), plain, &pump).await
    } else {
      self.until_starttls(Prefixed::new(guest_head, guest), upstream, &pump).await
    }
  }
}

/// Guest bytes already read, plus whether that leg opened with TLS.
struct OpenGuest<G> {
  stream: G,
  head: Vec<u8>,
  tls: Option<(Vec<u8>, String)>,
}

/// Facts the cleartext pump and the `StartTLS` upgrade share.
struct Pump<'a> {
  scope: &'a LdapScope,
  ctx: &'a PairCtx<'a>,
  budget: Duration,
  mint: &'a MintBucket,
  /// `false` when the upstream leg is already TLS, so `StartTLS` is answered here.
  upgrade_upstream: bool,
}

/// The four halves of a cleartext duplex, taken apart for the upgrade.
struct Split<G, S> {
  guest_r: ReadHalf<G>,
  guest_w: WriteHalf<G>,
  server_r: ReadHalf<S>,
  server_w: WriteHalf<S>,
}

impl LdapTransport {
  /// Both legs already know their transport. The password is swapped only
  /// when the upstream writer is TLS. A cleartext upstream keeps the decoy.
  async fn relay_settled<G, S>(&self, guest: OpenGuest<G>, upstream: S, pump: &Pump<'_>, upstream_name: &str) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let OpenGuest { stream, head, tls } = guest;
    let scope = pump.scope;
    let swap = scope.is_upstream_tls;
    match (tls, scope.is_upstream_tls) {
      (None, false) => relay(Prefixed::new(head, stream), upstream, pump.ctx, swap).await,
      (Some((hello_buf, identity)), false) => {
        let plain = self
          .accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls)
          .await?;
        relay(plain, upstream, pump.ctx, swap).await
      }
      (None, true) => {
        let plain = self.connect_server(scope, upstream_name, upstream).await?;
        relay(Prefixed::new(head, stream), plain, pump.ctx, swap).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = self
          .accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls)
          .await?;
        let server_plain = self.connect_server(scope, upstream_name, upstream).await?;
        relay(guest_plain, server_plain, pump.ctx, swap).await
      }
    }
  }

  /// Plaintext LDAP until a `StartTLS` request has been answered, then TLS.
  /// The pre-upgrade pair swaps only when the upstream socket is already TLS.
  async fn until_starttls<G, S>(&self, guest: G, server: S, pump: &Pump<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let (mut guest_r, mut guest_w) = split(guest);
    let (mut server_r, mut server_w) = split(server);
    let (mut down, mut up) = ldap_pair(pump.ctx, !pump.upgrade_upstream);
    let mut guest_buf = vec![0u8; 16 * 1024];
    let mut server_buf = vec![0u8; 16 * 1024];
    loop {
      tokio::select! {
        result = guest_r.read(&mut guest_buf) => {
          let n = read_count(result).map_err(|source| Error::GuestRead { source })?;
          if n == 0 {
            let _ = push_down(&mut down, &[], &mut server_w, pump.upgrade_upstream).await?;
            let _ = server_w.shutdown().await;
            return drain(&mut server_r, &mut guest_w, &mut up, &mut server_buf).await;
          }
          match push_down(&mut down, &guest_buf[..n], &mut server_w, pump.upgrade_upstream).await? {
            Step::Continue => {}
            Step::Close => return Ok(()),
            Step::Upgrade(id) => {
              return self
                .upgrade(id, Split { guest_r, guest_w, server_r, server_w }, &mut down, &mut up, pump)
                .await;
            }
          }
        }
        result = server_r.read(&mut server_buf) => {
          let n = read_count(result).map_err(|source| Error::UpstreamRead { source })?;
          if n == 0 {
            let _ = push_up(&mut up, &[], &mut guest_w).await?;
            let _ = guest_w.shutdown().await;
            return Ok(());
          }
          if push_up(&mut up, &server_buf[..n], &mut guest_w).await? == Step::Close {
            return Ok(());
          }
        }
      }
    }
  }

  /// Finish `StartTLS` and hand the plaintext legs to the shared relay.
  async fn upgrade<G, S>(&self, id: u32, split: Split<G, S>, down: &mut Ldap, up: &mut Ldap, pump: &Pump<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let Split {
      guest_r,
      mut guest_w,
      mut server_r,
      server_w,
    } = split;
    let prefix = down.take_prefix();
    let success = if pump.upgrade_upstream {
      up.expect_starttls(id);
      read_starttls_result(&mut server_r, &mut guest_w, up, pump.budget).await?
    } else {
      let bytes = starttls_success(id).map_err(|source| Error::LdapEncode { source })?;
      guest_w
        .write_all(&bytes)
        .await
        .map_err(|source| Error::ResponseChunkToGuest { source })?;
      guest_w.flush().await.map_err(|source| Error::GuestFlush { source })?;
      true
    };
    if !success {
      tracing::debug!("ldap starttls refused; closing");
      return Ok(());
    }
    let mut guest = guest_r.unsplit(guest_w);
    let server = server_r.unsplit(server_w);
    let authority = Some(pump.scope.downstream.host.as_str());
    let Some((hello_buf, identity, _)) = guest_tls_opening(&mut guest, &prefix, pump.budget, authority, pump.mint).await? else {
      return Ok(());
    };
    let guest_plain = self
      .accept_guest(&identity, Prefixed::new(hello_buf, guest), pump.scope.guest_tls)
      .await?;
    let (mut downstream, mut upstream) = ldap_pair(pump.ctx, true);
    if pump.upgrade_upstream {
      let server_plain = self.connect_server(pump.scope, pump.scope.upstream.host.as_str(), server).await?;
      relay_guarded(guest_plain, server_plain, &mut downstream, &mut upstream, &[]).await
    } else {
      relay_guarded(guest_plain, server, &mut downstream, &mut upstream, &[]).await
    }
  }
}

/// What one framed chunk asked the pump to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
  Continue,
  Close,
  Upgrade(u32),
}

/// `UnexpectedEof` from rustls is a normal FIN.
fn read_count(result: Result<usize, IoError>) -> Result<usize, IoError> {
  match result {
    Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
    other => other,
  }
}

/// Feed guest bytes downstream and carry the rewrite upstream.
async fn push_down<W>(down: &mut Ldap, chunk: &[u8], server: &mut W, upgrade_upstream: bool) -> Result<Step, Error>
where
  W: AsyncWrite + Unpin,
{
  let (rewritten, hits) = down.feed(chunk).await;
  log_hits(&hits);
  let id = down.take_starttls();
  match rewritten {
    Rewritten::Close => Ok(Step::Close),
    Rewritten::Hold => Ok(Step::Continue),
    Rewritten::Emit(bytes) => {
      if id.is_some() && !upgrade_upstream {
        return Ok(id.map_or(Step::Continue, Step::Upgrade));
      }
      server
        .write_all(&bytes)
        .await
        .map_err(|source| Error::RequestChunkToUpstream { source })?;
      server.flush().await.map_err(|source| Error::RequestHeadFlush { source })?;
      Ok(id.map_or(Step::Continue, Step::Upgrade))
    }
  }
}

/// Feed upstream bytes and carry the rewrite to the guest.
async fn push_up<W>(up: &mut Ldap, chunk: &[u8], guest: &mut W) -> Result<Step, Error>
where
  W: AsyncWrite + Unpin,
{
  let (rewritten, hits) = up.feed(chunk).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => Ok(Step::Close),
    Rewritten::Hold => Ok(Step::Continue),
    Rewritten::Emit(bytes) => {
      guest
        .write_all(&bytes)
        .await
        .map_err(|source| Error::ResponseChunkToGuest { source })?;
      guest.flush().await.map_err(|source| Error::GuestFlush { source })?;
      Ok(Step::Continue)
    }
  }
}

/// Read the server until its `StartTLS` extended response has been forwarded.
async fn read_starttls_result<R, W>(server: &mut R, guest: &mut W, up: &mut Ldap, budget: Duration) -> Result<bool, Error>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let deadline = tokio::time::Instant::now() + budget;
  let mut buf = vec![0u8; 16 * 1024];
  loop {
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    if left.is_zero() {
      return Err(Error::UpstreamRead {
        source: IoError::new(ErrorKind::TimedOut, "ldap starttls response"),
      });
    }
    let read = tokio::time::timeout(left, server.read(&mut buf))
      .await
      .map_err(|_elapsed| Error::UpstreamRead {
        source: IoError::new(ErrorKind::TimedOut, "ldap starttls response"),
      })?;
    let n = read_count(read).map_err(|source| Error::UpstreamRead { source })?;
    if n == 0 {
      return Ok(false);
    }
    if push_up(up, &buf[..n], guest).await? == Step::Close {
      return Ok(false);
    }
    if let Some(ok) = up.take_starttls_result() {
      return Ok(ok);
    }
  }
}

/// Drain upstream after the guest FIN, until the server closes.
async fn drain<R, W>(server: &mut R, guest: &mut W, up: &mut Ldap, buf: &mut [u8]) -> Result<(), Error>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  loop {
    let n = read_count(server.read(buf).await).map_err(|source| Error::UpstreamRead { source })?;
    if n == 0 || push_up(up, &buf[..n], guest).await? == Step::Close {
      let _ = guest.shutdown().await;
      return Ok(());
    }
  }
}

/// Pump one settled pair. `swap` is set only when `server` is already TLS.
async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>, swap: bool) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream, mut upstream) = ldap_pair(ctx, swap);
  relay_guarded(guest, server, &mut downstream, &mut upstream, &[]).await
}

/// Both directions for an LDAP scope. `swap` applies to the downstream leg:
/// a cleartext upstream must keep the decoy.
pub(crate) fn ldap_pair(ctx: &PairCtx<'_>, swap: bool) -> (Ldap, Ldap) {
  (
    Ldap::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream, swap),
    Ldap::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream, false),
  )
}
