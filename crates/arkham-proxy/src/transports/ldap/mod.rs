//! LDAP vertical: transport halves, `StartTLS` upgrade, and the BER machine.

pub(crate) mod machine;

use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf, split};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{GuestTlsMode, LdapScope, RootCert};
use arkham_pki::ca::CertAuthority;
use arkham_pki::ca::generate_domain_pair;

use super::PairCtx;
use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::mint::MintBucket;
use crate::relay::{log_hits, relay_guarded};
use crate::transports::engine::{Direction, Ldap, Rewritten, Wire};
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

  /// Leaf for one name, cached.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted.
  fn leaf(&self, sni: &str) -> Result<Arc<ServerConfig>, Error> {
    if let Some(config) = self.leaves.get(sni) {
      return Ok(config.clone());
    }
    let config = Arc::new((*self.ca.generate_domain_cert(sni)?.server_config).clone());
    self.leaves.insert(sni.to_string(), Arc::clone(&config));
    Ok(config)
  }

  /// `mtls` variant of [`Self::leaf`].
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the verifier cannot
  /// be built.
  fn leaf_mtls(&self, sni: &str) -> Result<Arc<ServerConfig>, Error> {
    let cache_key = format!("{sni}|mtls");
    if let Some(config) = self.leaves.get(&cache_key) {
      return Ok(config.clone());
    }
    let (chain, key_der) = generate_domain_pair(&self.ca, sni)?;
    let mut roots = RootCertStore::empty();
    roots
      .add(self.ca.cert_der().clone())
      .map_err(|err| Error::MtlsGuestRoots { source: err })?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
      .build()
      .map_err(|err| Error::MtlsGuestVerifier { source: err.into() })?;
    let config = Arc::new(
      rustls::server::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key_der)
        .map_err(|err| Error::MtlsLeaf { source: err })?,
    );
    self.leaves.insert(cache_key, Arc::clone(&config));
    Ok(config)
  }

  /// Trust anchors for the upstream leg.
  ///
  /// # Errors
  ///
  /// Returns an error when the anchor cannot be read or holds no certificates.
  fn roots_for(&self, root: &RootCert) -> Result<Arc<RootCertStore>, Error> {
    if let Some(store) = self.roots.get(root) {
      return Ok(store.clone());
    }
    let store = match root {
      RootCert::Path(path) => {
        let pem = std::fs::read(path).map_err(|err| Error::SslRootCert {
          path: path.clone(),
          source: err.into(),
        })?;
        let mut store = RootCertStore::empty();
        let mut anchors = 0usize;
        for cert in CertificateDer::pem_slice_iter(&pem) {
          let cert = cert.map_err(|err| Error::SslRootCert {
            path: path.clone(),
            source: err.into(),
          })?;
          store.add(cert).map_err(|err| Error::SslRootCert {
            path: path.clone(),
            source: err.into(),
          })?;
          anchors += 1;
        }
        if anchors == 0 {
          return Err(Error::EmptyRootCert { path: path.clone() });
        }
        store
      }
      RootCert::System => {
        let mut native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
          return Err(Error::SystemStore {
            source: native.errors.remove(0).into(),
          });
        }
        let mut store = RootCertStore::empty();
        for cert in native.certs {
          store.add(cert).map_err(|err| Error::SystemStore { source: err.into() })?;
        }
        if store.is_empty() {
          return Err(Error::EmptySystemStore);
        }
        store
      }
    };
    let store = Arc::new(store);
    self.roots.insert(root.clone(), Arc::clone(&store));
    Ok(store)
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
      GuestTlsMode::Tls => self.leaf(name)?,
      GuestTlsMode::Mtls => self.leaf_mtls(name)?,
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
    let roots = self.roots_for(&root)?;
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
    if scope.is_downstream_tls {
      return self
        .relay_settled(guest, guest_head, guest_tls, upstream, scope, &ctx, upstream_name)
        .await;
    }
    if scope.is_upstream_tls {
      let plain = self.connect_server(scope, upstream_name, upstream).await?;
      self
        .until_starttls(Prefixed::new(guest_head, guest), plain, scope, &ctx, budget, &state.mint, false)
        .await
    } else {
      self
        .until_starttls(Prefixed::new(guest_head, guest), upstream, scope, &ctx, budget, &state.mint, true)
        .await
    }
  }
}

impl LdapTransport {
  /// Both legs already know their transport. LDAPS, or cleartext with no
  /// upgrade, lands here.
  async fn relay_settled<G, S>(
    &self,
    guest: G,
    guest_head: Vec<u8>,
    guest_tls: Option<(Vec<u8>, String)>,
    upstream: S,
    scope: &LdapScope,
    ctx: &PairCtx<'_>,
    upstream_name: &str,
  ) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    match (guest_tls, scope.is_upstream_tls) {
      (None, false) => relay(Prefixed::new(guest_head, guest), upstream, ctx).await,
      (Some((hello_buf, identity)), false) => {
        let plain = self
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        relay(plain, upstream, ctx).await
      }
      (None, true) => {
        let plain = self.connect_server(scope, upstream_name, upstream).await?;
        relay(Prefixed::new(guest_head, guest), plain, ctx).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = self
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        let server_plain = self.connect_server(scope, upstream_name, upstream).await?;
        relay(guest_plain, server_plain, ctx).await
      }
    }
  }

  /// Plaintext LDAP until a `StartTLS` request has been answered, then TLS.
  async fn until_starttls<G, S>(
    &self,
    guest: G,
    server: S,
    scope: &LdapScope,
    ctx: &PairCtx<'_>,
    budget: Duration,
    mint: &MintBucket,
    upgrade_upstream: bool,
  ) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let (mut guest_r, mut guest_w) = split(guest);
    let (mut server_r, mut server_w) = split(server);
    let (mut down, mut up) = ldap_pair(ctx);
    let mut guest_buf = vec![0u8; 16 * 1024];
    let mut server_buf = vec![0u8; 16 * 1024];
    loop {
      tokio::select! {
        result = guest_r.read(&mut guest_buf) => {
          let n = read_count(result).map_err(|source| Error::GuestRead { source })?;
          if n == 0 {
            let _ = push_down(&mut down, &[], &mut server_w, upgrade_upstream).await?;
            let _ = server_w.shutdown().await;
            return drain(&mut server_r, &mut guest_w, &mut up, &mut server_buf).await;
          }
          match push_down(&mut down, &guest_buf[..n], &mut server_w, upgrade_upstream).await? {
            Step::Continue => {}
            Step::Close => return Ok(()),
            Step::Upgrade(id) => {
              return self.upgrade(
                id, guest_r, guest_w, server_r, server_w, &mut down, &mut up, scope, ctx, budget, mint, upgrade_upstream,
              ).await;
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
  async fn upgrade<G, S>(
    &self,
    id: u32,
    guest_r: ReadHalf<G>,
    mut guest_w: WriteHalf<G>,
    mut server_r: ReadHalf<S>,
    server_w: WriteHalf<S>,
    down: &mut Ldap,
    up: &mut Ldap,
    scope: &LdapScope,
    ctx: &PairCtx<'_>,
    budget: Duration,
    mint: &MintBucket,
    upgrade_upstream: bool,
  ) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let prefix = down.take_prefix();
    let success = if upgrade_upstream {
      up.expect_starttls(id);
      read_starttls_result(&mut server_r, &mut guest_w, up, budget).await?
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
    let authority = Some(scope.downstream.host.as_str());
    let Some((hello_buf, identity, _)) = guest_tls_opening(&mut guest, &prefix, budget, authority, mint).await? else {
      return Ok(());
    };
    let guest_plain = self
      .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
      .await?;
    let (mut downstream, mut upstream) = ldap_pair(ctx);
    if upgrade_upstream {
      let server_plain = self.connect_server(scope, scope.upstream.host.as_str(), server).await?;
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
      .map_err(|_| Error::UpstreamRead {
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

/// Pump one settled pair. Both legs are plaintext by the time this runs.
async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream, mut upstream) = ldap_pair(ctx);
  relay_guarded(guest, server, &mut downstream, &mut upstream, &[]).await
}

/// Both directions for an LDAP scope.
pub(crate) fn ldap_pair(ctx: &PairCtx<'_>) -> (Ldap, Ldap) {
  (
    Ldap::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream),
    Ldap::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream),
  )
}
