//! Redis vertical: transport halves, serve arm, and the RESP framing
//! machine — everything redis owns.

pub(crate) mod machine;

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{GuestTlsMode, RedisScope, RootCert};
use arkham_pki::ca::CertAuthority;
use arkham_pki::ca::generate_domain_pair;

use super::PairCtx;
use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Redis};
use rama::tls::client::ClientAuth;

/// First byte of a TLS record carrying a handshake: the only shape a
/// `rediss` guest leg opens with, and a shape a cleartext `redis` scope
/// never serves.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// Redis transport: each connection string states its own leg, and the
/// upstream `rediss` leg verifies the chain and the host name — the https
/// precedent, not libpq's.
#[derive(Debug)]
pub(crate) struct RedisTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl RedisTransport {
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

  /// Leaf for one name, cached. Minted before insert so two guests naming
  /// the same host keygen at most twice.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted.
  fn leaf(&self, sni: &str) -> Result<Arc<ServerConfig>, Error> {
    if let Some(config) = self.leaves.get(sni) {
      return Ok(config.clone());
    }
    // Redis has no ALPN identifier; a real server offers none either.
    let config = Arc::new((*self.ca.generate_domain_cert(sni)?.server_config).clone());
    self.leaves.insert(sni.to_string(), Arc::clone(&config));
    Ok(config)
  }

  /// `mtls` variant of [`Self::leaf`]: the same leaf shape, presented by a
  /// config that demands a client certificate this arkham's CA can verify.
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

  /// Trust anchors for the upstream leg: the entry's `sslrootcert`, or the
  /// platform store when it names none.
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
      // The platform trust store, read once; an unreadable or empty store
      // fails closed rather than silently verifying nothing.
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

impl TlsHalves for RedisTransport {
  type Scope = RedisScope;

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
      // `mtls` asks the guest for a client certificate and admits only ones
      // this arkham's own CA signs — the same anchor that mints the leaves.
      GuestTlsMode::Mtls => self.leaf_mtls(name)?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|err| Error::GuestRedisTls { source: err })
  }

  /// Handshake the server: chain and host name are always verified, against
  /// the entry's `sslrootcert` or the platform store.
  ///
  /// # Errors
  ///
  /// Returns an error when the trust anchor cannot be read, when the server
  /// name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &RedisScope, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let root = scope.root_cert.clone().unwrap_or(RootCert::System);
    let roots = self.roots_for(&root)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match (&scope.client_cert, &scope.client_key) {
      // The entry names the proxy's client identity, so the upstream leg
      // presents it; nothing else invents one.
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
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::RedisServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|err| Error::ServerRedisTls { source: err })
  }
}

impl Transport for RedisTransport {
  type Scope = RedisScope;

  /// The `redis://` / `rediss://` arm. Each connection string states its
  /// own leg's transport, so both legs are settled here and the wire
  /// machine then works on plaintext whichever way either arrived.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, RedisScope>) -> Result<(), Error>
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
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, initial, budget, host, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    } else if initial.first() == Some(&TLS_RECORD_HANDSHAKE) {
      // The scope says cleartext; a TLS hello is a different protocol on a
      // port this scope owns, and the arm never guesses another one.
      tracing::debug!("TLS opening on a cleartext redis scope; closing");
      return Ok(());
    }

    // The real string states the far end: the dial follows its host and
    // port, not the destination the guest aimed at.
    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    // Transparent capture knows the destination address, not the name in
    // the connection string. The scope was already chosen by port; keying
    // the swap on that address would miss the grant and forward the fake
    // password unchanged.
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
    let redis = &state.redis;
    match (guest_tls, scope.is_upstream_tls) {
      (None, false) => relay(Prefixed::new(guest_head, guest), upstream, &ctx).await,
      (Some((hello_buf, identity)), false) => {
        let plain = redis
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        relay(plain, upstream, &ctx).await
      }
      (None, true) => {
        let plain = redis.connect_server(scope, upstream_name, upstream).await?;
        relay(Prefixed::new(guest_head, guest), plain, &ctx).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = redis
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        let server_plain = redis.connect_server(scope, upstream_name, upstream).await?;
        relay(guest_plain, server_plain, &ctx).await
      }
    }
  }
}

/// Pump one settled pair: both legs are plaintext by the time this runs,
/// whichever transports carried them there.
async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream_machine, mut upstream_machine) = redis_pair(ctx);
  relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, &[]).await
}

/// Both directions for a redis scope: AUTH and HELLO reframe downstream,
/// redaction upstream, over whichever transports carried them there.
pub(crate) fn redis_pair(ctx: &PairCtx<'_>) -> (Redis, Redis) {
  (
    Redis::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream),
    Redis::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream),
  )
}
