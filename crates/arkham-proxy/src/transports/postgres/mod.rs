//! Postgres vertical: transport halves, serve arm, and the pgwire framing
//! machine — everything postgres owns.

pub(crate) mod machine;

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{GuestTlsMode, PostgresScope, RootCert, SslMode, SslNegotiation};
use arkham_pki::ca::CertAuthority;

use super::PairCtx;
use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Postgres};
use crate::transports::engine::{GuestOpening, read_guest_opening, request_upstream_tls};
use crate::transports::tls::{cached_leaf, cached_leaf_mtls, cached_roots};
use rama::tls::client::ClientAuth;

/// Postgres transport: guest leaves under the `postgresql` ALPN, upstream
/// handshakes under libpq's `sslmode` law.
#[derive(Debug)]
pub(crate) struct PostgresTransport {
  ca: CertAuthority,
  provider: Arc<CryptoProvider>,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl PostgresTransport {
  /// Build both halves over the CA that signs guest-facing leaves.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA cannot be read back from its own PEM.
  pub(crate) fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      // An own handle on the same CA: minting needs its signing key, and the
      // caller's borrow ends with this call.
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      provider: CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
      leaves: DashMap::new(),
      roots: DashMap::new(),
    })
  }
}

impl TlsHalves for PostgresTransport {
  type Scope = PostgresScope;

  /// Accept the guest's TLS, minting the leaf for `sni` on first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  async fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    // A real server offers this identifier, and a direct-TLS client looks for
    // it (PostgreSQL 17). Classic clients offer no ALPN and see none.
    let config = match guest_tls {
      GuestTlsMode::Tls => cached_leaf(&self.ca, &self.leaves, name, Some(POSTGRESQL_ALPN))?,
      // `mtls` asks the guest for a client certificate and admits only ones
      // this arkham's own CA signs — the same anchor that mints the leaves.
      GuestTlsMode::Mtls => cached_leaf_mtls(&self.ca, &self.leaves, name, Some(POSTGRESQL_ALPN))?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|err| Error::GuestPostgresTls { source: err })
  }

  /// Handshake the server, verifying only what the entry asked to verify.
  ///
  /// # Errors
  ///
  /// Returns an error when the named trust anchor cannot be read, when the
  /// server name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &PostgresScope, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let roots = match &scope.root_cert {
      Some(root) => Some(cached_roots(&self.roots, root)?),
      None => None,
    };
    let verifier = EgressCertVerifier {
      roots,
      check_name: scope.ssl == SslMode::VerifyFull,
      provider: Arc::clone(&self.provider),
    };
    let builder = ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(verifier));
    let mut config = match (&scope.client_cert, &scope.client_key) {
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
    if scope.negotiation == SslNegotiation::Direct {
      // Direct TLS is defined by this identifier, on both ends (RFC 9113 does
      // the same for `h2`). A negotiated-shape client offers nothing.
      config.alpn_protocols = vec![POSTGRESQL_ALPN.to_vec()];
    }
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::PostgresServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|err| Error::ServerPostgresTls { source: err })
  }
}

impl Transport for PostgresTransport {
  type Scope = PostgresScope;

  /// The `postgres://` arm. The entry states the far side's transport and
  /// the guest states its own, so both legs are settled here and the wire
  /// machine then works on plaintext whichever way either arrived.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, PostgresScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      host,
      raw_host,
      port,
      initial,
      ..
    } = params;
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let Some(opening) = read_guest_opening(&mut guest, initial, budget).await? else {
      return Ok(());
    };
    let mut server_name = host.map(ToString::to_string);
    // Guest leg: everything already read past the opening, plus the name to
    // mint for when the guest asked for TLS. Those bytes were consumed from
    // the guest stream, so they are replayed into whichever leg follows.
    let mut guest_tls: Option<(Vec<u8>, String)> = None;
    let mut guest_head = Vec::new();
    if let GuestOpening::Tls(buf) = opening {
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, &buf, budget, host, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    } else if let GuestOpening::Cleartext(buf) = opening {
      guest_head = buf;
    }

    // The real string states the far end: the dial follows its host and
    // port, not the destination the guest aimed at.
    let mut upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    // `disable` never asks. `allow` mimics libpq statelessly: the guest's
    // own escalation decides the upstream leg. A cleartext guest gets
    // cleartext upstream — a hostssl-only refusal is relayed honestly, and
    // it is the guest's libpq that reconnects with an SSLRequest — while a
    // guest that asked for TLS escalates the upstream to TLS too.
    let asks_tls = match scope.ssl {
      SslMode::Disable => false,
      SslMode::Allow => guest_tls.is_some(),
      SslMode::Prefer | SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull => true,
    };
    let accepted = if asks_tls {
      request_upstream_tls(&mut upstream, scope.negotiation, budget).await?
    } else {
      false
    };
    let needed = matches!(scope.ssl, SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull);
    if needed && !accepted {
      tracing::debug!(host = %scope.upstream.host, "server refused TLS on an entry that requires it; closing");
      return Ok(());
    }

    let ctx = PairCtx {
      grants: &snapshot.grants,
      host: server_name.as_deref().unwrap_or(raw_host),
      port,
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    // The upstream leg verifies against the real string's host, which its
    // certificate must carry.
    let upstream_name = scope.upstream.host.as_str();
    let postgres = &state.postgres;
    match (guest_tls, accepted) {
      (None, false) => relay(Prefixed::new(guest_head, guest), upstream, &ctx).await,
      (Some((hello_buf, identity)), false) => {
        let plain = postgres
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        relay(plain, upstream, &ctx).await
      }
      (None, true) => {
        let plain = postgres.connect_server(scope, upstream_name, upstream).await?;
        relay(Prefixed::new(guest_head, guest), plain, &ctx).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = postgres
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        let server_plain = postgres.connect_server(scope, upstream_name, upstream).await?;
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
  let (mut downstream_machine, mut upstream_machine) = postgres_pair(ctx);
  relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, &[], &[]).await
}

/// ALPN identifier for direct Postgres TLS.
const POSTGRESQL_ALPN: &[u8] = b"postgresql";

/// Egress server verification shaped by the entry rather than by this proxy.
///
/// libpq verifies nothing when no trust anchor is named, which is what makes
/// `require` usable against a private server; it verifies the chain once one
/// is; and it checks the host name only for `verify-full`. Inventing an anchor
/// here would fail the servers those modes exist to reach.
#[derive(Debug)]
struct EgressCertVerifier {
  roots: Option<Arc<RootCertStore>>,
  check_name: bool,
  provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for EgressCertVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, RustlsError> {
    let Some(roots) = self.roots.as_ref() else {
      return Ok(ServerCertVerified::assertion());
    };
    let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
    rustls::client::verify_server_cert_signed_by_trust_anchor(
      &cert,
      roots,
      intermediates,
      now,
      self.provider.signature_verification_algorithms.all,
    )?;
    if self.check_name {
      rustls::client::verify_server_name(&cert, server_name)?;
    }
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.provider.signature_verification_algorithms.supported_schemes()
  }
}

/// Cleartext Postgres: pgwire greeting, then raw relay on postgres grants.
pub(crate) fn postgres_pair(ctx: &PairCtx<'_>) -> (Postgres, Postgres) {
  (
    Postgres::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream),
    Postgres::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream),
  )
}
