//! End-to-end proxy tests: real clients through the MITM against real
//! stub servers, per protocol and per transport.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arkham_config::grants::{ResolvedConfig, Scheme};
use arkham_pki::ca::CertAuthority;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::{ProxyState, bind_explicit, parse_authority, serve, serve_transparent_stream};
use crate::relay::relay_guarded;

#[cfg(test)]
/// Test helper: bound address of a listener.
fn local_addr(listener: &TcpListener) -> SocketAddr {
  listener.local_addr().expect("listener has an address")
}

#[cfg(test)]
/// Three-byte H2 frame-length prefix (big-endian, capped at 24 bits).
fn h2_len(len: usize) -> [u8; 3] {
  u32::try_from(len).expect("frame length fits 24 bits").to_be_bytes()[1..4]
    .try_into()
    .expect("three bytes")
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  use crate::transports::engine::{Direction, Http, Rewritten, Wire};
  use arkham_config::grants::{
    Credential, EndpointScope, Grant, GuestTlsMode, PostgresLeg, PostgresScope, RedisScope, SslMode, SslNegotiation,
  };
  use arkham_config::{PluginDirection, ResolvedPlugin};
  use arkham_pki::ca::install_crypto_provider;
  use rustls::pki_types::ServerName;
  use tokio_rustls::{TlsAcceptor, TlsConnector};

  #[test]
  fn parse_authority_bracketed_v6_default_port() {
    assert_eq!(parse_authority("[::1]:8080", None), Some(("::1".to_string(), 8080)));
    assert_eq!(parse_authority("[::1]", Some(80)), Some(("::1".to_string(), 80)));
    assert_eq!(parse_authority("[::1]", None), None);
    assert_eq!(parse_authority("[::1]extra", Some(80)), None);
    assert_eq!(parse_authority("example.com", Some(80)), Some(("example.com".to_string(), 80)));
    // Unbracketed IPv6 is never split: mirrors the grant parser rejection.
    assert_eq!(parse_authority("::1", Some(80)), None);
    assert_eq!(parse_authority("::1", None), None);
    assert_eq!(parse_authority("2001:db8::1:443", None), None);
    // Userinfo never authenticates upstream: reject, don't dial it.
    assert_eq!(parse_authority("user@example.com:80", None), None);
  }
  fn test_state() -> Arc<ProxyState> {
    test_state_with(Vec::new(), &CertAuthority::generate().unwrap())
  }

  fn test_state_with(grants: Vec<Grant>, ca: &CertAuthority) -> Arc<ProxyState> {
    test_state_with_plugins(grants, Vec::new(), ca)
  }

  fn test_state_with_plugins(grants: Vec<Grant>, plugins: Vec<ResolvedPlugin>, ca: &CertAuthority) -> Arc<ProxyState> {
    test_state_with_budget(grants, plugins, ca, 10)
  }

  /// [`test_state_with_plugins`] with an explicit handshake budget, for the
  /// tests that pin timeout behavior.
  fn test_state_with_budget(
    grants: Vec<Grant>,
    plugins: Vec<ResolvedPlugin>,
    ca: &CertAuthority,
    handshake_timeout_secs: u64,
  ) -> Arc<ProxyState> {
    install_crypto_provider();
    Arc::new(
      ProxyState::new(
        ResolvedConfig {
          proxy: arkham_config::config::ProxyCfg {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_file: None,
            ssh_host_key: None,
            ssh_known_hosts: None,
            root_certs: Vec::new(),
            handshake_timeout_secs,
          },
          grants,
          plugins,
        },
        ca,
      )
      .unwrap(),
    )
  }

  async fn run_proxy_with(state: Arc<ProxyState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = bind_explicit("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
      serve(listener, state).await;
    });
    (addr, handle)
  }

  async fn run_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    run_proxy_with(test_state()).await
  }

  /// Read until the HTTP head is complete, then return all bytes read so far.
  async fn read_head_from<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
      let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      assert!(n > 0, "unexpected EOF waiting for head");
      buf.extend_from_slice(&chunk[..n]);
      if buf.windows(4).any(|w| w == b"\r\n\r\n") {
        return buf;
      }
    }
  }

  struct MitmFixture {
    proxy_addr: SocketAddr,
    proxy: tokio::task::JoinHandle<()>,
    stub: TcpListener,
    stub_port: u16,
    stub_acceptor: TlsAcceptor,
    connector: TlsConnector,
  }

  /// ALPN a fixture's TLS pair negotiates: what a real client offers and a real
  /// server selects. The pump frames an HTTPS scope by this and by nothing
  /// else, so [`Alpn::None`] models a protocol that is not HTTP.
  #[derive(Clone, Copy, PartialEq, Eq)]
  enum Alpn {
    /// `http/1.1`, the ordinary HTTPS negotiation.
    Http1,
    /// `h2`.
    H2,
    /// No protocol agreed.
    None,
  }

  impl Alpn {
    fn protocols(self) -> Vec<Vec<u8>> {
      match self {
        Alpn::Http1 => vec![b"http/1.1".to_vec()],
        Alpn::H2 => vec![b"h2".to_vec()],
        Alpn::None => Vec::new(),
      }
    }
  }

  /// Stub server config that selects `alpn`, like a real HTTPS server.
  fn stub_server_config(base: &rustls::ServerConfig, alpn: Alpn) -> rustls::ServerConfig {
    let mut config = base.clone();
    config.alpn_protocols = alpn.protocols();
    config
  }

  /// Guest client config that offers `alpn`, like a real HTTPS client.
  fn guest_client_config(roots: rustls::RootCertStore, alpn: Alpn) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = alpn.protocols();
    Arc::new(config)
  }

  /// Proxy + TLS stub presenting a arkham-signed localhost cert; client
  /// connector trusts the arkham CA. Grants built with the stub port.
  async fn mitm_fixture(make_grants: impl Fn(u16) -> Vec<Grant>) -> MitmFixture {
    mitm_fixture_alpn(make_grants, |_| Vec::new(), Alpn::Http1).await
  }

  /// [`mitm_fixture`] negotiating `h2`.
  async fn mitm_fixture_h2(make_grants: impl Fn(u16) -> Vec<Grant>) -> MitmFixture {
    mitm_fixture_alpn(make_grants, |_| Vec::new(), Alpn::H2).await
  }

  /// [`mitm_fixture`] with no ALPN agreed at all.
  async fn mitm_fixture_no_alpn(make_grants: impl Fn(u16) -> Vec<Grant>) -> MitmFixture {
    mitm_fixture_alpn(make_grants, |_| Vec::new(), Alpn::None).await
  }

  /// [`mitm_fixture`] plus plugin fixtures built with the stub port.
  async fn mitm_fixture_with_plugins(
    make_grants: impl Fn(u16) -> Vec<Grant>,
    make_plugins: impl Fn(u16) -> Vec<ResolvedPlugin>,
  ) -> MitmFixture {
    mitm_fixture_alpn(make_grants, make_plugins, Alpn::Http1).await
  }

  /// [`mitm_fixture_with_plugins`] negotiating `h2`.
  async fn mitm_fixture_with_plugins_h2(
    make_grants: impl Fn(u16) -> Vec<Grant>,
    make_plugins: impl Fn(u16) -> Vec<ResolvedPlugin>,
  ) -> MitmFixture {
    mitm_fixture_alpn(make_grants, make_plugins, Alpn::H2).await
  }

  /// Fixture body shared by the flavors above.
  async fn mitm_fixture_alpn(
    make_grants: impl Fn(u16) -> Vec<Grant>,
    make_plugins: impl Fn(u16) -> Vec<ResolvedPlugin>,
    alpn: Alpn,
  ) -> MitmFixture {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = ca.generate_domain_cert("localhost").unwrap();
    let stub_acceptor = TlsAcceptor::from(Arc::new(stub_server_config(&stub_cert.server_config, alpn)));
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let mut grants = make_grants(stub_port);
    // Egress trusts webpki plus per-entry bundles only: fixture scopes ride
    // the arkham bundle explicitly, exactly like production rules must.
    let bundle_dir = tempfile::tempdir().unwrap();
    let bundle = bundle_dir.path().join("arkham-ca.pem");
    std::fs::write(&bundle, ca.cert_pem()).unwrap();
    for grant in &mut grants {
      let Grant::Token { allow, .. } = grant else { continue };
      for scope in allow {
        if scope.scheme == Scheme::Https && scope.root_cert.is_none() {
          scope.root_cert = Some(bundle.clone());
        }
      }
    }
    let plugins = make_plugins(stub_port);
    let (proxy_addr, proxy) = run_proxy_with(test_state_with_plugins(grants, plugins, &ca)).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let connector = TlsConnector::from(guest_client_config(roots, alpn));
    MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    }
  }

  fn localhost_grant(port: u16, fake: &str, value: &str) -> Vec<Grant> {
    vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: fake.into(),
        value: secrecy::SecretString::from(value.to_string()),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "localhost".parse().unwrap(),
        port,
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }]
  }

  /// CONNECT through the proxy and complete a client TLS handshake.
  async fn mitm_client_tls(proxy_addr: SocketAddr, stub_port: u16, connector: &TlsConnector) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let server_name = ServerName::try_from("localhost".to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client))
      .await
      .unwrap()
      .unwrap()
  }

  /// Read a full Content-Length body given head bytes already read.
  async fn read_body<S: AsyncRead + Unpin>(tls: &mut S, head_bytes: &[u8], len: usize) -> Vec<u8> {
    let head_end = head_bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let mut body = Vec::from(&head_bytes[head_end..]);
    while body.len() < len {
      let mut chunk = vec![0u8; len - body.len()];
      let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      assert!(n > 0, "unexpected EOF waiting for body");
      body.extend_from_slice(&chunk[..n]);
    }
    body
  }

  #[tokio::test]
  async fn connect_splices_bytes_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await;

    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut buf = [0u8; 5];
      conn.read_exact(&mut buf).await.unwrap();
      assert_eq!(&buf, b"hello");
      conn.write_all(b"world").await.unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: {stub_addr}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    client.write_all(b"hello").await.unwrap();
    let mut echo = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&echo, b"world");

    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn absolute_form_forwards_head_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await;

    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let head = read_head_from(&mut conn).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(
        head_str.starts_with(&format!("GET http://{stub_addr}/x HTTP/1.1\r\n")),
        "{head_str}"
      );
      conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("GET http://{stub_addr}/x HTTP/1.1\r\nHost: {stub_addr}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
      .await
      .unwrap()
      .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{}", response.escape_ascii());

    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn malformed_request_closes_without_response() {
    let (proxy_addr, proxy) = run_proxy().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(response, [] as [u8; 0]);
    proxy.abort();
  }

  #[tokio::test]
  async fn mitm_terminates_both_ends_verbatim() {
    let fx = mitm_fixture(|port| localhost_grant(port, "fake", "value")).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains("Authorization: Bearer hello\r\n"), "{head_str}");
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer hello\r\n\r\n")
      .await
      .unwrap();
    let response = read_head_from(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
    assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn mitm_substitutes_request_and_redacts_response() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let fx = mitm_fixture(|port| localhost_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Authorization: Bearer {VALUE}\r\n")), "{head_str}");
      assert!(!head_str.contains(FAKE), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let response = read_head_from(&mut tls).await;
    let resp_str = String::from_utf8_lossy(&response);
    assert!(!resp_str.contains(VALUE), "{resp_str}");
    let expect_body = format!("echo:{FAKE}");
    assert_eq!(read_body(&mut tls, &response, expect_body.len()).await, expect_body.as_bytes());
    stub_task.await.unwrap();
    proxy.abort();
  }

  fn localhost_tcp_grant(port: u16, fake: &str, value: &str) -> Vec<Grant> {
    vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: fake.into(),
        value: secrecy::SecretString::from(value.to_string()),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Tcp,
        host: "localhost".parse().unwrap(),
        port,
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }]
  }

  #[tokio::test]
  async fn tcp_only_grant_splices_tls_verbatim() {
    // A tcp:// grant on the TLS port must not trigger MITM: the handshake
    // passes through to the stub, fakes stay fakes, values stay values.
    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
    let fx = mitm_fixture(|port| localhost_tcp_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Authorization: Bearer {FAKE}\r\n")), "{head_str}");
      assert!(!head_str.contains(VALUE), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let response = read_head_from(&mut tls).await;
    let resp_str = String::from_utf8_lossy(&response);
    assert!(resp_str.contains(VALUE), "{resp_str}");
    let expect_body = format!("echo:{VALUE}");
    assert_eq!(read_body(&mut tls, &response, expect_body.len()).await, expect_body.as_bytes());
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn connect_authority_sni_mismatch_closes_without_dial() {
    let fx = mitm_fixture(|port| localhost_grant(port, "fake", "value")).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      connector,
      ..
    } = fx;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    // Authority says localhost, SNI says otherwise: the relay must close
    // quietly instead of minting, so the handshake fails on EOF.
    let server_name = ServerName::try_from("other.test".to_string()).unwrap();
    let handshake = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client)).await;
    let failed = match handshake {
      Err(_) | Ok(Err(_)) => true,
      Ok(Ok(_)) => false,
    };
    assert!(failed, "mismatched SNI must not complete a handshake");
    // No upstream dial happened: the stub accept still hangs.
    tokio::time::timeout(Duration::from_secs(2), stub.accept()).await.unwrap_err();
    proxy.abort();
  }
  #[tokio::test]
  async fn non_candidate_splices_bytes_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await; // no grants: splice path
    let blob: Vec<u8> = (0..256u32).map(|i| u8::try_from(i % 251).expect("fits u8")).collect();
    let expect = blob.clone();
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut got = vec![0u8; expect.len()];
      conn.read_exact(&mut got).await.unwrap();
      assert_eq!(got, expect);
    });
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    client.write_all(&blob).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), stub_task).await.unwrap().unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn tls_through_splice_leaves_fake_untouched() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let fx = mitm_fixture(|_| Vec::new()).await; // no grants: splice, full TLS through
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Bearer {FAKE}\r\n")), "{head_str}");
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let response = read_head_from(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
    assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn https_scope_without_alpn_relays_raw() {
    // No ALPN agreed, so nothing proves the plaintext is HTTP and the pump
    // frames it raw: bytes swap in place, with no head parsed and none waited
    // for. That last part is what lets a non-HTTP protocol on an https scope
    // flow immediately instead of stalling on a head that never comes.
    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
    let fx = mitm_fixture_no_alpn(|port| localhost_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let mut auth = vec![0u8; 5 + VALUE.len() + 1];
      tls.read_exact(&mut auth).await.unwrap();
      assert_eq!(auth, format!("AUTH {VALUE}\n").into_bytes(), "upstream sees the real value");
      tls.write_all(format!("TOKEN {VALUE}\n").as_bytes()).await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls.write_all(format!("AUTH {FAKE}\n").as_bytes()).await.unwrap();
    let mut token = vec![0u8; 6 + VALUE.len() + 1];
    tls.read_exact(&mut token).await.unwrap();
    assert_eq!(token, format!("TOKEN {FAKE}\n").into_bytes(), "guest sees the fake back");
    stub_task.await.unwrap();
    proxy.abort();
  }

  /// The entry's `sslcert`/`sslkey` pair is the proxy's upstream client
  /// identity: the stub demands a client certificate the arkham CA signed, and
  /// the substitution round trip only completes when the egress leg presents
  /// exactly the entry's.
  #[tokio::test]
  async fn https_entry_presents_its_client_identity_upstream() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    use rama::crypto::pem::PemEncode as _;
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (client_chain, client_key) = arkham_pki::ca::generate_client_pair(&ca, "arkham-client").unwrap();
    let mut cert_pem = Vec::new();
    for cert in &client_chain {
      cert_pem.extend_from_slice(cert.to_pem().as_bytes());
    }
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    let bundle = dir.path().join("arkham-ca.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, client_key.to_pem()).unwrap();
    std::fs::write(&bundle, ca.cert_pem()).unwrap();

    let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&ca, "localhost").unwrap();
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(ca.cert_der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
      .build()
      .unwrap();
    let server_config = rustls::ServerConfig::builder()
      .with_client_cert_verifier(verifier)
      .with_single_cert(server_chain, server_key)
      .unwrap();
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let stub_task = tokio::spawn(async move {
      let (stream, _) = stub.accept().await.unwrap();
      let mut tls = TlsAcceptor::from(Arc::new(server_config)).accept(stream).await.unwrap();
      let peer = tls.get_ref().1.peer_certificates().and_then(|certs| certs.first().cloned());
      let head = read_head_from(&mut tls).await;
      assert!(head.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
      tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
      peer
    });

    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE.to_string()),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "localhost".parse().unwrap(),
        port: stub_port,
        client_cert: Some(cert_path.clone()),
        client_key: Some(key_path.clone()),
        root_cert: Some(bundle),
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = test_state_with_plugins(grants, Vec::new(), &ca);
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
    guest
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut ok = [0u8; 19];
    guest.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
    let mut tls = connector
      .connect(rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), guest)
      .await
      .unwrap();
    tls
      .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let head = read_head_from(&mut tls).await;
    assert!(head.starts_with(b"HTTP/1.1 200 OK"));

    let peer = stub_task.await.unwrap();
    assert_eq!(peer.as_ref(), client_chain.first());
  }

  /// `root_cert` on an https entry: egress trusts the entry's private CA
  /// bundle on top of the globals, so substitution works against hosts no
  /// public CA signs. The stub's CA is standalone, never the arkham CA.
  #[tokio::test]
  async fn https_entry_root_cert_trusts_private_upstream_ca() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let upstream_ca = CertAuthority::generate().unwrap();

    let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&upstream_ca, "localhost").unwrap();
    let server_config = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(server_chain, server_key)
      .unwrap();
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let seen_later = Arc::clone(&seen);
    let stub_task = tokio::spawn(async move {
      let (stream, _) = stub.accept().await.unwrap();
      let mut tls = TlsAcceptor::from(Arc::new(server_config)).accept(stream).await.unwrap();
      let head = read_head_from(&mut tls).await;
      seen_later.lock().await.extend_from_slice(&head);
      tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("upstream-ca.pem");
    std::fs::write(&bundle, upstream_ca.cert_pem()).unwrap();

    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE.to_string()),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "localhost".parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: Some(bundle),
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = test_state_with_plugins(grants, Vec::new(), &ca);
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
    guest
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut ok = [0u8; 19];
    guest.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
    let mut tls = connector
      .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
      .await
      .unwrap();
    tls
      .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let head = read_head_from(&mut tls).await;
    assert!(head.starts_with(b"HTTP/1.1 200 OK"));

    stub_task.await.unwrap();
    let seen = seen.lock().await;
    assert!(seen.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
  }

  /// Global `root_certs`: the bundle in `[proxy]` trusts the private-CA stub
  /// for entries naming no `root_cert` of their own.
  #[tokio::test]
  async fn https_global_root_certs_trust_private_upstream_ca() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let upstream_ca = CertAuthority::generate().unwrap();

    let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&upstream_ca, "localhost").unwrap();
    let server_config = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(server_chain, server_key)
      .unwrap();
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let seen_later = Arc::clone(&seen);
    let stub_task = tokio::spawn(async move {
      let (stream, _) = stub.accept().await.unwrap();
      let mut tls = TlsAcceptor::from(Arc::new(server_config)).accept(stream).await.unwrap();
      let head = read_head_from(&mut tls).await;
      seen_later.lock().await.extend_from_slice(&head);
      tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("upstream-ca.pem");
    std::fs::write(&bundle, upstream_ca.cert_pem()).unwrap();

    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE.to_string()),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "localhost".parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = Arc::new(
      ProxyState::new(
        ResolvedConfig {
          proxy: arkham_config::config::ProxyCfg {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_file: None,
            root_certs: vec![bundle],
            ssh_host_key: None,
            ssh_known_hosts: None,
            handshake_timeout_secs: 10,
          },
          grants,
          plugins: Vec::new(),
        },
        &ca,
      )
      .unwrap(),
    );
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
    guest
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut ok = [0u8; 19];
    guest.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
    let mut tls = connector
      .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
      .await
      .unwrap();
    tls
      .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let head = read_head_from(&mut tls).await;
    assert!(head.starts_with(b"HTTP/1.1 200 OK"));

    stub_task.await.unwrap();
    let seen = seen.lock().await;
    assert!(seen.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
  }

  /// Same private-CA stub without `root_cert`: egress fails closed at the
  /// upstream handshake, so the guest never gets a response head.
  #[tokio::test]
  async fn https_without_root_cert_fails_closed_on_private_upstream_ca() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let upstream_ca = CertAuthority::generate().unwrap();

    let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&upstream_ca, "localhost").unwrap();
    let server_config = Arc::new(
      rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_chain, server_key)
        .unwrap(),
    );
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    tokio::spawn(async move {
      loop {
        let Ok((stream, _)) = stub.accept().await else { return };
        let acceptor = TlsAcceptor::from(Arc::clone(&server_config));
        tokio::spawn(async move {
          let Ok(mut tls) = acceptor.accept(stream).await else { return };
          let _ = read_head_from(&mut tls).await;
        });
      }
    });

    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from("real".to_string()),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "localhost".parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = test_state_with_plugins(grants, Vec::new(), &ca);
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
    guest
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut ok = [0u8; 19];
    guest.read_exact(&mut ok).await.unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
    let Ok(mut tls) = connector
      .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
      .await
    else {
      return;
    };
    tls
      .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut chunk = [0u8; 4096];
    let closed = match tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk)).await {
      Err(_) | Ok(Err(_) | Ok(0)) => true,
      Ok(Ok(_)) => false,
    };
    assert!(closed, "egress to an untrusted upstream must fail closed");
  }

  /// `guest_tls_mode = "mtls"` on an https entry: arkham demands a client
  /// certificate from the guest and admits only ones its own CA signs.
  ///
  /// TLS 1.3 hands the guest the server Finished before the server
  /// validates the guest certificate, so a refused guest's `connect` can
  /// still return `Ok` — the refusal surfaces on the read after, never in
  /// the connect result. The assertion point is therefore the request
  /// round trip, not the handshake.
  #[tokio::test]
  #[expect(clippy::too_many_lines, reason = "linear test script, split would obscure the flow")]
  async fn https_guest_mtls_admits_only_ca_signed_guests() {
    // CONNECT, guest TLS, one GET, then read until the response head is
    // whole; a refused guest never gets that far.
    async fn guest_round_trip(
      proxy_addr: SocketAddr,
      stub_port: u16,
      config: Arc<rustls::ClientConfig>,
      token: &'static str,
    ) -> std::io::Result<Vec<u8>> {
      let mut guest = TcpStream::connect(proxy_addr).await?;
      guest
        .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
        .await?;
      let mut ok = [0u8; 19];
      guest.read_exact(&mut ok).await?;
      let mut tls = TlsConnector::from(config)
        .connect(rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), guest)
        .await?;
      tls
        .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\r\n").as_bytes())
        .await?;
      let mut head = Vec::new();
      let mut chunk = [0u8; 4096];
      loop {
        let n = match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk)).await {
          Ok(read) => read?,
          Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer")),
        };
        if n == 0 {
          return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "refused"));
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
          return Ok(head);
        }
      }
    }
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("arkham-ca.pem");
    std::fs::write(&bundle, ca.cert_pem()).unwrap();

    let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&ca, "localhost").unwrap();
    let server_config = Arc::new(
      rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_chain, server_key)
        .unwrap(),
    );
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let seen_later = Arc::clone(&seen);
    // One upstream connection per guest attempt (the relay dials upstream
    // before answering the guest); refused guests leave the handler on
    // EOF or timeout instead of an HTTP exchange.
    let stub_task = tokio::spawn(async move {
      loop {
        let Ok((conn, _)) = stub.accept().await else { return };
        let seen = Arc::clone(&seen);
        let acceptor = TlsAcceptor::from(Arc::clone(&server_config));
        tokio::spawn(async move {
          let Ok(mut tls) = acceptor.accept(conn).await else { return };
          let mut buf = Vec::new();
          let mut chunk = [0u8; 4096];
          loop {
            let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk)).await else {
              return;
            };
            if n == 0 {
              return;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
              break;
            }
          }
          seen.lock().await.extend(buf);
          tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
        });
      }
    });

    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE.to_string()),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "localhost".parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: Some(bundle),
        guest_tls: arkham_config::grants::GuestTlsMode::Mtls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = test_state_with_plugins(grants, Vec::new(), &ca);
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    // CA-signed guest: full round trip with fake-to-real substitution.
    let (chain, key) = arkham_pki::ca::generate_client_pair(&ca, "guest").unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_client_auth_cert(chain, key)
      .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let head = guest_round_trip(proxy_addr, stub_port, Arc::new(config), FAKE).await.unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200 OK"));
    assert!(seen_later.lock().await.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));

    // Certless guest: refused — the read after connect dies.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    guest_round_trip(proxy_addr, stub_port, guest_client_config(roots, Alpn::Http1), FAKE)
      .await
      .expect_err("the certless guest must not round-trip");

    // Guest with a certificate arkham's CA did not sign: refused too.
    let stranger = CertAuthority::generate().unwrap();
    let (chain, key) = arkham_pki::ca::generate_client_pair(&stranger, "guest").unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_client_auth_cert(chain, key)
      .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    guest_round_trip(proxy_addr, stub_port, Arc::new(config), FAKE)
      .await
      .expect_err("an untrusted guest must not round-trip");

    stub_task.abort();
  }

  #[tokio::test]
  async fn mitm_h2_substitutes_headers() {
    use httlib_hpack::{Decoder, Encoder};

    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let fx = mitm_fixture_h2(|port| localhost_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;

    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      // Raw preface + HEADERS arrive; upstream HPACK-decodes the value.
      let mut preface = [0u8; 24];
      tls.read_exact(&mut preface).await.unwrap();
      assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
      let mut hdr = [0u8; 9];
      tls.read_exact(&mut hdr).await.unwrap();
      assert_eq!(hdr[3], 0x1, "expected HEADERS");
      assert_eq!(u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff, 1);
      let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
      let mut block = vec![0u8; len];
      tls.read_exact(&mut block).await.unwrap();
      let mut decoder = Decoder::default();
      let mut headers = Vec::new();
      decoder.decode(&mut block, &mut headers).unwrap();
      let auth = headers.iter().find(|(name, _, _)| name == b"authorization").unwrap();
      assert_eq!(auth.1, format!("Bearer {VALUE}").as_bytes());
      tls.shutdown().await.unwrap();
    });

    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let mut encoder = Encoder::default();
    let mut block = Vec::new();
    for (name, value) in [
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/"),
      (":authority", "localhost"),
      ("authorization", &format!("Bearer {FAKE}")),
    ] {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut block,
        )
        .unwrap();
    }
    let mut frame = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    let len = u32::try_from(block.len()).unwrap();
    frame.extend_from_slice(&len.to_be_bytes()[1..]);
    frame.extend_from_slice(&[0x1, 0x4 | 0x1, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS|END_STREAM
    frame.extend_from_slice(&block);
    tls.write_all(&frame).await.unwrap();
    tls.flush().await.unwrap();
    // Stub shuts down after asserting; EOF ends the test race-free.
    let mut one = [0u8; 1];
    assert_eq!(tls.read(&mut one).await.unwrap(), 0);
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn absolute_form_ungranted_chunked_splices_byte_identical() {
    // No grants: chunked bodies must pass through byte-identical, never
    // re-encoded into a single chunk.
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await;
    let body = "3\r\naaa\r\n3\r\nbbb\r\n0\r\n\r\n";
    let request = format!("POST http://{stub_addr}/x HTTP/1.1\r\nHost: {stub_addr}\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
    let expected = request.clone().into_bytes();
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut buf = Vec::new();
      let mut chunk = [0u8; 4096];
      loop {
        let n = conn.read(&mut chunk).await.unwrap();
        if n == 0 {
          break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.ends_with(b"0\r\n\r\n") {
          break;
        }
      }
      assert_eq!(buf, expected, "ungranted chunked request must be byte-identical");
      conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
    });
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
      .await
      .unwrap()
      .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{}", response.escape_ascii());
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn connect_pipelined_bytes_reach_upstream_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await; // no grants: splice path
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut buf = [0u8; 5];
      conn.read_exact(&mut buf).await.unwrap();
      assert_eq!(&buf, b"early", "pipelined post-head bytes must survive");
      conn.write_all(b"ok").await.unwrap();
    });
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    // CONNECT head + payload in ONE write: the tail must be replayed.
    client
      .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: x\r\n\r\nearly").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let mut reply = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&reply, b"ok");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn transparent_plain_http_honors_http_grant() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Http,
        host: "127.0.0.1".parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = test_state_with(grants, &ca);
    let snapshot = state.snapshot();
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let head = read_head_from(&mut conn).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Authorization: Bearer {VALUE}")), "{head_str}");
      let body = format!("echo:{VALUE}");
      conn
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
    });
    let (guest, mut client_end) = tokio::io::duplex(64 * 1024);
    let serve = tokio::spawn({
      let state = Arc::clone(&state);
      let snapshot = Arc::clone(&snapshot);
      async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
    });
    client_end
      .write_all(
        format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{stub_port}\r\nAuthorization: Bearer {FAKE}\r\nConnection: close\r\n\r\n").as_bytes(),
      )
      .await
      .unwrap();
    let response = read_head_from(&mut client_end).await;
    let resp_str = String::from_utf8_lossy(&response);
    assert!(!resp_str.contains(VALUE), "{resp_str}");
    let expect = format!("echo:{FAKE}");
    assert_eq!(read_body(&mut client_end, &response, expect.len()).await, expect.as_bytes());
    stub_task.await.unwrap();
    serve.await.unwrap().unwrap();
  }

  #[tokio::test]
  async fn transparent_tls_mitm_substitutes_by_sni_identity() {
    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
    const SNI: &str = "testtun.invalid";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("arkham-ca.pem");
    std::fs::write(&bundle, ca.cert_pem()).unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = ca.generate_domain_cert(SNI).unwrap();
    let stub_acceptor = TlsAcceptor::from(Arc::new(stub_server_config(&stub_cert.server_config, Alpn::Http1)));
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: SNI.parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: Some(bundle),
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = test_state_with(grants, &ca);
    let snapshot = state.snapshot();
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
    });
    let (guest, client_end) = tokio::io::duplex(64 * 1024);
    let serve = tokio::spawn({
      let state = Arc::clone(&state);
      let snapshot = Arc::clone(&snapshot);
      // TUN shape: dial target is an address, the SNI alone is the identity.
      async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
    let server_name = ServerName::try_from(SNI.to_string()).unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client_end))
      .await
      .unwrap()
      .unwrap();
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: {SNI}\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    stub_task.await.unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
      let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      response.extend_from_slice(&chunk[..n]);
      if response.windows(4).any(|w| w == b"\r\n\r\n") {
        break;
      }
    }
    let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let expect = format!("echo:{FAKE}");
    let mut body = Vec::from(&response[head_end..]);
    while body.len() < expect.len() {
      let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(body, expect.as_bytes());
    serve.await.unwrap().unwrap();
  }

  #[tokio::test]
  async fn transparent_tls_mitm_uses_captured_ip_when_hello_has_no_sni() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let upstream_ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("upstream-ca.pem");
    std::fs::write(&bundle, upstream_ca.cert_pem()).unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = upstream_ca.generate_domain_cert("127.0.0.1").unwrap();
    let stub_acceptor = TlsAcceptor::from(Arc::new(stub_server_config(&stub_cert.server_config, Alpn::Http1)));
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "127.0.0.1".parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: Some(bundle),
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = test_state_with(grants, &ca);
    let snapshot = state.snapshot();
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
    });
    let (guest, client_end) = tokio::io::duplex(64 * 1024);
    let serve = tokio::spawn({
      let state = Arc::clone(&state);
      let snapshot = Arc::clone(&snapshot);
      // IP-literal client: the captured destination is the identity.
      async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
    // IpAddress sends no SNI extension, like kubectl against an address.
    let server_name = ServerName::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap().into());
    let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client_end))
      .await
      .unwrap()
      .unwrap();
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    stub_task.await.unwrap();
    let head = read_head_from(&mut tls).await;
    let expect = format!("echo:{FAKE}");
    assert_eq!(read_body(&mut tls, &head, expect.len()).await, expect.as_bytes());
    serve.await.unwrap().unwrap();
  }

  /// Hook that votes `Close` on every call.
  struct CloseHook;

  impl arkham_plugin::RewriteHook for CloseHook {
    fn rewrite_head<'a>(&'a mut self, _head: &'a mut arkham_plugin::Head) -> arkham_plugin::BoxFuture<'a, arkham_plugin::Verdict> {
      Box::pin(async move { arkham_plugin::Verdict::Close })
    }

    fn rewrite_trailers<'a>(
      &'a mut self,
      _headers: &'a mut Vec<arkham_plugin::Header>,
    ) -> arkham_plugin::BoxFuture<'a, arkham_plugin::Verdict> {
      Box::pin(async move { arkham_plugin::Verdict::Close })
    }

    fn rewrite_chunk<'a>(&'a mut self, _data: &'a mut Vec<u8>, _eof: bool) -> arkham_plugin::BoxFuture<'a, arkham_plugin::Verdict> {
      Box::pin(async move { arkham_plugin::Verdict::Close })
    }
  }

  #[tokio::test]
  async fn plugin_e2e_close_verdict_drops_connection() {
    let (guest_end, mut client_end) = tokio::io::duplex(64 * 1024);
    let (server_end, mut stub_end) = tokio::io::duplex(64 * 1024);
    let (mut request, mut response) = (
      Http::new(&[], Scheme::Http, "x", 80, Direction::Downstream, Some(Box::new(CloseHook)), None),
      Http::new(&[], Scheme::Http, "x", 80, Direction::Upstream, None, None),
    );
    let (relay_out, ()) = tokio::join!(relay_guarded(guest_end, server_end, &mut request, &mut response, b""), async {
      client_end.write_all(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    });
    relay_out.unwrap();
    assert!(matches!(request.feed(&[]).await, (Rewritten::Close, _)));
    // The latched head never reached the wire: upstream sees nothing.
    // The relay already returned, dropping its server half, so the read
    // resolves as EOF — zero bytes means `Ok(0)`, a leak would be `Ok(n)`.
    let mut buf = [0u8; 64];
    let n = stub_end.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "upstream must receive zero bytes");
  }

  /// Fixture component path, or `None` when `ARKHAM_PLUGIN_FIXTURES` is unset
  /// or the fixture was not built (`mise run build:plugins` first).
  fn plugin_fixture(name: &str) -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var_os("ARKHAM_PLUGIN_FIXTURES")?).join(format!("{name}.wasm"));
    path.is_file().then_some(path)
  }

  /// Plugin allow list mirroring [`localhost_grant`]: the MITM leg selects
  /// hooks with the same identity the machine receives.
  fn plugin_allow(port: u16) -> Vec<EndpointScope> {
    vec![EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port,
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,
    }]
  }

  fn plugin_entry(name: &str, port: u16, fixture: std::path::PathBuf) -> ResolvedPlugin {
    ResolvedPlugin {
      name: name.to_string(),
      path: fixture,
      allow: plugin_allow(port),
      direction: PluginDirection::Both,
    }
  }

  #[tokio::test]
  async fn plugin_e2e_request_head_chunk_and_trailers() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, FAKE, VALUE),
      |port| vec![plugin_entry("marker-request", port, fixture.clone())],
    )
    .await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Authorization: Bearer {VALUE}\r\n")), "{head_str}");
      assert!(!head_str.contains(FAKE), "{head_str}");
      // Stage 1 plugin head effect.
      assert!(head_str.contains("x-arkham-plugin: marker\r\n"), "{head_str}");
      // Chunked rest: the head read may have swallowed the whole message
      // (client sent it in one block); only read more when the chunked
      // terminator is not in hand yet.
      let mut message = head_str;
      while !message.contains("x-trailer-plugin: marker\r\n\r\n") {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
          .await
          .unwrap()
          .unwrap();
        assert!(n > 0, "unexpected EOF waiting for chunked body");
        message.push_str(&String::from_utf8_lossy(&chunk[..n]));
      }
      assert!(message.contains("C\r\nhello-marked\r\n0\r\n"), "{message}");
      assert!(message.contains("x-client-trailer: yes\r\n"), "{message}");
      assert!(message.contains("x-trailer-plugin: marker\r\n"), "{message}");
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(
        format!(
          "POST /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\nTransfer-Encoding: chunked\r\nTrailer: x-client-trailer\r\n\r\n5\r\nhello\r\n0\r\nx-client-trailer: yes\r\n\r\n"
        )
        .as_bytes(),
      )
      .await
      .unwrap();
    let response = read_head_from(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
    assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_response_head_and_chunk() {
    let Some(fixture) = plugin_fixture("marker-response") else {
      println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-response.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("marker-response", port, fixture.clone())],
    )
    .await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      assert!(
        !String::from_utf8(head).unwrap().contains("x-arkham-response-plugin"),
        "response-only world leaves the request leg alone"
      );
      tls
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        .await
        .unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let response = read_head_from(&mut tls).await;
    let resp_str = String::from_utf8_lossy(&response);
    assert!(resp_str.contains("x-arkham-response-plugin: marker\r\n"), "{resp_str}");
    // The chunk hook grew the body; chunked framing carries the new size.
    let mut message = response;
    while !message.ends_with(b"0\r\n\r\n") {
      let mut chunk = [0u8; 4096];
      let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      assert!(n > 0, "unexpected EOF waiting for chunked body");
      message.extend_from_slice(&chunk[..n]);
    }
    let message = String::from_utf8_lossy(&message);
    assert!(message.contains("C\r\nhello-marked\r\n0\r\n\r\n"), "{message}");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_h2_chunk_hook_per_frame() {
    use httlib_hpack::{Decoder, Encoder};

    fn data_frame(flags: u8, payload: &[u8]) -> Vec<u8> {
      let mut frame = Vec::new();
      frame.extend_from_slice(&h2_len(payload.len()));
      frame.extend_from_slice(&[0x0, flags, 0, 0, 0, 1]);
      frame.extend_from_slice(payload);
      frame
    }

    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins_h2(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("marker-request", port, fixture.clone())],
    )
    .await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let mut preface = [0u8; 24];
      tls.read_exact(&mut preface).await.unwrap();
      assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
      let mut hdr = [0u8; 9];
      tls.read_exact(&mut hdr).await.unwrap();
      assert_eq!(hdr[3], 0x1, "expected HEADERS");
      let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
      let mut block = vec![0u8; len];
      tls.read_exact(&mut block).await.unwrap();
      let mut decoder = Decoder::default();
      let mut headers = Vec::new();
      decoder.decode(&mut block, &mut headers).unwrap();
      assert!(
        headers
          .iter()
          .any(|(name, value, _)| name == b"x-arkham-plugin" && value == b"marker"),
        "head hook marker upstream"
      );
      // Three DATA frames, END_STREAM only on the last.
      let mut bodies = Vec::new();
      for (i, end_stream) in [false, false, true].iter().enumerate() {
        let mut hdr = [0u8; 9];
        tls.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 0x0, "expected DATA frame {i}");
        assert_eq!(hdr[4] & 0x1, u8::from(*end_stream), "END_STREAM on frame {i}");
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let mut payload = vec![0u8; len];
        tls.read_exact(&mut payload).await.unwrap();
        bodies.push(payload);
      }
      // One marker per DATA frame: the hook ran per frame (streaming),
      // not once over a buffered body (which would mark at most once).
      let joined = String::from_utf8(bodies.concat()).unwrap();
      assert_eq!(joined.matches("-marked").count(), 3, "{joined}");
      assert_eq!(joined.replace("-marked", ""), "AAAAAAAABBBBBBBBC");
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let mut encoder = Encoder::default();
    let mut block = Vec::new();
    for (name, value) in [
      (":method", "POST"),
      (":scheme", "https"),
      (":path", "/x"),
      (":authority", "localhost"),
    ] {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut block,
        )
        .unwrap();
    }
    let mut request = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    request.extend_from_slice(&h2_len(block.len()));
    request.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS
    request.extend_from_slice(&block);
    request.extend_from_slice(&data_frame(0x0, b"AAAAAAAA"));
    request.extend_from_slice(&data_frame(0x0, b"BBBBBBBB"));
    request.extend_from_slice(&data_frame(0x1, b"C"));
    tls.write_all(&request).await.unwrap();
    tls.flush().await.unwrap();
    let mut one = [0u8; 1];
    assert_eq!(tls.read(&mut one).await.unwrap(), 0);
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_h2_trailers_hook() {
    use httlib_hpack::{Decoder, Encoder};

    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins_h2(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("marker-request", port, fixture.clone())],
    )
    .await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let mut preface = [0u8; 24];
      tls.read_exact(&mut preface).await.unwrap();
      // Skip the request HEADERS; the second HEADERS block is trailers.
      for _ in 0..2 {
        let mut hdr = [0u8; 9];
        tls.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 0x1, "expected HEADERS");
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let mut block = vec![0u8; len];
        tls.read_exact(&mut block).await.unwrap();
        if hdr[4] & 0x1 == 0x1 {
          let mut decoder = Decoder::default();
          let mut headers = Vec::new();
          decoder.decode(&mut block, &mut headers).unwrap();
          assert!(headers.iter().any(|(name, value, _)| name == b"x-t" && value == b"abc"));
          assert!(
            headers
              .iter()
              .any(|(name, value, _)| name == b"x-trailer-plugin" && value == b"marker"),
            "trailer hook marker upstream"
          );
        }
      }
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let mut encoder = Encoder::default();
    let mut head_block = Vec::new();
    for (name, value) in [
      (":method", "POST"),
      (":scheme", "https"),
      (":path", "/x"),
      (":authority", "localhost"),
    ] {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut head_block,
        )
        .unwrap();
    }
    let mut trailer_block = Vec::new();
    encoder
      .encode(
        ("x-t".as_bytes().to_vec(), "abc".as_bytes().to_vec(), Encoder::NEVER_INDEXED),
        &mut trailer_block,
      )
      .unwrap();
    let mut request = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    request.extend_from_slice(&h2_len(head_block.len()));
    request.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS
    request.extend_from_slice(&head_block);
    request.extend_from_slice(&h2_len(trailer_block.len()));
    request.extend_from_slice(&[0x1, 0x4 | 0x1, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS|END_STREAM
    request.extend_from_slice(&trailer_block);
    tls.write_all(&request).await.unwrap();
    tls.flush().await.unwrap();
    let mut one = [0u8; 1];
    assert_eq!(tls.read(&mut one).await.unwrap(), 0);
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_grant_mismatch_not_invoked() {
    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| {
        vec![ResolvedPlugin {
          name: "marker-request".to_string(),
          path: fixture.clone(),
          allow: vec![EndpointScope {
            scheme: Scheme::Https,
            host: "other.invalid".parse().unwrap(),
            port,
            client_cert: None,
            client_key: None,
            root_cert: None,
            guest_tls: arkham_config::grants::GuestTlsMode::Tls,
          }],
          direction: PluginDirection::Both,
        }]
      },
    )
    .await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      assert!(
        !String::from_utf8(head).unwrap().contains("x-arkham-plugin"),
        "ungranted plugin stays out of the head"
      );
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let response = read_head_from(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
    assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_trap_fails_closed() {
    let Some(fixture) = plugin_fixture("trap-request") else {
      println!("skip: ARKHAM_PLUGIN_FIXTURES missing trap-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("trap-request", port, fixture.clone())],
    )
    .await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      // The proxy already completed the upstream TLS handshake before the
      // guest trapped on the request head: application bytes must be zero.
      let mut buf = [0u8; 64];
      let res = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await.unwrap();
      assert!(
        matches!(res, Ok(0)) || res.is_err(),
        "upstream must receive zero bytes, got {res:?}"
      );
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut one = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut one)).await.unwrap();
    assert!(matches!(res, Ok(0)) || res.is_err(), "guest connection must drop, got {res:?}");
    stub_task.await.unwrap();
    proxy.abort();
  }

  use std::pin::Pin;
  use std::task::{Context, Poll};

  use bytes::Bytes;

  /// Request or response body with no declared length, so hyper frames it
  /// chunked and the de-chunking on the far side is a real implementation's.
  struct Chunks(Vec<Bytes>);

  impl hyper::body::Body for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
      let this = self.get_mut();
      Poll::Ready(if this.0.is_empty() {
        None
      } else {
        Some(Ok(hyper::body::Frame::data(this.0.remove(0))))
      })
    }
  }

  /// Real hyper client and real hyper server through the MITM, chunked in both
  /// directions, with the needle split across chunk boundaries. The proxy
  /// re-chunks around its hold-back window, so the framing on the wire is
  /// arkham's own output and has to be accepted by an independent HTTP/1
  /// implementation on either side.
  #[tokio::test]
  async fn http1_real_client_and_server_round_trip_chunked() {
    use http_body_util::BodyExt as _;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;

    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let fx = mitm_fixture(|port| localhost_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;

    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let tls = stub_acceptor.accept(conn).await.unwrap();
      let service = service_fn(|req: Request<Incoming>| async move {
        assert_eq!(
          req.headers().get("authorization").unwrap().to_str().unwrap(),
          format!("Bearer {VALUE}")
        );
        // The proxy re-emitted this request's chunked framing itself.
        assert_eq!(req.headers().get("transfer-encoding").unwrap().to_str().unwrap(), "chunked");
        let body = req.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), format!("upload:{VALUE}"));
        let parts = format!("download:{VALUE}")
          .as_bytes()
          .chunks(8)
          .map(Bytes::copy_from_slice)
          .collect();
        Ok::<_, std::io::Error>(Response::new(Chunks(parts)))
      });
      hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls), service)
        .await
        .unwrap();
    });

    let tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
    let client_task = tokio::spawn(conn);
    let parts: Vec<Bytes> = format!("upload:{FAKE}").as_bytes().chunks(7).map(Bytes::copy_from_slice).collect();
    let request = Request::builder()
      .method("POST")
      .uri("/x")
      .header("host", "localhost")
      .header("authorization", format!("Bearer {FAKE}"))
      .body(Chunks(parts))
      .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    // The chunked path, not a fixed-length fallback: the response body below
    // is framed by arkham, not passed through.
    assert_eq!(response.headers().get("transfer-encoding").unwrap().to_str().unwrap(), "chunked");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(String::from_utf8(body.to_vec()).unwrap(), format!("download:{FAKE}"));
    drop(sender);
    let _ = client_task.await;
    tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
    proxy.abort();
  }

  /// Real h2 client and real h2 server through the MITM, needle split across
  /// DATA frames in both directions. h2 is a full HTTP/2 implementation: it
  /// judges the HPACK blocks arkham re-encodes and the frame framing it emits.
  #[tokio::test]
  async fn http2_real_client_and_server_round_trip_split_data() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let fx = mitm_fixture_h2(|port| localhost_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;

    let stub_task: tokio::task::JoinHandle<Result<(), String>> = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.map_err(|err| format!("accept: {err}"))?;
      let tls = stub_acceptor.accept(conn).await.map_err(|err| format!("tls: {err}"))?;
      let mut server = h2::server::handshake(tls).await.map_err(|err| format!("h2 handshake: {err}"))?;
      let Some(result) = server.accept().await else {
        return Err(String::from("no request"));
      };
      let (request, mut respond) = result.map_err(|err| format!("accept request: {err}"))?;
      let (parts, mut body) = request.into_parts();
      let mut received = Vec::new();
      while let Some(chunk) = body.data().await {
        match chunk {
          Ok(chunk) => received.extend_from_slice(&chunk),
          Err(err) => return Err(format!("body: {err}")),
        }
      }
      let auth = parts
        .headers
        .get("authorization")
        .map(|value| value.to_str().unwrap_or("?").to_string());
      let response = hyper::Response::builder().status(200).body(()).unwrap();
      let mut stream = respond.send_response(response, false).map_err(|err| format!("respond: {err}"))?;
      let reply = format!("download:{VALUE}");
      let (first, second) = reply.as_bytes().split_at(12);
      stream
        .send_data(Bytes::copy_from_slice(first), false)
        .map_err(|err| format!("send reply 1: {err}"))?;
      stream
        .send_data(Bytes::copy_from_slice(second), true)
        .map_err(|err| format!("send reply 2: {err}"))?;
      // h2 flushes writes by driving the connection, so give it a bounded turn
      // rather than relying on what a drop happens to do with the buffer.
      let _ = tokio::time::timeout(Duration::from_millis(300), server.accept()).await;
      if auth.as_deref() != Some(format!("Bearer {VALUE}").as_str()) {
        return Err(format!("authorization header is {auth:?}"));
      }
      if received != format!("upload:{VALUE}").as_bytes() {
        return Err(format!("request body is {:?}", String::from_utf8_lossy(&received)));
      }
      Ok(())
    });

    let tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let (mut sender, conn) = h2::client::handshake(tls).await.unwrap();
    let client_task = tokio::spawn(async move {
      let _ = conn.await;
    });
    let request = hyper::Request::builder()
      .method("POST")
      .uri("https://localhost/x")
      .header("authorization", format!("Bearer {FAKE}"))
      .body(())
      .unwrap();
    let (response, mut stream) = sender.send_request(request, false).unwrap();
    let upload = format!("upload:{FAKE}");
    let (first, second) = upload.as_bytes().split_at(12);
    stream.send_data(Bytes::copy_from_slice(first), false).unwrap();
    stream.send_data(Bytes::copy_from_slice(second), true).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(chunk) = body.data().await {
      received.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(String::from_utf8(received).unwrap(), format!("download:{FAKE}"));
    // The stub's report is the assertion that substitution reached the
    // upstream, so await it rather than ending the test on the client alone.
    let stub_result = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
    client_task.abort();
    stub_result.unwrap().unwrap().unwrap();
    proxy.abort();
  }

  /// Real Postgres client and real Postgres server through the MITM on the
  /// cleartext path. tokio-postgres judges the startup handshake arkham parses
  /// and the relay; pgwire serves it. The fake travels out in the statement
  /// and the real value travels back in the row, so both substitution
  /// directions are exercised end to end.
  #[tokio::test]
  #[expect(clippy::too_many_lines, reason = "linear test script, split would obscure the flow")]
  async fn postgres_real_client_and_server_round_trip() {
    use std::sync::Mutex;

    use futures::Sink;
    use futures::stream;
    use pgwire::api::query::SimpleQueryHandler;
    use pgwire::api::results::{DataRowEncoder, FieldFormat, FieldInfo, QueryResponse, Response};
    use pgwire::api::{ClientInfo, PgWireServerHandlers, Type};
    use pgwire::error::{PgWireError, PgWireResult};
    use pgwire::messages::PgWireBackendMessage;

    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";

    /// Answers every statement with one row carrying the real value, and
    /// records the statement it was handed.
    struct StubQueryHandler {
      seen: Arc<Mutex<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl SimpleQueryHandler for StubQueryHandler {
      async fn do_query<C>(&self, _client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
      where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: std::fmt::Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
      {
        *self.seen.lock().unwrap() = Some(query.to_string());
        let field = FieldInfo::new("token".into(), None, None, Type::VARCHAR, FieldFormat::Text);
        let schema = Arc::new(vec![field]);
        let mut encoder = DataRowEncoder::new(Arc::clone(&schema));
        encoder.encode_field(&VALUE.to_string())?;
        let row = encoder.take_row();
        Ok(vec![Response::Query(QueryResponse::new(schema, stream::iter(vec![Ok(row)])))])
      }
    }

    struct StubHandlers {
      query: Arc<StubQueryHandler>,
    }

    impl PgWireServerHandlers for StubHandlers {
      fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
        Arc::clone(&self.query)
      }
    }

    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let handler = Arc::new(StubQueryHandler { seen: Arc::clone(&seen) });
    let fx = mitm_fixture(|port| {
      vec![Grant::Postgres {
        credential: Credential {
          label: "pg".into(),
          fake: FAKE.into(),
          value: secrecy::SecretString::from(VALUE),
        },
        scope: Box::new(
          PostgresScope::from_strings(
            &format!("postgres://app:{FAKE}@localhost:{port}/main"),
            &format!("postgres://app:{VALUE}@localhost:{port}/main?sslmode=disable"),
          )
          .unwrap(),
        ),
      }]
    })
    .await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      ..
    } = fx;

    // Cleartext `sslmode=disable`: the stub speaks Postgres on the raw socket.
    let stub_task: tokio::task::JoinHandle<Result<(), String>> = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.map_err(|err| format!("accept: {err}"))?;
      pgwire::tokio::process_socket(conn, None, StubHandlers { query: handler })
        .await
        .map_err(|err| format!("pgwire server: {err}"))
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = [0u8; 19];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let config: tokio_postgres::Config = format!("host=localhost port={stub_port} user=stubuser dbname=stubdb sslmode=disable")
      .parse()
      .unwrap();
    let (client, connection) = config.connect_raw(stream, tokio_postgres::NoTls).await.unwrap();
    let conn_task = tokio::spawn(async move {
      let _ = connection.await;
    });
    let rows = client.simple_query(&format!("SELECT '{FAKE}'")).await.unwrap();
    let mut token = None;
    for message in rows {
      if let tokio_postgres::SimpleQueryMessage::Row(row) = message {
        token = row.get("token").map(str::to_string);
      }
    }
    assert_eq!(token.as_deref(), Some(FAKE), "response row must carry the fake");
    assert_eq!(
      seen.lock().unwrap().as_deref(),
      Some(format!("SELECT '{VALUE}'").as_str()),
      "upstream must receive the real value"
    );
    drop(client);
    conn_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
    proxy.abort();
  }

  /// Real Redis client and real Redis server through the MITM, on both
  /// transports the strings can state.
  mod redis_e2e {
    use std::sync::Mutex;

    use super::*;
    use secrecy::ExposeSecret as _;

    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn redis_grant(fake: &str, real: &str) -> Grant {
      let scope = RedisScope::from_strings(fake, real).unwrap();
      Grant::Redis {
        credential: Credential {
          label: "r".into(),
          fake: scope.downstream.password.expose_secret().to_string(),
          value: scope.upstream.password.clone(),
        },
        scope: Box::new(scope),
      }
    }

    fn auth_frame(password: &str) -> String {
      format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{password}\r\n", password.len())
    }

    /// Serve one redis connection: AUTH then PING, recording every byte.
    async fn serve_redis<S>(mut conn: S, seen: Arc<Mutex<Vec<u8>>>)
    where
      S: AsyncRead + AsyncWrite + Unpin,
    {
      let expected = auth_frame(VALUE);
      let mut buf = vec![0u8; expected.len()];
      conn.read_exact(&mut buf).await.unwrap();
      *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = buf.clone();
      assert_eq!(String::from_utf8_lossy(&buf), expected, "upstream must see the real, reframed AUTH");
      conn.write_all(b"+OK\r\n").await.unwrap();
      let mut ping = [0u8; 14];
      conn.read_exact(&mut ping).await.unwrap();
      assert_eq!(&ping, b"*1\r\n$4\r\nPING\r\n");
      conn.write_all(b"+PONG\r\n").await.unwrap();
    }

    async fn connect_through_proxy(proxy_addr: SocketAddr, stub_port: u16) -> TcpStream {
      let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
      stream
        .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
      let mut head = [0u8; 19];
      stream.read_exact(&mut head).await.unwrap();
      assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
      stream
    }

    #[tokio::test]
    async fn redis_auth_swaps_over_cleartext() {
      let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
      let fx = mitm_fixture(|port| {
        vec![redis_grant(
          &format!("redis://app:{FAKE}@localhost:{port}/0"),
          &format!("redis://app:{VALUE}@localhost:{port}/0"),
        )]
      })
      .await;
      let stub_seen = Arc::clone(&seen);
      let stub_task = tokio::spawn(async move {
        let (conn, _) = fx.stub.accept().await.unwrap();
        serve_redis(conn, stub_seen).await;
      });

      let mut stream = connect_through_proxy(fx.proxy_addr, fx.stub_port).await;
      stream.write_all(auth_frame(FAKE).as_bytes()).await.unwrap();
      let mut ok = [0u8; 5];
      stream.read_exact(&mut ok).await.unwrap();
      assert_eq!(&ok, b"+OK\r\n");
      stream.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
      let mut pong = [0u8; 7];
      stream.read_exact(&mut pong).await.unwrap();
      assert_eq!(&pong, b"+PONG\r\n");
      drop(stream);
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
      assert_eq!(
        String::from_utf8_lossy(&seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
        auth_frame(VALUE),
        "the stub recorded the reframed real AUTH"
      );
      fx.proxy.abort();
    }

    #[tokio::test]
    async fn redis_auth_swaps_over_tls_both_legs() {
      install_crypto_provider();
      let ca = CertAuthority::generate().unwrap();
      let stub_cert = ca.generate_domain_cert("localhost").unwrap();
      let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
      let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let stub_port = local_addr(&stub).port();
      // A rediss string verifies against its own anchor, never the platform
      // store: the bundle is the arkham CA, exactly what the stub presents.
      let bundle_dir = tempfile::tempdir().unwrap();
      let bundle = bundle_dir.path().join("ca.pem");
      std::fs::write(&bundle, ca.cert_pem()).unwrap();
      let grants = vec![redis_grant(
        &format!("rediss://app:{FAKE}@localhost:{stub_port}/0"),
        &format!("rediss://app:{VALUE}@localhost:{stub_port}/0?sslrootcert={}", bundle.display()),
      )];
      let state = test_state_with(grants, &ca);
      let (proxy_addr, proxy) = run_proxy_with(state).await;

      let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
      let stub_seen = Arc::clone(&seen);
      let stub_task = tokio::spawn(async move {
        let (conn, _) = stub.accept().await.unwrap();
        let tls = acceptor.accept(conn).await.unwrap();
        serve_redis(tls, stub_seen).await;
      });

      let stream = connect_through_proxy(proxy_addr, stub_port).await;
      let mut roots = rustls::RootCertStore::empty();
      roots.add(ca.cert_der().clone()).unwrap();
      let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
      let name = ServerName::try_from("localhost".to_string()).unwrap();
      let mut tls = TlsConnector::from(Arc::new(config)).connect(name, stream).await.unwrap();
      tls.write_all(auth_frame(FAKE).as_bytes()).await.unwrap();
      let mut ok = [0u8; 5];
      tls.read_exact(&mut ok).await.unwrap();
      assert_eq!(&ok, b"+OK\r\n");
      tls.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
      let mut pong = [0u8; 7];
      tls.read_exact(&mut pong).await.unwrap();
      assert_eq!(&pong, b"+PONG\r\n");
      drop(tls);
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
      assert_eq!(
        String::from_utf8_lossy(&seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
        auth_frame(VALUE)
      );
      proxy.abort();
    }

    #[tokio::test]
    async fn redis_tls_without_sni_mints_for_the_grant_host() {
      install_crypto_provider();
      let ca = CertAuthority::generate().unwrap();
      let stub_cert = ca.generate_domain_cert("localhost").unwrap();
      let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
      let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let stub_port = local_addr(&stub).port();
      let bundle_dir = tempfile::tempdir().unwrap();
      let bundle = bundle_dir.path().join("ca.pem");
      std::fs::write(&bundle, ca.cert_pem()).unwrap();
      let grants = vec![redis_grant(
        &format!("rediss://app:{FAKE}@localhost:{stub_port}/0"),
        &format!("rediss://app:{VALUE}@localhost:{stub_port}/0?sslrootcert={}", bundle.display()),
      )];
      let state = test_state_with(grants, &ca);
      let snapshot = state.snapshot();

      let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
      let stub_seen = Arc::clone(&seen);
      let stub_task = tokio::spawn(async move {
        let (conn, _) = stub.accept().await.unwrap();
        let tls = acceptor.accept(conn).await.unwrap();
        serve_redis(tls, stub_seen).await;
      });

      let (guest, client_end) = tokio::io::duplex(64 * 1024);
      let serve = tokio::spawn({
        let state = Arc::clone(&state);
        let snapshot = Arc::clone(&snapshot);
        async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
      });

      let mut roots = rustls::RootCertStore::empty();
      roots.add(ca.cert_der().clone()).unwrap();
      let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
      // The guest checks the grant host and sends no SNI, the same shape as
      // Bun's Redis client on the transparent path.
      config.enable_sni = false;
      let name = ServerName::try_from("localhost".to_string()).unwrap();
      let mut tls = tokio::time::timeout(Duration::from_secs(10), TlsConnector::from(Arc::new(config)).connect(name, client_end))
        .await
        .unwrap()
        .unwrap();
      tls.write_all(auth_frame(FAKE).as_bytes()).await.unwrap();
      let mut ok = [0u8; 5];
      tls.read_exact(&mut ok).await.unwrap();
      assert_eq!(&ok, b"+OK\r\n");
      tls.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
      let mut pong = [0u8; 7];
      tls.read_exact(&mut pong).await.unwrap();
      assert_eq!(&pong, b"+PONG\r\n");
      drop(tls);
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
      assert_eq!(
        String::from_utf8_lossy(&seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
        auth_frame(VALUE)
      );
      serve.await.unwrap().unwrap();
    }
  }
  /// Real TLS Postgres on both ends: a TLS-capable client against a TLS-capable
  /// server, for each handshake shape the entry URL and the guest can ask for.
  ///
  /// The entry's `sslmode` is the statement about the far side and the guest
  /// states its own transport, so the same proxy is exercised in all four
  /// combinations.
  mod pg_tls {
    use futures::Sink;
    use futures::stream;
    use pgwire::api::query::SimpleQueryHandler;
    use pgwire::api::results::{DataRowEncoder, FieldFormat, FieldInfo, QueryResponse, Response};
    use pgwire::api::{ClientInfo, PgWireServerHandlers, Type};
    use pgwire::error::{PgWireError, PgWireResult};
    use pgwire::messages::PgWireBackendMessage;
    use tokio::io::ReadBuf;
    use tokio_postgres::tls::MakeTlsConnect as _;

    use super::*;

    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";

    /// Answers every statement with one row carrying the real value, and
    /// records the statement it was handed.
    struct StubQueryHandler {
      seen: Arc<std::sync::Mutex<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl SimpleQueryHandler for StubQueryHandler {
      async fn do_query<C>(&self, _client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
      where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: std::fmt::Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
      {
        *self.seen.lock().unwrap() = Some(query.to_string());
        let field = FieldInfo::new("token".into(), None, None, Type::VARCHAR, FieldFormat::Text);
        let schema = Arc::new(vec![field]);
        let mut encoder = DataRowEncoder::new(Arc::clone(&schema));
        encoder.encode_field(&VALUE.to_string())?;
        let row = encoder.take_row();
        Ok(vec![Response::Query(QueryResponse::new(schema, stream::iter(vec![Ok(row)])))])
      }
    }

    struct StubHandlers {
      query: Arc<StubQueryHandler>,
    }

    impl PgWireServerHandlers for StubHandlers {
      fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
        Arc::clone(&self.query)
      }
    }

    /// Client-side TLS for a real Postgres client: rustls trusting the CA the
    /// proxy mints from, which is what a `sslmode=require` client needs once
    /// the server's certificate is ours.
    #[derive(Clone)]
    struct PgTls {
      connector: TlsConnector,
    }

    struct PgTlsStream(tokio_rustls::client::TlsStream<TcpStream>);

    impl tokio_postgres::tls::TlsStream for PgTlsStream {
      fn channel_binding(&self) -> tokio_postgres::tls::ChannelBinding {
        tokio_postgres::tls::ChannelBinding::none()
      }
    }

    impl AsyncRead for PgTlsStream {
      fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
      }
    }

    impl AsyncWrite for PgTlsStream {
      fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
      }

      fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
      }

      fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
      }
    }

    struct PgConnect {
      connector: TlsConnector,
      server_name: rustls::pki_types::ServerName<'static>,
    }

    impl tokio_postgres::tls::MakeTlsConnect<TcpStream> for PgTls {
      type Stream = PgTlsStream;
      type TlsConnect = PgConnect;
      type Error = std::io::Error;

      fn make_tls_connect(&mut self, domain: &str) -> Result<PgConnect, std::io::Error> {
        let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
          .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        Ok(PgConnect {
          connector: self.connector.clone(),
          server_name,
        })
      }
    }

    impl tokio_postgres::tls::TlsConnect<TcpStream> for PgConnect {
      type Stream = PgTlsStream;
      type Error = std::io::Error;
      type Future = Pin<Box<dyn Future<Output = Result<PgTlsStream, std::io::Error>> + Send>>;

      fn connect(self, stream: TcpStream) -> Self::Future {
        Box::pin(async move { Ok(PgTlsStream(self.connector.connect(self.server_name, stream).await?)) })
      }
    }

    /// Everything a Postgres handshake test needs: the proxy in front of a
    /// pgwire listener, the stub's TLS acceptor when the test wants a TLS
    /// server, and a client connector trusting the CA.
    struct PgStack {
      proxy_addr: SocketAddr,
      proxy: tokio::task::JoinHandle<()>,
      stub: Arc<TcpListener>,
      stub_port: u16,
      seen: Arc<std::sync::Mutex<Option<String>>>,
      acceptor: Option<TlsAcceptor>,
      connector: PgTls,
    }

    /// What the far side speaks, which the entry URL has to describe
    /// truthfully for the handshake to complete.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Stub {
      /// A server without TLS: it answers `N` to an `SSLRequest`.
      Cleartext,
      /// A TLS server reached the libpq way, with no ALPN to negotiate.
      Tls,
      /// A PostgreSQL 17 direct-TLS server: the handshake comes first, and the
      /// `postgresql` identifier is mandatory on both ends.
      Direct,
      /// A TLS server that admits no client without a certificate the arkham
      /// CA signed: only an entry-supplied identity gets through.
      TlsRequiresClientAuth,
    }

    /// Both legs of a postgres rule from its two strings, both dialing the
    /// stub, with the needles the pg fixtures swap.
    fn pg_scope(port: u16, query: &str) -> PostgresScope {
      PostgresScope::from_strings(
        &format!("postgres://app:{FAKE}@localhost:{port}/stubdb"),
        &format!("postgres://app:{VALUE}@localhost:{port}/stubdb?{query}"),
      )
      .unwrap()
    }

    /// Start the stack for one `sslmode`/`sslnegotiation` shape and one kind of
    /// server.
    async fn pg_stack(ca: &CertAuthority, query: &str, server: Stub) -> PgStack {
      pg_stack_scope(ca, move |port| pg_scope(port, query), server).await
    }

    /// [`pg_stack`] with the entry scope built by hand, for entries whose
    /// facts do not all fit in a URL.
    async fn pg_stack_scope(ca: &CertAuthority, make_scope: impl Fn(u16) -> PostgresScope, server: Stub) -> PgStack {
      install_crypto_provider();
      let stub_cert = ca.generate_domain_cert("localhost").unwrap();
      let acceptor = match server {
        Stub::Cleartext => None,
        Stub::TlsRequiresClientAuth => Some({
          let (chain, key) = arkham_pki::ca::generate_domain_pair(ca, "localhost").unwrap();
          let mut roots = rustls::RootCertStore::empty();
          roots.add(ca.cert_der().clone()).unwrap();
          let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
          let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .unwrap();
          TlsAcceptor::from(Arc::new(config))
        }),
        Stub::Tls | Stub::Direct => Some({
          let mut config = (*stub_cert.server_config).clone();
          config.alpn_protocols = if server == Stub::Direct {
            vec![b"postgresql".to_vec()]
          } else {
            Vec::new()
          };
          TlsAcceptor::from(Arc::new(config))
        }),
      };
      let stub = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
      let stub_port = local_addr(&stub).port();
      let grants = vec![Grant::Postgres {
        credential: Credential {
          label: "pg".into(),
          fake: FAKE.into(),
          value: secrecy::SecretString::from(VALUE),
        },
        scope: Box::new(make_scope(stub_port)),
      }];
      let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, ca)).await;
      let mut roots = rustls::RootCertStore::empty();
      roots.add(ca.cert_der().clone()).unwrap();
      let mut client_config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
      if server == Stub::Direct {
        // A direct-TLS client offers the same identifier the server requires.
        client_config.alpn_protocols = vec![b"postgresql".to_vec()];
      }
      let connector = PgTls {
        connector: TlsConnector::from(Arc::new(client_config)),
      };
      PgStack {
        proxy_addr,
        proxy,
        stub,
        stub_port,
        seen: Arc::new(std::sync::Mutex::new(None)),
        acceptor,
        connector,
      }
    }

    /// Serve one Postgres connection on the stub listener, TLS or not.
    fn serve_stub(stack: &PgStack) -> tokio::task::JoinHandle<Result<(), String>> {
      let query = Arc::new(StubQueryHandler {
        seen: Arc::clone(&stack.seen),
      });
      let acceptor = stack.acceptor.clone();
      let stub = Arc::clone(&stack.stub);
      tokio::spawn(async move {
        let (conn, _) = stub.accept().await.map_err(|err| format!("accept: {err}"))?;
        pgwire::tokio::process_socket(conn, acceptor, StubHandlers { query })
          .await
          .map_err(|err| format!("pgwire server: {err}"))
      })
    }

    /// Run one statement through the proxy as the real client, returning the
    /// row's token and the statement the server saw.
    async fn round_trip(stack: &PgStack, connect: &str) -> Result<(String, Option<String>), String> {
      round_trip_with(stack, connect, stack.connector.clone()).await
    }

    /// [`round_trip`] with the client's TLS connector replaced.
    async fn round_trip_with(stack: &PgStack, connect: &str, mut connector: PgTls) -> Result<(String, Option<String>), String> {
      let mut stream = TcpStream::connect(stack.proxy_addr)
        .await
        .map_err(|err| format!("proxy connect: {err}"))?;
      stream
        .write_all(format!("CONNECT localhost:{} HTTP/1.1\r\nHost: localhost\r\n\r\n", stack.stub_port).as_bytes())
        .await
        .map_err(|err| format!("CONNECT: {err}"))?;
      let mut head = [0u8; 19];
      stream.read_exact(&mut head).await.map_err(|err| format!("CONNECT head: {err}"))?;
      if &head != b"HTTP/1.1 200 OK\r\n\r\n" {
        return Err(format!("CONNECT reply: {}", String::from_utf8_lossy(&head)));
      }
      let config: tokio_postgres::Config = format!("host=localhost port={} user=stubuser dbname=stubdb {connect}", stack.stub_port)
        .parse()
        .map_err(|err| format!("config: {err}"))?;
      let tls = connector
        .make_tls_connect("localhost")
        .map_err(|err| format!("client tls: {err}"))?;
      let (client, connection) = config
        .connect_raw(stream, tls)
        .await
        .map_err(|err| format!("client connect: {err}"))?;
      let conn_task = tokio::spawn(async move {
        let _ = connection.await;
      });
      let rows = client
        .simple_query(&format!("SELECT '{FAKE}'"))
        .await
        .map_err(|err| format!("query: {err}"))?;
      let mut token = None;
      for message in rows {
        if let tokio_postgres::SimpleQueryMessage::Row(row) = message {
          token = row.get("token").map(ToString::to_string);
        }
      }
      conn_task.abort();
      let token = token.ok_or_else(|| "no row came back".to_string())?;
      let seen = stack.seen.lock().unwrap().clone();
      Ok((token, seen))
    }

    /// Assert one happy round trip: fake in, real upstream, fake back.
    async fn assert_round_trip(stack: &PgStack, connect: &str) {
      let stub_task = serve_stub(stack);
      let (token, seen) = round_trip(stack, connect).await.unwrap();
      assert_eq!(token, FAKE, "the row must carry the fake");
      assert_eq!(
        seen.as_deref(),
        Some(format!("SELECT '{VALUE}'").as_str()),
        "the server must see the real value"
      );
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
      stack.proxy.abort();
    }

    #[tokio::test]
    async fn postgres_tls_classic_negotiation_round_trip() {
      // libpq's SSLRequest, on a TLS server: the shape every client uses.
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=require", Stub::Tls).await;
      assert_round_trip(&stack, "sslmode=require").await;
    }

    /// The entry's `sslcert`/`sslkey` pair is the proxy's identity to the
    /// server: this stub admits no one without a client certificate the
    /// arkham CA signed, so the round trip only completes when the upstream
    /// leg presents the entry's.
    #[tokio::test]
    async fn postgres_entry_presents_its_client_identity_to_the_server() {
      use rama::crypto::pem::PemEncode as _;
      let ca = CertAuthority::generate().unwrap();
      let dir = tempfile::tempdir().unwrap();
      let (chain, key) = arkham_pki::ca::generate_client_pair(&ca, "arkham-client").unwrap();
      let mut cert_pem = Vec::new();
      for cert in &chain {
        cert_pem.extend_from_slice(cert.to_pem().as_bytes());
      }
      let cert_path = dir.path().join("client.pem");
      let key_path = dir.path().join("client.key");
      std::fs::write(&cert_path, &cert_pem).unwrap();
      std::fs::write(&key_path, key.to_pem()).unwrap();
      let query = format!("sslmode=require&sslcert={}&sslkey={}", cert_path.display(), key_path.display());
      let stack = pg_stack(&ca, &query, Stub::TlsRequiresClientAuth).await;
      assert_round_trip(&stack, "sslmode=require").await;
    }

    /// `sslrootcert=system` names the platform trust store, not the arkham
    /// CA: a verify-full entry holds the self-signed stub against it and
    /// the session cannot complete, proving the store was loaded and enforced.
    #[tokio::test]
    async fn postgres_verify_full_system_store_rejects_the_stub() {
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=verify-full&sslrootcert=system", Stub::Tls).await;
      let stub_task = serve_stub(&stack);
      round_trip(&stack, "sslmode=require").await.unwrap_err();
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
      stack.proxy.abort();
    }

    /// A silent upstream — TCP accepted, `SSLRequest` never answered — must
    /// close the leg inside the entry-configured budget instead of holding
    /// the connection forever.
    #[tokio::test]
    async fn postgres_silent_upstream_closes_within_the_budget() {
      let ca = CertAuthority::generate().unwrap();
      let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let stub_port = stub.local_addr().unwrap().port();
      tokio::spawn(async move {
        let (_stream, _) = stub.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
      });
      let grants = vec![Grant::Postgres {
        credential: Credential {
          label: "pg".into(),
          fake: FAKE.into(),
          value: secrecy::SecretString::from(VALUE),
        },
        scope: Box::new(pg_scope(stub_port, "sslmode=require")),
      }];
      let state = test_state_with_budget(grants, Vec::new(), &ca, 1);
      let (proxy_addr, _proxy) = run_proxy_with(state).await;

      let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
      guest
        .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
      let mut head = [0u8; 19];
      guest.read_exact(&mut head).await.unwrap();
      assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
      // A cleartext guest greeting settles the guest leg; the arm then asks
      // the silent upstream for TLS and must hit the 1s budget.
      guest.write_all(&[0u8; 8]).await.unwrap();
      let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut buf = [0u8; 1];
        guest.read(&mut buf).await
      })
      .await
      .expect("the budget must close the leg");
      assert_eq!(result.unwrap(), 0, "the guest must see EOF, not silence");
    }

    /// `guest_tls_mode = "mtls"` on a postgres entry: arkham asks the guest
    /// for a client certificate and admits only ones its own CA signs. A
    /// client with a arkham-CA-signed identity gets through; one without is
    /// refused by the guest handshake itself.
    #[tokio::test]
    async fn postgres_guest_mtls_admits_only_ca_signed_guests() {
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack_scope(
        &ca,
        |port| PostgresScope {
          downstream: PostgresLeg {
            host: "localhost".to_string(),
            port,
            user: Some("app".to_string()),
            password: secrecy::SecretString::from(FAKE),
            database: None,
          },
          upstream: PostgresLeg {
            host: "localhost".to_string(),
            port,
            user: Some("app".to_string()),
            password: secrecy::SecretString::from(VALUE),
            database: None,
          },
          ssl: SslMode::Prefer,
          negotiation: SslNegotiation::Postgres,
          root_cert: None,
          client_cert: None,
          client_key: None,
          guest_tls: GuestTlsMode::Mtls,
        },
        Stub::Tls,
      )
      .await;

      // Present a arkham-CA-signed identity: the session completes.
      let stub_task = serve_stub(&stack);
      let (chain, key) = arkham_pki::ca::generate_client_pair(&ca, "guest").unwrap();
      let mut roots = rustls::RootCertStore::empty();
      roots.add(ca.cert_der().clone()).unwrap();
      let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap();
      let connector = PgTls {
        connector: TlsConnector::from(Arc::new(client_config)),
      };
      let (token, seen) = round_trip_with(&stack, "sslmode=require", connector).await.unwrap();
      assert_eq!(token, FAKE, "the row must carry the fake");
      assert_eq!(seen.as_deref(), Some(format!("SELECT '{VALUE}'").as_str()));
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;

      // No client identity: arkham's own handshake refuses the guest.
      let stub_task = serve_stub(&stack);
      round_trip(&stack, "sslmode=require").await.unwrap_err();
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
      stack.proxy.abort();
    }

    /// `sslmode=allow` with a cleartext guest: the upstream leg stays
    /// cleartext — the greeting relays on with no `SSLRequest` in front of it.
    #[tokio::test]
    async fn postgres_allow_with_a_cleartext_guest_never_asks_upstream_for_tls() {
      let ca = CertAuthority::generate().unwrap();
      let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let spy_port = spy.local_addr().unwrap().port();
      let seen = tokio::spawn(async move {
        let (mut stream, _) = spy.accept().await.unwrap();
        let mut buf = [0u8; 8];
        let _ = stream.read_exact(&mut buf).await;
        buf
      });
      let grants = vec![Grant::Postgres {
        credential: Credential {
          label: "pg".into(),
          fake: FAKE.into(),
          value: secrecy::SecretString::from(VALUE),
        },
        scope: Box::new(pg_scope(spy_port, "sslmode=allow")),
      }];
      let state = test_state_with_budget(grants, Vec::new(), &ca, 10);
      let (proxy_addr, _proxy) = run_proxy_with(state).await;

      let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
      guest
        .write_all(format!("CONNECT localhost:{spy_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
      let mut head = [0u8; 19];
      guest.read_exact(&mut head).await.unwrap();
      assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
      // A real cleartext startup: length 23, protocol 3.0, user stubuser.
      let mut startup = Vec::new();
      startup.extend(23u32.to_be_bytes());
      startup.extend(196_608u32.to_be_bytes());
      startup.extend(b"user\0stubuser\0\0");
      guest.write_all(&startup).await.unwrap();
      let upstream_first8 = seen.await.unwrap();
      assert_ne!(
        &upstream_first8[4..8],
        &pgwire::messages::startup::SslRequest::BODY_MAGIC_NUMBER.to_be_bytes(),
        "allow with a cleartext guest must not ask the server for TLS"
      );
    }

    /// `sslmode=allow` with a guest that asked for TLS: the upstream leg
    /// escalates too — the first bytes upstream are the `SSLRequest`.
    #[tokio::test]
    async fn postgres_allow_with_a_tls_guest_escalates_upstream_to_tls() {
      let ca = CertAuthority::generate().unwrap();
      let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let spy_port = spy.local_addr().unwrap().port();
      let seen = tokio::spawn(async move {
        let (mut stream, _) = spy.accept().await.unwrap();
        let mut buf = [0u8; 8];
        let _ = stream.read_exact(&mut buf).await;
        buf
      });
      let grants = vec![Grant::Postgres {
        credential: Credential {
          label: "pg".into(),
          fake: FAKE.into(),
          value: secrecy::SecretString::from(VALUE),
        },
        scope: Box::new(pg_scope(spy_port, "sslmode=allow")),
      }];
      let state = test_state_with_budget(grants, Vec::new(), &ca, 10);
      let (proxy_addr, _proxy) = run_proxy_with(state).await;

      let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
      guest
        .write_all(format!("CONNECT localhost:{spy_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
      let mut head = [0u8; 19];
      guest.read_exact(&mut head).await.unwrap();
      assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
      // libpq's escalation shape: SSLRequest, one 'S' answer, then TLS.
      let mut request = Vec::new();
      request.extend(8u32.to_be_bytes());
      request.extend(pgwire::messages::startup::SslRequest::BODY_MAGIC_NUMBER.to_be_bytes());
      guest.write_all(&request).await.unwrap();
      let mut answer = [0u8; 1];
      guest.read_exact(&mut answer).await.unwrap();
      assert_eq!(answer[0], b'S');
      let mut roots = rustls::RootCertStore::empty();
      roots.add(ca.cert_der().clone()).unwrap();
      let connector = TlsConnector::from(guest_client_config(roots, Alpn::None));
      let result = connector
        .connect(rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), guest)
        .await;
      // The spy never answers its SSLRequest, so the arm fails closed — but
      // the escalation ask is already on record.
      assert!(result.is_err(), "the silent upstream must close the leg");
      let upstream_first8 = seen.await.unwrap();
      assert_eq!(
        &upstream_first8[4..8],
        &pgwire::messages::startup::SslRequest::BODY_MAGIC_NUMBER.to_be_bytes(),
        "allow with a TLS guest must ask the server for TLS"
      );
    }

    #[tokio::test]
    async fn postgres_tls_direct_negotiation_round_trip() {
      // PostgreSQL 17 direct TLS: no SSLRequest, `postgresql` in ALPN.
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=require&sslnegotiation=direct", Stub::Direct).await;
      assert_round_trip(&stack, "sslmode=require sslnegotiation=direct").await;
    }

    #[tokio::test]
    async fn postgres_prefer_uses_tls_when_the_server_offers_it() {
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=prefer", Stub::Tls).await;
      assert_round_trip(&stack, "sslmode=prefer").await;
    }

    #[tokio::test]
    async fn postgres_prefer_falls_back_when_the_server_refuses_tls() {
      // The other half of `prefer`: a server that answers `N` still gets the
      // session, which is what makes the mode usable against cleartext servers.
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=prefer", Stub::Cleartext).await;
      assert_round_trip(&stack, "sslmode=prefer").await;
    }

    #[tokio::test]
    async fn postgres_verify_full_round_trip_against_the_entry_anchor() {
      let ca = CertAuthority::generate().unwrap();
      let dir = tempfile::tempdir().unwrap();
      let anchor = dir.path().join("root.pem");
      std::fs::write(&anchor, ca.cert_pem()).unwrap();
      let stack = pg_stack(&ca, &format!("sslmode=verify-full&sslrootcert={}", anchor.display()), Stub::Tls).await;
      // The client states its own policy; this one has no `verify-full` of its
      // own, and it is the entry that asks the proxy to verify.
      assert_round_trip(&stack, "sslmode=require").await;
    }

    #[tokio::test]
    async fn postgres_tls_client_on_a_cleartext_entry_still_reaches_the_server() {
      // The entry says the far side is cleartext; the guest asks for TLS
      // anyway, and a real server would have answered `S` too.
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=disable", Stub::Cleartext).await;
      assert_round_trip(&stack, "sslmode=require").await;
    }

    #[tokio::test]
    async fn postgres_cleartext_client_on_a_tls_entry_still_reaches_the_server() {
      // The entry says the far side needs TLS; the guest opens cleartext.
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=require", Stub::Tls).await;
      assert_round_trip(&stack, "sslmode=disable").await;
    }

    #[tokio::test]
    async fn postgres_require_closes_when_the_server_refuses_tls() {
      // A cleartext-only server under an entry that requires TLS: no session,
      // and no statement — and no credential — reaches the server.
      let ca = CertAuthority::generate().unwrap();
      let stack = pg_stack(&ca, "sslmode=require", Stub::Cleartext).await;
      let stub_task = serve_stub(&stack);
      assert!(
        round_trip(&stack, "sslmode=require").await.is_err(),
        "a refused TLS leg cannot carry a session"
      );
      assert_eq!(stack.seen.lock().unwrap().as_deref(), None, "no statement may reach the server");
      let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
      stack.proxy.abort();
    }
  }
}
