//! SMTP AUTH through the MITM: PLAIN before and after STARTTLS, and
//! implicit TLS with no SNI. The peer is scripted; the compose demo
//! drives a real server and a real client.

use std::sync::Mutex;

use super::*;
use base64::Engine as _;
use secrecy::ExposeSecret as _;

const FAKE: &str = "fake-smtp-pass"; // betterleaks:allow
const VALUE: &str = "real-smtp-pass"; // betterleaks:allow
const USER: &str = "agent@demo.test";

fn smtp_grant(fake: &str, real: &str) -> Grant {
  let scope = arkham_config::grants::SmtpScope::from_strings(fake, real).unwrap();
  Grant::Smtp {
    credential: Credential {
      label: "smtp".into(),
      fake: scope.downstream.password.expose_secret().to_string(),
      value: scope.upstream.password.clone(),
    },
    scope: Box::new(scope),
  }
}

fn plain_initial(user: &str, pass: &str) -> String {
  base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"))
}

fn auth_line(user: &str, pass: &str) -> String {
  format!("AUTH PLAIN {}\r\n", plain_initial(user, pass))
}

async fn read_reply<S>(stream: &mut S) -> String
where
  S: AsyncRead + Unpin,
{
  let mut all = Vec::new();
  let mut buf = [0u8; 1];
  let mut line = Vec::new();
  loop {
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 1, "smtp reply ended early");
    line.push(buf[0]);
    if buf[0] != b'\n' {
      continue;
    }
    let finished = line.get(3) != Some(&b'-');
    all.extend_from_slice(&line);
    line.clear();
    if finished {
      break;
    }
  }
  String::from_utf8(all).unwrap()
}

async fn write_cmd<S>(stream: &mut S, line: &str)
where
  S: AsyncWrite + Unpin,
{
  stream.write_all(line.as_bytes()).await.unwrap();
  stream.flush().await.unwrap();
}

/// One scripted submission server. `starttls` upgrades after the
/// command and records every AUTH line, cleartext then TLS.
async fn serve_submission<S>(mut conn: S, acceptor: Option<TlsAcceptor>, seen: Arc<Mutex<Vec<String>>>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  write_cmd(&mut conn, "220 mail.demo.test ESMTP\r\n").await;
  loop {
    let line = read_reply(&mut conn).await;
    if line.to_ascii_uppercase().starts_with("EHLO") || line.to_ascii_uppercase().starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250 AUTH PLAIN LOGIN\r\n").await;
      continue;
    }
    if line.to_ascii_uppercase().starts_with("STARTTLS") {
      write_cmd(&mut conn, "220 2.0.0 Ready to start TLS\r\n").await;
      let Some(acceptor) = acceptor else {
        return;
      };
      let tls = acceptor.accept(conn).await.unwrap();
      serve_authed(tls, seen).await;
      return;
    }
    if line.to_ascii_uppercase().starts_with("AUTH ") {
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
      write_cmd(&mut conn, "235 2.7.0 Authentication successful\r\n").await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

async fn serve_authed<S>(mut conn: S, seen: Arc<Mutex<Vec<String>>>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  loop {
    let line = read_reply(&mut conn).await;
    if line.to_ascii_uppercase().starts_with("EHLO") || line.to_ascii_uppercase().starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250 AUTH PLAIN LOGIN\r\n").await;
      continue;
    }
    if line.to_ascii_uppercase().starts_with("AUTH ") {
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
      // Before STARTTLS the proxy must have forwarded the decoy, and the
      // server refuses it. After the upgrade the real password is the
      // only one that authenticates. The caller decides which reply by
      // how many AUTH lines it has already seen: the first is the
      // pre-upgrade refusal when this function is the post-upgrade half.
      write_cmd(&mut conn, "235 2.7.0 Authentication successful\r\n").await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

/// Submission dialogue that refuses AUTH until STARTTLS, recording both
/// AUTH lines so the test can see the decoy and then the real password.
/// `refuse_once` answers the first STARTTLS with `454` and the next with
/// `220`. `HELP`, `VRFY`, and `EXPN` stay in the cleartext loop.
async fn serve_starttls<S>(mut conn: S, acceptor: TlsAcceptor, seen: Arc<Mutex<Vec<String>>>, mut refuse_once: bool)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  write_cmd(&mut conn, "220 mail.demo.test ESMTP\r\n").await;
  loop {
    let line = read_reply(&mut conn).await;
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("EHLO") || upper.starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n").await;
      continue;
    }
    if upper.starts_with("HELP") || upper.starts_with("VRFY") || upper.starts_with("EXPN") {
      write_cmd(&mut conn, "250 2.0.0 ok\r\n").await;
      continue;
    }
    if upper.starts_with("AUTH ") {
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
      write_cmd(&mut conn, "530 5.7.0 Must issue a STARTTLS command first\r\n").await;
      continue;
    }
    if upper.starts_with("STARTTLS") {
      if refuse_once {
        refuse_once = false;
        write_cmd(&mut conn, "454 4.7.0 TLS temporarily unavailable\r\n").await;
        continue;
      }
      write_cmd(&mut conn, "220 2.0.0 Ready to start TLS\r\n").await;
      let tls = acceptor.accept(conn).await.unwrap();
      serve_authed(tls, seen).await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

#[tokio::test]
async fn smtp_auth_before_starttls_stays_the_decoy_and_swaps_after() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
  let fx = mitm_fixture_no_alpn(|port| {
    vec![smtp_grant(
      &format!("smtp://agent%40demo.test:{FAKE}@localhost:{port}"),
      &format!(
        "smtp://agent%40demo.test:{VALUE}@localhost:{port}?starttls=required&sslrootcert={}",
        bundle.display()
      ),
    )]
  })
  .await;
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_starttls(conn, acceptor, stub_seen, false).await;
  });

  let mut stream = {
    let mut stream = TcpStream::connect(fx.proxy_addr).await.unwrap();
    stream
      .write_all(format!("CONNECT localhost:{} HTTP/1.1\r\nHost: localhost\r\n\r\n", fx.stub_port).as_bytes())
      .await
      .unwrap();
    let mut head = [0u8; 19];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    stream
  };
  let greeting = read_reply(&mut stream).await;
  assert!(greeting.starts_with("220"), "{greeting}");
  write_cmd(&mut stream, "EHLO client\r\n").await;
  let ehlo = read_reply(&mut stream).await;
  assert!(ehlo.contains("250"), "{ehlo}");
  write_cmd(&mut stream, &auth_line(USER, FAKE)).await;
  let refused = read_reply(&mut stream).await;
  assert!(refused.starts_with("530"), "{refused}");
  assert!(!refused.contains(VALUE), "{refused}");
  write_cmd(&mut stream, "STARTTLS\r\n").await;
  let ready = read_reply(&mut stream).await;
  assert!(ready.starts_with("220"), "{ready}");

  // The guest trusts the proxy CA. The stub's CA is a different one, named
  // by sslrootcert, and is what the proxy checks on the upstream leg.
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = fx.connector.connect(name, stream).await.unwrap();
  write_cmd(&mut tls, "EHLO client\r\n").await;
  let ehlo = read_reply(&mut tls).await;
  assert!(ehlo.contains("250"), "{ehlo}");
  write_cmd(&mut tls, &auth_line(USER, FAKE)).await;
  let ok = read_reply(&mut tls).await;
  assert!(ok.starts_with("235"), "{ok}");
  assert!(!ok.contains(VALUE), "{ok}");
  drop(tls);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded.len(), 2, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, FAKE)),
    "pre-upgrade AUTH must carry the decoy: {}",
    recorded[0]
  );
  assert!(
    !recorded[0].contains(&plain_initial(USER, VALUE)),
    "pre-upgrade AUTH must not carry the real password"
  );
  assert!(
    recorded[1].contains(&plain_initial(USER, VALUE)),
    "post-upgrade AUTH must carry the real password: {}",
    recorded[1]
  );
  assert!(!recorded[1].contains(&plain_initial(USER, FAKE)));
  fx.proxy.abort();
}

/// `HELP` is an opening command. `STARTTLS` after it still upgrades, and
/// the AUTH that follows carries the real password.
#[tokio::test]
async fn help_then_starttls_still_swaps_auth() {
  let (fx, bundle, acceptor, seen) = starttls_fixture().await;
  let stub_seen = Arc::clone(&seen);
  let proxy_addr = fx.proxy_addr;
  let stub_port = fx.stub_port;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_starttls(conn, acceptor, stub_seen, false).await;
  });
  let mut stream = tunnel(proxy_addr, stub_port).await;
  let greeting = read_reply(&mut stream).await;
  assert!(greeting.starts_with("220"), "{greeting}");
  write_cmd(&mut stream, "EHLO client\r\n").await;
  let _ = read_reply(&mut stream).await;
  for line in ["HELP\r\n", "VRFY agent@demo.test\r\n", "EXPN list\r\n"] {
    write_cmd(&mut stream, line).await;
    let reply = read_reply(&mut stream).await;
    assert!(reply.starts_with("250"), "{line} {reply}");
  }
  upgrade_and_auth(&fx.connector, &fx.proxy, stream, &seen, stub_task).await;
  let _ = bundle;
}

/// A `454` leaves the session in the opening. The next `STARTTLS` upgrades.
#[tokio::test]
async fn refused_starttls_then_retry_still_swaps_auth() {
  let (fx, bundle, acceptor, seen) = starttls_fixture().await;
  let stub_seen = Arc::clone(&seen);
  let proxy_addr = fx.proxy_addr;
  let stub_port = fx.stub_port;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_starttls(conn, acceptor, stub_seen, true).await;
  });
  let mut stream = tunnel(proxy_addr, stub_port).await;
  let greeting = read_reply(&mut stream).await;
  assert!(greeting.starts_with("220"), "{greeting}");
  write_cmd(&mut stream, "EHLO client\r\n").await;
  let _ = read_reply(&mut stream).await;
  write_cmd(&mut stream, "STARTTLS\r\n").await;
  let refused = read_reply(&mut stream).await;
  assert!(refused.starts_with("454"), "{refused}");
  upgrade_and_auth(&fx.connector, &fx.proxy, stream, &seen, stub_task).await;
  let _ = bundle;
}

async fn starttls_fixture() -> (MitmFixture, tempfile::TempDir, TlsAcceptor, Arc<Mutex<Vec<String>>>) {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let bundle_display = bundle.display().to_string();
  let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
  let fx = mitm_fixture_no_alpn(move |port| {
    vec![smtp_grant(
      &format!("smtp://agent%40demo.test:{FAKE}@localhost:{port}"),
      &format!("smtp://agent%40demo.test:{VALUE}@localhost:{port}?starttls=required&sslrootcert={bundle_display}"),
    )]
  })
  .await;
  (fx, bundle_dir, acceptor, seen)
}

async fn tunnel(proxy_addr: SocketAddr, stub_port: u16) -> TcpStream {
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

async fn upgrade_and_auth(
  connector: &TlsConnector,
  proxy: &tokio::task::JoinHandle<()>,
  mut stream: TcpStream,
  seen: &Mutex<Vec<String>>,
  stub_task: tokio::task::JoinHandle<()>,
) {
  write_cmd(&mut stream, "STARTTLS\r\n").await;
  let ready = read_reply(&mut stream).await;
  assert!(ready.starts_with("220"), "{ready}");
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = connector.connect(name, stream).await.unwrap();
  write_cmd(&mut tls, "EHLO client\r\n").await;
  let ehlo = read_reply(&mut tls).await;
  assert!(ehlo.contains("250"), "{ehlo}");
  write_cmd(&mut tls, &auth_line(USER, FAKE)).await;
  let ok = read_reply(&mut tls).await;
  assert!(ok.starts_with("235"), "{ok}");
  assert!(!ok.contains(VALUE), "{ok}");
  drop(tls);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded.len(), 1, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, VALUE)),
    "post-upgrade AUTH must carry the real password: {}",
    recorded[0]
  );
  proxy.abort();
}

/// Server that advertises CHUNKING and accepts `BDAT` chunks. Records
/// each payload so the test can see the octets pass without a deadlock.
async fn serve_bdat<S>(mut conn: S, seen: Arc<Mutex<Vec<Vec<u8>>>>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  write_cmd(&mut conn, "220 mail.demo.test ESMTP\r\n").await;
  loop {
    let line = read_reply(&mut conn).await;
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("EHLO") || upper.starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250-PIPELINING\r\n250 CHUNKING\r\n").await;
      continue;
    }
    if upper.starts_with("BDAT") {
      let Some(n) = bdat_size(line.as_bytes()) else {
        write_cmd(&mut conn, "501 5.5.4 missing chunk size\r\n").await;
        continue;
      };
      let mut payload = vec![0u8; n];
      if n > 0 {
        conn.read_exact(&mut payload).await.unwrap();
      }
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(payload);
      write_cmd(&mut conn, "250 2.0.0 chunk accepted\r\n").await;
      continue;
    }
    if upper.starts_with("QUIT") {
      write_cmd(&mut conn, "221 bye\r\n").await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

fn bdat_size(line: &[u8]) -> Option<usize> {
  let body = line.strip_suffix(b"\r\n").unwrap_or(line);
  let mut parts = body.split(|byte| *byte == b' ' || *byte == b'\t').filter(|part| !part.is_empty());
  let verb = parts.next()?;
  if !verb.eq_ignore_ascii_case(b"BDAT") {
    return None;
  }
  let size = std::str::from_utf8(parts.next()?).ok()?;
  size.parse().ok()
}

#[tokio::test]
async fn bdat_payload_is_passed_exactly() {
  let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
  let fx = mitm_fixture(|port| {
    vec![smtp_grant(
      &format!("smtp://agent%40demo.test:{FAKE}@localhost:{port}"),
      &format!("smtp://agent%40demo.test:{VALUE}@localhost:{port}"),
    )]
  })
  .await;
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_bdat(conn, stub_seen).await;
  });

  let result = tokio::time::timeout(Duration::from_secs(5), async {
    let mut stream = TcpStream::connect(fx.proxy_addr).await.unwrap();
    stream
      .write_all(format!("CONNECT localhost:{} HTTP/1.1\r\nHost: localhost\r\n\r\n", fx.stub_port).as_bytes())
      .await
      .unwrap();
    let mut head = [0u8; 19];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let greeting = read_reply(&mut stream).await;
    assert!(greeting.starts_with("220"), "{greeting}");
    write_cmd(&mut stream, "EHLO client\r\n").await;
    let ehlo = read_reply(&mut stream).await;
    assert_eq!(ehlo, "250-mail.demo.test\r\n250-PIPELINING\r\n250 CHUNKING\r\n");
    write_cmd(&mut stream, "BDAT 5\r\n").await;
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let accepted = read_reply(&mut stream).await;
    assert!(accepted.starts_with("250"), "{accepted}");
    write_cmd(&mut stream, "BDAT 0 LAST\r\n").await;
    let last = read_reply(&mut stream).await;
    assert!(last.starts_with("250"), "{last}");
    write_cmd(&mut stream, "BDAT\r\n").await;
    let missing = read_reply(&mut stream).await;
    assert!(missing.starts_with("501"), "{missing}");
    write_cmd(&mut stream, "QUIT\r\n").await;
  })
  .await;
  fx.proxy.abort();
  result.expect("BDAT splice timed out");
  let _ = tokio::time::timeout(Duration::from_secs(2), stub_task).await;
  let recorded = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded, vec![b"hello".to_vec(), Vec::new()]);
}

/// A session that never upgrades stays cleartext upstream. The decoy
/// is what the server records; the real password is not on that wire.
#[tokio::test]
async fn smtp_cleartext_session_forwards_the_decoy() {
  let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
  let fx = mitm_fixture(|port| {
    vec![smtp_grant(
      &format!("smtp://agent%40demo.test:{FAKE}@localhost:{port}"),
      &format!("smtp://agent%40demo.test:{VALUE}@localhost:{port}"),
    )]
  })
  .await;
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_submission(conn, None, stub_seen).await;
  });

  let mut stream = TcpStream::connect(fx.proxy_addr).await.unwrap();
  stream
    .write_all(format!("CONNECT localhost:{} HTTP/1.1\r\nHost: localhost\r\n\r\n", fx.stub_port).as_bytes())
    .await
    .unwrap();
  let mut head = [0u8; 19];
  stream.read_exact(&mut head).await.unwrap();
  assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
  let greeting = read_reply(&mut stream).await;
  assert!(greeting.starts_with("220"), "{greeting}");
  write_cmd(&mut stream, "EHLO client\r\n").await;
  let _ = read_reply(&mut stream).await;
  write_cmd(&mut stream, &auth_line(USER, FAKE)).await;
  let ok = read_reply(&mut stream).await;
  assert!(ok.starts_with("235"), "{ok}");
  assert!(!ok.contains(VALUE), "{ok}");
  drop(stream);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded.len(), 1, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, FAKE)),
    "cleartext AUTH must carry the decoy: {}",
    recorded[0]
  );
  assert!(
    !recorded[0].contains(&plain_initial(USER, VALUE)),
    "cleartext AUTH must not carry the real password"
  );
  fx.proxy.abort();
}

#[tokio::test]
async fn smtps_without_sni_mints_for_the_grant_host() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let grants = vec![smtp_grant(
    &format!("smtps://agent%40demo.test:{FAKE}@localhost:{stub_port}"),
    &format!(
      "smtps://agent%40demo.test:{VALUE}@localhost:{stub_port}?sslrootcert={}",
      bundle.display()
    ),
  )];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();
  let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let tls = acceptor.accept(conn).await.unwrap();
    serve_submission(tls, None, stub_seen).await;
  });

  let (guest, client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
  });

  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  config.enable_sni = false;
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = tokio::time::timeout(
    Duration::from_secs(10),
    TlsConnector::from(Arc::new(config)).connect(name, client_end),
  )
  .await
  .unwrap()
  .unwrap();
  let greeting = read_reply(&mut tls).await;
  assert!(greeting.starts_with("220"), "{greeting}");
  write_cmd(&mut tls, "EHLO client\r\n").await;
  let _ = read_reply(&mut tls).await;
  write_cmd(&mut tls, &auth_line(USER, FAKE)).await;
  let ok = read_reply(&mut tls).await;
  assert!(ok.starts_with("235"), "{ok}");
  assert!(!ok.contains(VALUE), "{ok}");
  drop(tls);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert!(recorded[0].contains(&plain_initial(USER, VALUE)), "{recorded:?}");
  serve.await.unwrap().unwrap();
}
