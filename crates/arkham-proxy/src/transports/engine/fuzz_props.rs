//! Property and fuzz tests: adversarial byte streams through the
//! substitution machines (HTTP and SMTP), the SNI parser, and grant parsing.
//!
//! Two families:
//! - **Invariants** (valid framing, adversarial splits): a token split
//!   across any arrival boundary must recombine and substitute whole;
//!   fixed-length bodies must not drift; chunked output must re-parse.
//! - **Crash resistance** (arbitrary bytes): no input, arrival split, or
//!   pipelining combination may panic or hang.
//!
//! Tests are sync: async machine entry points run on a current-thread
//! tokio runtime via `block_on` (no timers, no IO — the machines are
//! deterministic over the byte input alone).
use proptest::prelude::*;

use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use arkham_config::grants::{Credential, Grant, GuestTlsMode, Scheme, SmtpLeg, SmtpScope};
use base64::Engine as _;
use secrecy::SecretString;

use crate::transports::smtp::{GuestLeg, MAX_COMMAND, Smtp, acceptance_reply, plain_guest};

use super::{Direction, Http, Raw, Rewritten, Wire};
use crate::transports::http::h2::{H2, H2_PREFACE};

/// Needle decoy (request-direction needle) and its real value.
const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn grants() -> Vec<Grant> {
  vec![Grant::Token {
    credential: Credential {
      label: "github".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
    },
    allow: vec!["https://*".parse().expect("grant")],
    pattern: None,
    oauth2: None,
  }]
}

fn req_machine() -> Http {
  Http::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream, None, None)
}

fn resp_machine() -> Http {
  Http::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Upstream, None, None)
}

fn h2_req_machine() -> H2 {
  H2::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream, None, None)
}

fn h2_resp_machine() -> H2 {
  H2::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Upstream, None, None)
}

impl Rewritten<'_> {
  fn emit_bytes(self) -> Vec<u8> {
    match self {
      Self::Emit(bytes) => bytes.into_owned(),
      _ => Vec::new(),
    }
  }
}

fn block_on<F>(fut: F) -> F::Output
where
  F: std::future::Future,
{
  thread_local! {
    static RT: tokio::runtime::Runtime =
      tokio::runtime::Builder::new_current_thread().build().expect("test runtime");
  }
  RT.with(|rt| rt.block_on(fut))
}

/// Drain a machine over `splits` (ascending cuts into `data`, implied
/// final cut at `data.len()`), then one empty EOF flush. Concatenated
/// output, total hit count.
fn run_split<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize) {
  let (out, hits, _) = run_split_parts(m, data, splits);
  (out, hits)
}

/// [`run_split`] plus whether any feed returned [`Rewritten::Close`].
fn run_split_parts<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize, bool) {
  let mut out = Vec::new();
  let mut hits = 0;
  let mut prev = 0;
  let mut closed = false;
  for &cut in splits.iter().chain(std::iter::once(&data.len())) {
    // A relay only calls with non-empty chunks; an empty call is the
    // EOF flush. Skip cuts that would produce an interior empty call.
    if cut > prev {
      let (rewritten, chunk_hits) = block_on(m.feed(&data[prev..cut]));
      closed |= matches!(rewritten, Rewritten::Close);
      out.extend_from_slice(&rewritten.emit_bytes());
      hits += chunk_hits.len();
      prev = cut;
    }
  }
  if prev < data.len() {
    let (rewritten, chunk_hits) = block_on(m.feed(&data[prev..]));
    closed |= matches!(rewritten, Rewritten::Close);
    out.extend_from_slice(&rewritten.emit_bytes());
    hits += chunk_hits.len();
  }
  let (rewritten, chunk_hits) = block_on(m.feed(&[]));
  closed |= matches!(rewritten, Rewritten::Close);
  out.extend_from_slice(&rewritten.emit_bytes());
  hits += chunk_hits.len();
  (out, hits, closed)
}

/// Drain an H2 machine the same way.
fn run_split_h2<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize) {
  run_split(m, data, splits)
}

/// One request head + fixed body with the needle spliced into `payload` at
/// `at`; body length is exact.
fn fixed_message(payload: &[u8], at: usize) -> Vec<u8> {
  let mut body = Vec::with_capacity(payload.len() + FAKE.len());
  body.extend_from_slice(&payload[..at]);
  body.extend_from_slice(FAKE.as_bytes());
  body.extend_from_slice(&payload[at..]);
  let head = format!("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", body.len());
  let mut out = head.into_bytes();
  out.extend_from_slice(&body);
  out
}

/// Chunked-encode `body` in `chunk`-sized pieces.
fn chunked_encode(body: &[u8], chunk: usize) -> Vec<u8> {
  let mut msg = Vec::new();
  let mut off = 0;
  while off < body.len() {
    let take = chunk.min(body.len() - off);
    msg.extend_from_slice(format!("{take:X}\r\n").as_bytes());
    msg.extend_from_slice(&body[off..off + take]);
    msg.extend_from_slice(b"\r\n");
    off += take;
  }
  msg.extend_from_slice(b"0\r\n\r\n");
  msg
}

/// Decode a chunked body (payload bytes only) from `msg[head_end..]`.
fn chunked_decode(msg: &[u8], head_end: usize) -> Option<Vec<u8>> {
  let mut got = Vec::new();
  let mut pos = head_end;
  loop {
    let rel = msg[pos..].windows(2).position(|w| w == b"\r\n")? + pos;
    let size_str = String::from_utf8_lossy(&msg[pos..rel]);
    let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16).ok()?;
    pos = rel + 2;
    if size == 0 {
      return Some(got);
    }
    if msg.len() < pos + size + 2 {
      return None;
    }
    got.extend_from_slice(&msg[pos..pos + size]);
    pos += size + 2;
  }
}

/// H2 request preface + static-encoded HEADERS frame opening stream 1.
/// Indexed static-table fields only: :method POST (3), :path / (4).
fn h2_request_head() -> Vec<u8> {
  let block: &[u8] = &[0x83, 0x84];
  let mut out = H2_PREFACE.to_vec();
  append_h2_frame(&mut out, 0x1, 0x4, 1, block);
  out
}

/// H2 response HEADERS frame: indexed :status 200 (8) on stream 1.
fn h2_response_head() -> Vec<u8> {
  let mut out = Vec::new();
  append_h2_frame(&mut out, 0x1, 0x4, 1, &[0x88]);
  out
}

/// Append one H2 frame.
fn append_h2_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
  let len = u32::try_from(payload.len()).expect("frame length fits u32");
  out.extend_from_slice(&len.to_be_bytes()[1..4]);
  out.push(kind);
  out.push(flags);
  out.extend_from_slice(&stream.to_be_bytes());
  out.extend_from_slice(payload);
}

fn collect_h2_data(out: &[u8]) -> Vec<u8> {
  let mut got = Vec::new();
  // Request-direction output starts with the echoed connection preface.
  let mut pos = if out.starts_with(H2_PREFACE) { H2_PREFACE.len() } else { 0 };
  while out.len() - pos >= 9 {
    let len = ((out[pos] as usize) << 16) | ((out[pos + 1] as usize) << 8) | out[pos + 2] as usize;
    if out.len() - pos < 9 + len {
      break;
    }
    if out[pos + 3] == 0x0 {
      got.extend_from_slice(&out[pos + 9..pos + 9 + len]);
    }
    pos += 9 + len;
  }
  got
}

fn h1_head_end(msg: &[u8]) -> usize {
  msg.windows(4).position(|w| w == b"\r\n\r\n").expect("head boundary") + 4
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// Raw TCP: a needle split across any two arrivals recombines and
  /// substitutes whole; the fake never survives on the wire.
  #[test]
  fn prop_raw_split_token_substitutes_whole(
    pre in proptest::collection::vec(any::<u8>(), 0..64),
    suffix in proptest::collection::vec(any::<u8>(), 0..64),
  ) {
    let grants = vec![Grant::Token {

      credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
      },
      allow: vec!["tcp://*:1".parse().expect("grant")],
      pattern: None,
      oauth2: None,
    }];
    let mut m = Raw::new(&grants, Scheme::Tcp, "h", 1, Direction::Downstream);
    let mid = FAKE.len() / 2;
    let mut data = pre.clone();
    data.extend_from_slice(&FAKE.as_bytes()[..mid]);
    let mut splits = vec![data.len()];
    data.extend_from_slice(&FAKE.as_bytes()[mid..]);
    data.extend_from_slice(&suffix);
    splits.push(data.len());

    let (out, _) = run_split(&mut m, &data, &splits);
    prop_assert!(out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "token lost");
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake survived");
  }

  /// H1 fixed body: any split of the arrivals yields exactly the
  /// substituted body — same total length (framing preserved), token
  /// whole, fake gone.
  #[test]
  fn prop_h1_fixed_split_invariant(
    payload in proptest::collection::vec(0u8..0x80, 0..64),
    at in 0usize..64,
    cuts in proptest::collection::vec(0usize..160, 0..4),
  ) {
    let data = fixed_message(&payload, at.min(payload.len()));
    let head_len = h1_head_end(&data);
    let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(data.len())).collect();
    cuts.sort_unstable();
    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &data, &cuts);
    prop_assert!(!m.must_close(), "equal-length swap must not fail closed");
    prop_assert_eq!(out.len(), data.len(), "fixed framing must not drift");
    prop_assert_eq!(&out[head_len..], [ &payload[..at.min(payload.len())], VALUE.as_bytes(), &payload[at.min(payload.len())..] ].concat());
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake leaked");
  }

  /// H1 chunked: any chunking of a needle-bearing body, fed through any
  /// arrival split, decodes back to exactly the substituted payload.
  #[test]
  fn prop_h1_chunked_roundtrip(
    payload in proptest::collection::vec(0u8..0x80, 0..256),
    at in 0usize..256,
    chunk in 1usize..64,
    cut in 0usize..600,
  ) {
    let mut body = Vec::with_capacity(payload.len() + FAKE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(FAKE.as_bytes());
    body.extend_from_slice(&payload[at..]);
    let want: Vec<u8> = [&payload[..at], VALUE.as_bytes(), &payload[at..]].concat();
    let mut msg = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    msg.extend_from_slice(&chunked_encode(&body, chunk));
    let head_end = h1_head_end(&msg);

    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close(), "equal-length swap must not fail closed");
    let got = chunked_decode(&out, head_end).expect("valid chunked framing");
    prop_assert_eq!(got, want, "case: payload={:?} at={} chunk={} cut={}", payload, at, chunk, cut);
    prop_assert!(out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "token lost: case: payload={:?} at={} chunk={} cut={}", payload, at, chunk, cut);
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake leaked: case: payload={:?} at={} chunk={} cut={}", payload, at, chunk, cut);
  }

  /// H1 pipelining: two complete messages in one arrival (or split at any
  /// cut) both substitute — the spill loop must re-enter Head state
  /// cleanly, never drop or duplicate the boundary bytes.
  #[test]
  fn prop_h1_pipelined_messages_substitute(
    fill_a in proptest::collection::vec(0u8..0x80, 0..48),
    fill_b in proptest::collection::vec(0u8..0x80, 0..48),
    cut in 0usize..600,
  ) {
    let a_body = [fill_a.as_slice(), FAKE.as_bytes()].concat();
    let b_body = [FAKE.as_bytes(), fill_b.as_slice()].concat();
    let mut msg = format!("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", a_body.len()).into_bytes();
    msg.extend_from_slice(&a_body);
    msg.extend_from_slice(format!("POST /b HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", b_body.len()).as_bytes());
    msg.extend_from_slice(&b_body);

    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close());
    prop_assert_eq!(out.len(), msg.len(), "pipelined framing must not drift");
    prop_assert_eq!(out.windows(FAKE.len()).filter(|w| *w == FAKE.as_bytes()).count(), 0, "fake leaked");
    // Both bodies substituted: two distinct VALUE occurrences on the wire.
    prop_assert_eq!(out.windows(VALUE.len()).filter(|w| *w == VALUE.as_bytes()).count(), 2, "case: fill_a={:?} fill_b={:?} cut={}", fill_a, fill_b, cut);
  }

  /// H1 chunked with chunk extensions: legal framing the parser must
  /// accept (size line split on `;`) while re-chunking without them.
  #[test]
  fn prop_h1_chunked_extensions_roundtrip(
    payload in proptest::collection::vec(0u8..0x80, 0..128),
    at in 0usize..128,
    cut in 0usize..400,
  ) {
    let at = at.min(payload.len());
    let body: Vec<u8> = [&payload[..at], FAKE.as_bytes(), &payload[at..]].concat();
    let want: Vec<u8> = [&payload[..at], VALUE.as_bytes(), &payload[at..]].concat();
    let mut msg = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let mut off = 0;
    while off < body.len() {
      let take = 7.min(body.len() - off);
      msg.extend_from_slice(format!("{take:X};q=1\r\n").as_bytes());
      msg.extend_from_slice(&body[off..off + take]);
      msg.extend_from_slice(b"\r\n");
      off += take;
    }
    msg.extend_from_slice(b"0\r\n\r\n");
    let head_end = h1_head_end(&msg);

    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close());
    let got = chunked_decode(&out, head_end).expect("valid chunked framing");
    prop_assert_eq!(got, want, "case: payload={:?} at={} cut={}", payload, at, cut);
  }

  /// H1 close-delimited response: any split still redacts the whole
  /// needle at EOF.
  #[test]
  fn prop_h1_close_delimited_redacts_at_eof(
    payload in proptest::collection::vec(0u8..0x80, 0..64),
    at in 0usize..64,
    cut in 0usize..160,
  ) {
    let mut body = Vec::with_capacity(payload.len() + VALUE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(VALUE.as_bytes());
    body.extend_from_slice(&payload[at..]);
    let mut msg = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n".to_vec();
    msg.extend_from_slice(&body);
    let head_end = h1_head_end(&msg);

    let mut m = resp_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close(), "redaction is equal-length; close is for scan-only leaks");
    prop_assert_eq!(&out[head_end..], [ &payload[..at], FAKE.as_bytes(), &payload[at..] ].concat());
    prop_assert!(!out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "real value leaked");
  }

  /// H2: needle-bearing body split across DATA frames at any frame size,
  /// fed through any arrival split — concatenated DATA payloads equal
  /// the substituted body, no needle sliced or leaked.
  #[test]
  fn prop_h2_data_split_invariant(
    payload in proptest::collection::vec(0u8..0x80, 0..256),
    at in 0usize..256,
    frame_len in 1usize..128,
    cuts in proptest::collection::vec(0usize..1200, 0..4),
  ) {
    let mut body = Vec::with_capacity(payload.len() + FAKE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(FAKE.as_bytes());
    body.extend_from_slice(&payload[at..]);
    let want: Vec<u8> = [&payload[..at], VALUE.as_bytes(), &payload[at..]].concat();

    let mut msg = h2_request_head();
    let mut off = 0;
    loop {
      let take = frame_len.min(body.len().saturating_sub(off));
      let last = off + take >= body.len();
      let flags = u8::from(last);
      append_h2_frame(&mut msg, 0x0, flags, 1, &body[off..off + take]);
      off += take;
      if last {
        break;
      }
    }
    let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(msg.len())).collect();
    cuts.sort_unstable();

    let mut m = h2_req_machine();
    let (out, _) = run_split_h2(&mut m, &msg, &cuts);
    let got = collect_h2_data(&out);
    prop_assert_eq!(got, want, "case: payload={:?} at={} frame_len={} cuts={:?}", payload, at, frame_len, cuts);
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake leaked: case: payload={:?} at={} frame_len={} cuts={:?}", payload, at, frame_len, cuts);
  }

  /// H2 response leg: redaction holds for frames arriving whole or split.
  #[test]
  fn prop_h2_response_redacts_across_splits(
    payload in proptest::collection::vec(0u8..0x80, 0..128),
    at in 0usize..128,
    frame_len in 1usize..64,
    cut in 0usize..600,
  ) {
    let mut body = Vec::with_capacity(payload.len() + VALUE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(VALUE.as_bytes());
    body.extend_from_slice(&payload[at..]);

    let mut msg = h2_response_head();
    let mut off = 0;
    loop {
      let take = frame_len.min(body.len().saturating_sub(off));
      let last = off + take >= body.len();
      let flags = u8::from(last);
      append_h2_frame(&mut msg, 0x0, flags, 1, &body[off..off + take]);
      off += take;
      if last {
        break;
      }
    }

    let mut m = h2_resp_machine();
    let (out, _) = run_split_h2(&mut m, &msg, &[cut.min(msg.len())]);
    let got = collect_h2_data(&out);
    let want: Vec<u8> = [&payload[..at], FAKE.as_bytes(), &payload[at..]].concat();
    prop_assert_eq!(got, want, "DATA payloads must equal the redacted body");
    prop_assert!(!out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "real value leaked");
  }

  /// Crash resistance, H1: arbitrary bytes on either leg through any
  /// single split — no panic, EOF flush terminates.
  #[test]
  fn prop_h1_arbitrary_no_panic(
    data in proptest::collection::vec(any::<u8>(), 0..1024),
    cut in 0usize..1024,
    dir in 0u8..2,
  ) {
    let mut m = if dir == 0 { req_machine() } else { resp_machine() };
    let _ = run_split(&mut m, &data, &[cut.min(data.len())]);
    let _ = m.must_close();
  }

  /// Crash resistance, H2: arbitrary bytes on either leg — preface
  /// mismatch degrades opaque, framing garbage never panics.
  #[test]
  fn prop_h2_arbitrary_no_panic(
    data in proptest::collection::vec(any::<u8>(), 0..1024),
    cut in 0usize..1024,
    dir in 0u8..2,
  ) {
    let mut m = if dir == 0 { h2_req_machine() } else { h2_resp_machine() };
    let _ = run_split_h2(&mut m, &data, &[cut.min(data.len())]);
    let _ = m.must_close();
  }

  /// Crash resistance, SNI: arbitrary bytes never panic the ClientHello
  /// walker.
  #[test]
  fn prop_sni_arbitrary_no_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
    let _ = crate::identity::hello_sni(&data);
  }

  /// Crash resistance, grants: arbitrary strings parse or reject
  /// cleanly, and a valid entry round-trips through matching.
  #[test]
  fn prop_grant_parse_no_panic(s in ".*") {
    if let Ok(scope) = s.parse::<arkham_config::grants::EndpointScope>() {
      let host = match &scope.host {
        arkham_config::grants::HostPat::Any => "anything.example".to_string(),
        arkham_config::grants::HostPat::Wildcard(pattern) => {
          let suffix = pattern.strip_prefix("*.").unwrap_or(pattern);
          format!("sub.{suffix}")
        }
        arkham_config::grants::HostPat::Exact(host) => host.clone(),
      };
      assert!(
        arkham_config::grants::uri_match(
          std::slice::from_ref(&scope),
          scope.scheme,
          &host,
          scope.port,
        ),
        "entry `{s}` must match the host its own pattern derives"
      );
    }
  }
}

const SMTP_FAKE_USER: &str = "guest@demo.test";
const SMTP_REAL_USER: &str = "owner@demo.test";

#[derive(Clone, Copy, Debug)]
enum SmtpMech {
  Plain,
  Login,
  Xoauth2,
  Bearer,
}

enum SmtpStep {
  Down(Vec<u8>),
  Up(Vec<u8>),
}

struct SmtpSession {
  steps: Vec<SmtpStep>,
  real: String,
  fake: String,
  /// Bytes the swapped AUTH must place on the upstream wire.
  swapped: Vec<u8>,
  /// AUTH line planted in the DATA body. It must pass unchanged.
  body_line: Vec<u8>,
  bdat: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Arrival<'a> {
  Whole,
  Cuts(&'a [usize]),
  Bytes,
}

fn smtp_b64(raw: &[u8]) -> String {
  base64::engine::general_purpose::STANDARD.encode(raw)
}

fn smtp_plain_token(user: &str, pass: &str) -> String {
  smtp_b64(format!("\0{user}\0{pass}").as_bytes())
}

fn smtp_xoauth_token(user: &str, pass: &str) -> String {
  smtp_b64(format!("user={user}\u{1}auth=Bearer {pass}\u{1}\u{1}").as_bytes())
}

fn smtp_bearer_token(user: &str, pass: &str) -> String {
  smtp_b64(format!("n,a={user},\u{1}host=mail\u{1}auth=Bearer {pass}\u{1}\u{1}").as_bytes())
}

fn smtp_line(text: &str) -> Vec<u8> {
  let mut out = text.as_bytes().to_vec();
  out.extend_from_slice(b"\r\n");
  out
}

fn smtp_grants(fake_pass: &str, real_pass: &str) -> Vec<Grant> {
  let scope = SmtpScope {
    downstream: SmtpLeg {
      host: "mail".into(),
      port: 587,
      user: SMTP_FAKE_USER.into(),
      password: SecretString::from(fake_pass),
    },
    is_downstream_tls: false,
    upstream: SmtpLeg {
      host: "mail".into(),
      port: 587,
      user: SMTP_REAL_USER.into(),
      password: SecretString::from(real_pass),
    },
    is_upstream_tls: false,
    starttls_required: true,
    root_cert: None,
    client_cert: None,
    client_key: None,
    guest_tls: GuestTlsMode::default(),
  };
  vec![Grant::Smtp {
    credential: Credential {
      label: "smtp".into(),
      fake: fake_pass.into(),
      value: SecretString::from(real_pass),
    },
    scope: Box::new(scope),
  }]
}

fn smtp_machines(fake_pass: &str, real_pass: &str) -> (Smtp, Smtp) {
  let grants = smtp_grants(fake_pass, real_pass);
  let mut down = Smtp::new(&grants, "mail", 587, Direction::Downstream);
  down.set_protected(true);
  let mut up = Smtp::new(&grants, "mail", 587, Direction::Upstream);
  Smtp::share_data_gate(&down, &mut up);
  (down, up)
}

fn smtp_count(hay: &[u8], needle: &[u8]) -> usize {
  if needle.is_empty() || hay.len() < needle.len() {
    return 0;
  }
  hay.windows(needle.len()).filter(|window| *window == needle).count()
}

fn smtp_contains(hay: &[u8], needle: &[u8]) -> bool {
  smtp_count(hay, needle) > 0
}

/// `q…` is the decoy and `z…` is the real password, so neither collides with SMTP verbs.
fn smtp_tagged(prefix: char, chars: &[char]) -> String {
  let mut out = String::with_capacity(chars.len().saturating_add(1));
  out.push(prefix);
  for ch in chars {
    out.push(*ch);
  }
  out
}

fn smtp_session(
  mech: SmtpMech,
  inline: bool,
  fake_chars: &[char],
  real_chars: &[char],
  body_len: usize,
  bdat_len: usize,
  multiline_354: bool,
) -> SmtpSession {
  let fake = smtp_tagged('q', fake_chars);
  let real = smtp_tagged('z', real_chars);
  let mut steps = Vec::new();
  steps.push(SmtpStep::Down(smtp_line("EHLO mail.example")));
  steps.push(SmtpStep::Up(smtp_line(&format!("250-{real}"))));
  steps.push(SmtpStep::Up(smtp_line("250 mail")));
  let swapped = smtp_auth_steps(&mut steps, mech, inline, &fake, &real);
  steps.push(SmtpStep::Up(smtp_line(&format!("535 5.7.8 {real}"))));
  steps.push(SmtpStep::Down(smtp_line("DATA")));
  if multiline_354 {
    steps.push(SmtpStep::Up(smtp_line("354-go")));
  }
  steps.push(SmtpStep::Up(smtp_line("354 go")));
  let body_line = smtp_line(&format!("AUTH PLAIN {}", smtp_plain_token(SMTP_FAKE_USER, &fake)));
  let mut body = vec![b'n'; body_len];
  body.extend_from_slice(&body_line);
  body.extend_from_slice(b".\r\n");
  steps.push(SmtpStep::Down(body));
  steps.push(SmtpStep::Up(smtp_line("250 queued")));
  let bdat = vec![0x7f; bdat_len];
  let mut bdat_step = smtp_line(&format!("BDAT {bdat_len}"));
  bdat_step.extend_from_slice(&bdat);
  bdat_step.extend_from_slice(&smtp_line("NOOP"));
  steps.push(SmtpStep::Down(bdat_step));
  SmtpSession {
    steps,
    real,
    fake,
    swapped,
    body_line,
    bdat,
  }
}

fn smtp_auth_steps(steps: &mut Vec<SmtpStep>, mech: SmtpMech, inline: bool, fake: &str, real: &str) -> Vec<u8> {
  let user_b64 = smtp_b64(SMTP_FAKE_USER.as_bytes());
  let pass_b64 = smtp_b64(fake.as_bytes());
  let real_user_b64 = smtp_b64(SMTP_REAL_USER.as_bytes());
  let real_pass_b64 = smtp_b64(real.as_bytes());
  match (mech, inline) {
    (SmtpMech::Plain, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!(
        "AUTH PLAIN {}",
        smtp_plain_token(SMTP_FAKE_USER, fake)
      ))));
      smtp_plain_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Plain, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH PLAIN")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&smtp_plain_token(SMTP_FAKE_USER, fake))));
      smtp_plain_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Login, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!("AUTH LOGIN {user_b64}"))));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&pass_b64)));
      format!("{real_user_b64}\r\n{real_pass_b64}").into_bytes()
    }
    (SmtpMech::Login, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH LOGIN")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&user_b64)));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&pass_b64)));
      format!("{real_user_b64}\r\n{real_pass_b64}").into_bytes()
    }
    (SmtpMech::Xoauth2, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!(
        "AUTH XOAUTH2 {}",
        smtp_xoauth_token(SMTP_FAKE_USER, fake)
      ))));
      smtp_xoauth_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Xoauth2, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH XOAUTH2")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&smtp_xoauth_token(SMTP_FAKE_USER, fake))));
      smtp_xoauth_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Bearer, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!(
        "AUTH OAUTHBEARER {}",
        smtp_bearer_token(SMTP_FAKE_USER, fake)
      ))));
      smtp_bearer_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Bearer, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH OAUTHBEARER")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&smtp_bearer_token(SMTP_FAKE_USER, fake))));
      smtp_bearer_token(SMTP_REAL_USER, real).into_bytes()
    }
  }
}

struct SmtpEmitted {
  down: Vec<u8>,
  up: Vec<u8>,
  closed: bool,
}

fn drive_smtp(session: &SmtpSession, arrival: Arrival<'_>) -> SmtpEmitted {
  let (mut down, mut up) = smtp_machines(&session.fake, &session.real);
  let mut emitted = SmtpEmitted {
    down: Vec::new(),
    up: Vec::new(),
    closed: false,
  };
  for step in &session.steps {
    let data = match step {
      SmtpStep::Down(bytes) | SmtpStep::Up(bytes) => bytes.as_slice(),
    };
    let splits = smtp_splits(data, arrival);
    let (bytes, _, closed) = match step {
      SmtpStep::Down(_) => run_split_parts(&mut down, data, &splits),
      SmtpStep::Up(_) => run_split_parts(&mut up, data, &splits),
    };
    match step {
      SmtpStep::Down(_) => emitted.down.extend_from_slice(&bytes),
      SmtpStep::Up(_) => emitted.up.extend_from_slice(&bytes),
    }
    emitted.closed |= closed;
    if emitted.closed {
      break;
    }
  }
  emitted
}

fn smtp_splits(data: &[u8], arrival: Arrival<'_>) -> Vec<usize> {
  match arrival {
    Arrival::Whole => Vec::new(),
    Arrival::Cuts(cuts) => {
      let mut points: Vec<usize> = cuts.iter().copied().filter(|cut| *cut > 0 && *cut < data.len()).collect();
      points.sort_unstable();
      points.dedup();
      points
    }
    Arrival::Bytes => (1..data.len()).collect(),
  }
}

fn smtp_first_diff(left: &[u8], right: &[u8]) -> Option<usize> {
  let shared = left.len().min(right.len());
  left
    .get(..shared)
    .unwrap_or(&[])
    .iter()
    .zip(right.get(..shared).unwrap_or(&[]))
    .position(|(lhs, rhs)| lhs != rhs)
    .or_else(|| (left.len() != right.len()).then_some(shared))
}

/// Greeting bytes and the index where `pass` starts.
/// `at` is an offset in the final line. `MAX_COMMAND - 4` places the
/// password after a command-sized prefix.
fn smtp_greeting(continuations: u8, at: usize, pass: &str) -> (Vec<u8>, usize) {
  let mut out = Vec::new();
  for _ in 0..continuations {
    out.extend_from_slice(b"220-wait\r\n");
  }
  let mut line = b"220 ".to_vec();
  if line.len() < at {
    line.resize(at, b'x');
  }
  let pass_at = out.len().saturating_add(line.len());
  line.extend_from_slice(pass.as_bytes());
  line.extend_from_slice(b"\r\n");
  out.extend_from_slice(&line);
  (out, pass_at)
}

struct SmtpOpening {
  code: Option<[u8; 3]>,
  guest: Vec<u8>,
  rest: Vec<u8>,
}

/// One reply stream. Each poll yields bytes up to the next cut, then
/// pends once before the following poll. The waker is woken so
/// `block_on` resumes.
struct CutPend {
  data: Vec<u8>,
  cuts: Vec<usize>,
  at: usize,
  reads: usize,
  pends: usize,
  arm_pend: bool,
}

impl CutPend {
  fn new(data: Vec<u8>, cuts: &[usize]) -> Self {
    let mut cuts: Vec<usize> = cuts.iter().copied().filter(|cut| *cut > 0 && *cut < data.len()).collect();
    cuts.sort_unstable();
    cuts.dedup();
    Self {
      data,
      cuts,
      at: 0,
      reads: 0,
      pends: 0,
      arm_pend: false,
    }
  }
}

impl AsyncRead for CutPend {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    if self.arm_pend {
      self.arm_pend = false;
      self.pends = self.pends.saturating_add(1);
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    if buf.remaining() == 0 {
      return Poll::Ready(Ok(()));
    }
    let Some(rest) = self.data.get(self.at..) else {
      return Poll::Ready(Ok(()));
    };
    if rest.is_empty() {
      return Poll::Ready(Ok(()));
    }
    let end = self.cuts.iter().copied().find(|cut| *cut > self.at).unwrap_or(self.data.len());
    let n = end.saturating_sub(self.at).min(buf.remaining());
    if n == 0 {
      return Poll::Ready(Err(std::io::Error::other("reply cut produced an empty read")));
    }
    let Some(chunk) = rest.get(..n) else {
      return Poll::Ready(Ok(()));
    };
    buf.put_slice(chunk);
    self.at = self.at.saturating_add(n);
    self.reads = self.reads.saturating_add(1);
    self.arm_pend = self.at < self.data.len();
    Poll::Ready(Ok(()))
  }
}

fn smtp_read_opening(up: &mut Smtp, reader: &mut CutPend, lead: &[u8]) -> Result<SmtpOpening, crate::Error> {
  block_on(async {
    let mut guest = plain_guest(Cursor::new(Vec::new()));
    let done = acceptance_reply(reader, up, &mut guest, lead).await?;
    let guest = match guest {
      GuestLeg::Plain(cursor) => cursor.into_inner(),
      GuestLeg::Tls(_) => Vec::new(),
    };
    Ok(SmtpOpening {
      code: done.code,
      guest,
      rest: done.rest,
    })
  })
}

fn smtp_feed_reply(fake: &str, real: &str, greet: &[u8], arrival: Arrival<'_>) -> (Vec<u8>, bool) {
  let grants = smtp_grants(fake, real);
  let mut up = Smtp::new(&grants, "mail", 587, Direction::Upstream);
  let splits = smtp_splits(greet, arrival);
  let (out, _, closed) = run_split_parts(&mut up, greet, &splits);
  (out, closed)
}

fn smtp_distinct(fake: &[char], real: &[char]) -> bool {
  let fake = smtp_tagged('q', fake);
  let real = smtp_tagged('z', real);
  fake != real && !fake.contains(real.as_str()) && !real.contains(fake.as_str())
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// AUTH, a multiline reply, DATA, and BDAT survive every arrival split
  /// from [`run_split`]. The real password is absent from guest-bound bytes.
  /// It may be shorter or longer than the decoy.
  #[test]
  fn prop_session_chunks_match_and_hide_the_real_password(
    mech in prop_oneof![Just(SmtpMech::Plain), Just(SmtpMech::Login), Just(SmtpMech::Xoauth2), Just(SmtpMech::Bearer)],
    inline in any::<bool>(),
    fake_chars in proptest::collection::vec(prop::char::range('a', 'z'), 6..12),
    real_chars in prop_oneof![
      proptest::collection::vec(prop::char::range('a', 'z'), 3..6),
      proptest::collection::vec(prop::char::range('a', 'z'), 16..28),
    ],
    body_len in 0usize..12,
    bdat_len in 0usize..12,
    multiline_354 in any::<bool>(),
    cuts in proptest::collection::vec(0usize..480, 0..5),
  ) {
    prop_assume!(smtp_distinct(&fake_chars, &real_chars));
    let session = smtp_session(mech, inline, &fake_chars, &real_chars, body_len, bdat_len, multiline_354);
    let whole = drive_smtp(&session, Arrival::Whole);
    let split = drive_smtp(&session, Arrival::Cuts(&cuts));
    let bytes = drive_smtp(&session, Arrival::Bytes);
    prop_assert!(!whole.closed && !split.closed && !bytes.closed, "a generated session closed the machine");
    prop_assert_eq!(smtp_first_diff(&whole.down, &split.down), None, "downstream split diverged, lens {} {}", whole.down.len(), split.down.len());
    prop_assert_eq!(smtp_first_diff(&whole.up, &split.up), None, "upstream split diverged, lens {} {}", whole.up.len(), split.up.len());
    prop_assert_eq!(smtp_first_diff(&whole.down, &bytes.down), None, "downstream bytes diverged, lens {} {}", whole.down.len(), bytes.down.len());
    prop_assert_eq!(smtp_first_diff(&whole.up, &bytes.up), None, "upstream bytes diverged, lens {} {}", whole.up.len(), bytes.up.len());
    let real = session.real.as_bytes();
    let fake = session.fake.as_bytes();
    prop_assert!(!whole.up.windows(real.len()).any(|window| window == real), "real password reached the guest");
    prop_assert!(!split.up.windows(real.len()).any(|window| window == real), "real password reached the guest on a split");
    prop_assert!(!bytes.up.windows(real.len()).any(|window| window == real), "real password reached the guest one byte at a time");
    prop_assert_eq!(smtp_count(&whole.up, fake), 2, "both reply copies of the password should become the decoy");
    prop_assert!(smtp_contains(&whole.down, &session.swapped), "AUTH did not swap onto the upstream wire");
    prop_assert!(smtp_contains(&whole.down, &session.body_line), "DATA body was rewritten");
    prop_assert!(session.bdat.is_empty() || smtp_contains(&whole.down, &session.bdat), "BDAT octets were dropped");
  }
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// A reply cut at any offset is still one opening reply. The reader
  /// splits at those cuts and pends between them. Bytes after the final
  /// newline are the next read.
  #[test]
  fn prop_reply_cut_keeps_the_opening_in_sync(
    fake_chars in proptest::collection::vec(prop::char::range('a', 'z'), 6..10),
    real_chars in prop_oneof![
      proptest::collection::vec(prop::char::range('a', 'z'), 3..6),
      proptest::collection::vec(prop::char::range('a', 'z'), 16..24),
    ],
    continuations in 0u8..3,
    small_pad in 0usize..24,
    straddling in any::<bool>(),
    cuts in proptest::collection::vec(0usize..20_000, 0..4),
  ) {
    prop_assume!(smtp_distinct(&fake_chars, &real_chars));
    let fake = smtp_tagged('q', &fake_chars);
    let real = smtp_tagged('z', &real_chars);
    let at = if straddling { MAX_COMMAND.saturating_sub(4) } else { 4usize.saturating_add(small_pad) };
    let (greet, pass_at) = smtp_greeting(continuations, at, &real);
    let line_cut = pass_at.saturating_sub(at).saturating_add(MAX_COMMAND);
    prop_assume!(pass_at < greet.len());
    let mut cuts = cuts;
    cuts.push(line_cut);
    cuts.push(pass_at);
    cuts.push(pass_at.saturating_add(1));

    let (whole, whole_closed) = smtp_feed_reply(&fake, &real, &greet, Arrival::Whole);
    let (split, split_closed) = smtp_feed_reply(&fake, &real, &greet, Arrival::Cuts(&cuts));
    let (bytes, bytes_closed) = smtp_feed_reply(&fake, &real, &greet, Arrival::Bytes);
    let (mut down, mut up) = smtp_machines(&fake, &real);
    prop_assert!(!whole_closed && !split_closed && !bytes_closed, "the reply closed the upstream machine");
    prop_assert_eq!(smtp_first_diff(&whole, &split), None, "reply split diverged at the cut");
    prop_assert_eq!(smtp_first_diff(&whole, &bytes), None, "reply bytes diverged");
    prop_assert!(!whole.windows(real.len()).any(|window| window == real.as_bytes()), "real password survived a whole reply");
    prop_assert!(!split.windows(real.len()).any(|window| window == real.as_bytes()), "real password survived a cut");
    prop_assert!(!bytes.windows(real.len()).any(|window| window == real.as_bytes()), "real password survived one-byte reads");
    prop_assert!(whole.windows(fake.len()).any(|window| window == fake.as_bytes()), "the decoy did not replace the password");

    let mut stream = greet.clone();
    stream.extend_from_slice(b"250 ok\r\n");
    let mut reader = CutPend::new(stream, &cuts);
    let first = smtp_read_opening(&mut up, &mut reader, &[]).expect("greeting");
    prop_assert!(!reader.cuts.is_empty(), "the greeting had no interior cut");
    prop_assert!(
      reader.pends >= 1,
      "reply reader pends {}, reads {}",
      reader.pends,
      reader.reads
    );
    prop_assert_eq!(first.code, Some(*b"220"), "the final line decides the opening");
    prop_assert!(!first.guest.windows(6).any(|window| window == b"250 ok"), "the next reply was written with the greeting");
    prop_assert!(!first.guest.windows(real.len()).any(|window| window == real.as_bytes()), "guest saw the real password");
    prop_assert!(first.guest.windows(fake.len()).any(|window| window == fake.as_bytes()), "guest missed the decoy");
    prop_assert_eq!(&first.guest, &whole, "reader chunks diverged from one feed");
    let second = smtp_read_opening(&mut up, &mut reader, &first.rest).expect("next reply");
    prop_assert_eq!(second.code, Some(*b"250"), "the following reply was no longer in sync");
    prop_assert!(second.guest.windows(6).any(|window| window == b"250 ok"), "the following reply was dropped");

    let mut closed = false;
    let (_, _, data_closed) = run_split_parts(&mut down, b"DATA\r\n", &[]);
    closed |= data_closed;
    let (_, _, reply_closed) = run_split_parts(&mut up, b"354 go\r\n", &[]);
    closed |= reply_closed;
    let mut body = b"AUTH PLAIN ".to_vec();
    body.extend_from_slice(smtp_plain_token(SMTP_FAKE_USER, &fake).as_bytes());
    body.extend_from_slice(b"\r\n.\r\n");
    let (data_out, _, body_closed) = run_split_parts(&mut down, &body, &[]);
    closed |= body_closed;
    let body_marker = smtp_plain_token(SMTP_FAKE_USER, &fake);
    prop_assert!(!closed, "DATA after the opening closed the machine");
    prop_assert!(data_out.windows(body_marker.len()).any(|window| window == body_marker.as_bytes()), "DATA after the opening was parsed as AUTH");
  }
}
