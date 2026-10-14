//! LDAP wire format: simple-bind password rewrite over BER.
//!
//! Downstream frames `LDAPMessage` values with a BER length reader, then
//! `rasn` decodes each one. A simple bind whose password is the decoy is
//! re-encoded with the real password (and the upstream bind DN, when the
//! two legs name different ones). Every other message, including `StartTLS`,
//! is forwarded byte-identical. Upstream redacts a diagnostic that carries
//! the real password back to the decoy and closes if the real password
//! would still leave the proxy.

use std::borrow::Cow;

use arkham_config::grants::Grant;
use rasn::prelude::OctetString;
use rasn_ldap::{AuthenticationChoice, BindRequest, ExtendedResponse, LdapMessage, LdapString, ProtocolOp, ResultCode};
use secrecy::ExposeSecret as _;

use crate::transports::engine::{Direction, Hit, Location, Rewritten, Wire};

/// Cap for one buffered LDAP message. A simple bind is tens of bytes;
/// anything past this is a drip or an attack, never a bind.
const MAX_MESSAGE: usize = 64 * 1024;

/// Nested BER depth past which a message is not a bind we will reframe.
const MAX_DEPTH: usize = 32;

/// `StartTLS` extended operation OID (RFC 4511).
const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// One LDAP direction leg.
pub(crate) struct Ldap {
  down: Option<Down>,
  up: Option<Up>,
  /// Message id of a `StartTLS` request just framed.
  starttls: Option<u32>,
  /// Bytes that followed that request in the same buffer. They are the
  /// handshake, not more LDAP.
  prefix: Vec<u8>,
  /// `Some` once the extended response for [`Self::expect_starttls`] arrives.
  starttls_ok: Option<bool>,
}

/// Downstream parse state.
struct Down {
  buf: Vec<u8>,
  fake: String,
  real: String,
  downstream_dn: String,
  upstream_dn: String,
  label: String,
  closed: bool,
}

/// Upstream redaction state.
struct Up {
  buf: Vec<u8>,
  fake: String,
  real: String,
  label: String,
  closed: bool,
  /// Message id whose extended response is the `StartTLS` result.
  expect_id: Option<u32>,
}

impl Ldap {
  /// Fresh leg. Downstream swaps binds; upstream redacts diagnostics.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    let down = if dir == Direction::Downstream {
      grants.iter().find_map(|grant| {
        let scope = grant.ldap(Some(host), port)?;
        Some(Down {
          buf: Vec::new(),
          fake: scope.downstream.password.expose_secret().to_string(),
          real: scope.upstream.password.expose_secret().to_string(),
          downstream_dn: scope.downstream.dn.clone(),
          upstream_dn: scope.upstream.dn.clone(),
          label: grant.credential().map(|credential| credential.label.clone()).unwrap_or_default(),
          closed: false,
        })
      })
    } else {
      None
    };
    let up = if dir == Direction::Upstream {
      grants.iter().find_map(|grant| {
        let scope = grant.ldap(Some(host), port)?;
        Some(Up {
          buf: Vec::new(),
          fake: scope.downstream.password.expose_secret().to_string(),
          real: scope.upstream.password.expose_secret().to_string(),
          label: grant.credential().map(|credential| credential.label.clone()).unwrap_or_default(),
          closed: false,
          expect_id: None,
        })
      })
    } else {
      None
    };
    Self {
      down,
      up,
      starttls: None,
      prefix: Vec::new(),
      starttls_ok: None,
    }
  }

  /// Message id of a `StartTLS` request framed by the last `feed`, once.
  pub(crate) fn take_starttls(&mut self) -> Option<u32> {
    self.starttls.take()
  }

  /// Bytes after that request. The caller replays them into the handshake.
  pub(crate) fn take_prefix(&mut self) -> Vec<u8> {
    std::mem::take(&mut self.prefix)
  }

  /// The next extended response with `id` is the `StartTLS` result.
  pub(crate) fn expect_starttls(&mut self, id: u32) {
    if let Some(up) = self.up.as_mut() {
      up.expect_id = Some(id);
    }
  }

  /// `Some(true)` when the expected `StartTLS` response succeeded.
  pub(crate) fn take_starttls_result(&mut self) -> Option<bool> {
    self.starttls_ok.take()
  }
}

/// A success extended response for `id`, used when the upstream leg is
/// already TLS and the `StartTLS` request must not be forwarded.
///
/// # Errors
///
/// Returns the encoder error when the fixed success message cannot be encoded.
pub(crate) fn starttls_success(id: u32) -> Result<Vec<u8>, rasn::error::EncodeError> {
  let message = LdapMessage::new(
    id,
    ProtocolOp::ExtendedResp(ExtendedResponse {
      result_code: ResultCode::Success,
      matched_dn: LdapString::from(""),
      diagnostic_message: LdapString::from(""),
      referral: None,
      response_name: Some(OctetString::from_static(STARTTLS_OID)),
      response_value: None,
    }),
  );
  rasn::ber::encode(&message)
}

impl Wire for Ldap {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    if self.down.is_some() {
      return self.feed_down(chunk).await;
    }
    if self.up.is_some() {
      return self.feed_up(chunk).await;
    }
    (Rewritten::Emit(Cow::Borrowed(chunk)), Vec::new())
  }
}

impl Ldap {
  /// Guest to upstream.
  async fn feed_down<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let Some(down) = self.down.as_mut() else {
      return (Rewritten::Hold, Vec::new());
    };
    if down.closed {
      return (Rewritten::Close, Vec::new());
    }
    if chunk.is_empty() {
      return if down.buf.is_empty() {
        (Rewritten::Hold, Vec::new())
      } else {
        down.closed = true;
        (Rewritten::Close, Vec::new())
      };
    }
    down.buf.extend_from_slice(chunk);
    if down.buf.len() > MAX_MESSAGE {
      down.closed = true;
      return (Rewritten::Close, Vec::new());
    }
    let mut out = Vec::new();
    let mut hits = Vec::new();
    loop {
      let frame = match take_message(&mut down.buf) {
        Ok(None) => break,
        Ok(Some(frame)) => frame,
        Err(()) => {
          down.closed = true;
          return (Rewritten::Close, hits);
        }
      };
      match rewrite_down(&frame, down) {
        Ok(RewrittenDown::Same) => out.extend_from_slice(&frame),
        Ok(RewrittenDown::Swapped { bytes, hit }) => {
          out.extend_from_slice(&bytes);
          hits.push(hit);
        }
        Ok(RewrittenDown::StartTls { id }) => {
          out.extend_from_slice(&frame);
          self.starttls = Some(id);
          self.prefix = std::mem::take(&mut down.buf);
          break;
        }
        Err(()) => {
          down.closed = true;
          return (Rewritten::Close, Vec::new());
        }
      }
    }
    if out.is_empty() {
      (Rewritten::Hold, hits)
    } else {
      (Rewritten::Emit(Cow::Owned(out)), hits)
    }
  }

  /// Upstream to guest.
  async fn feed_up<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let Some(up) = self.up.as_mut() else {
      return (Rewritten::Hold, Vec::new());
    };
    if up.closed {
      return (Rewritten::Close, Vec::new());
    }
    if chunk.is_empty() {
      return if up.buf.is_empty() {
        (Rewritten::Hold, Vec::new())
      } else {
        up.closed = true;
        (Rewritten::Close, Vec::new())
      };
    }
    up.buf.extend_from_slice(chunk);
    if up.buf.len() > MAX_MESSAGE {
      up.closed = true;
      return (Rewritten::Close, Vec::new());
    }
    let mut out = Vec::new();
    let mut hits = Vec::new();
    loop {
      let frame = match take_message(&mut up.buf) {
        Ok(None) => break,
        Ok(Some(frame)) => frame,
        Err(()) => {
          up.closed = true;
          return (Rewritten::Close, hits);
        }
      };
      match redact_up(&frame, up) {
        Ok(Redacted::Same) => out.extend_from_slice(&frame),
        Ok(Redacted::Replaced { bytes, hit, starttls_ok }) => {
          out.extend_from_slice(&bytes);
          if let Some(hit) = hit {
            hits.push(hit);
          }
          if let Some(ok) = starttls_ok {
            self.starttls_ok = Some(ok);
          }
        }
        Err(()) => {
          up.closed = true;
          return (Rewritten::Close, Vec::new());
        }
      }
    }
    if out.is_empty() {
      (Rewritten::Hold, hits)
    } else {
      (Rewritten::Emit(Cow::Owned(out)), hits)
    }
  }
}

/// One downstream message after the swap decision.
enum RewrittenDown {
  Same,
  Swapped { bytes: Vec<u8>, hit: Hit },
  StartTls { id: u32 },
}

/// One upstream message after redaction.
enum Redacted {
  Same,
  Replaced {
    bytes: Vec<u8>,
    hit: Option<Hit>,
    starttls_ok: Option<bool>,
  },
}

/// Swap a simple bind, or notice `StartTLS`. Unchanged messages stay the
/// original bytes so a non-matching bind is byte-identical.
fn rewrite_down(frame: &[u8], down: &Down) -> Result<RewrittenDown, ()> {
  let message: LdapMessage = rasn::ber::decode(frame).map_err(|_| ())?;
  match message.protocol_op {
    ProtocolOp::BindRequest(request) => rewrite_bind(request, message.message_id, down),
    ProtocolOp::ExtendedReq(request) if request.request_name.as_ref() == STARTTLS_OID && request.request_value.is_none() => {
      Ok(RewrittenDown::StartTls { id: message.message_id })
    }
    _ => Ok(RewrittenDown::Same),
  }
}

/// Re-encode a simple bind whose password is the decoy.
fn rewrite_bind(request: BindRequest, message_id: u32, down: &Down) -> Result<RewrittenDown, ()> {
  let AuthenticationChoice::Simple(password) = &request.authentication else {
    return Ok(RewrittenDown::Same);
  };
  if password.as_ref() != down.fake.as_bytes() {
    return Ok(RewrittenDown::Same);
  }
  let dn = if request.name.0 == down.downstream_dn && down.downstream_dn != down.upstream_dn {
    LdapString::from(down.upstream_dn.as_str())
  } else {
    request.name.clone()
  };
  let swapped = BindRequest::new(
    request.version,
    dn,
    AuthenticationChoice::Simple(OctetString::from(down.real.as_bytes())),
  );
  let encoded = rasn::ber::encode(&LdapMessage::new(message_id, ProtocolOp::BindRequest(swapped))).map_err(|_| ())?;
  // A re-encode that still carries the decoy, or that dropped the real
  // password, is not a swap. Close rather than send the decoy upstream.
  if contains_bytes(&encoded, down.fake.as_bytes()) || !contains_bytes(&encoded, down.real.as_bytes()) {
    return Err(());
  }
  Ok(RewrittenDown::Swapped {
    bytes: encoded,
    hit: Hit {
      label: down.label.clone(),
      location: Location::Body,
    },
  })
}

/// Redact the real password out of a response diagnostic.
fn redact_up(frame: &[u8], up: &mut Up) -> Result<Redacted, ()> {
  let secret = up.real.as_bytes();
  let leaked = contains_bytes(frame, secret);
  let mut message: LdapMessage = rasn::ber::decode(frame).map_err(|_| ())?;
  let starttls_ok = starttls_result(&message, up.expect_id);
  if starttls_ok.is_some() {
    up.expect_id = None;
  }
  if !leaked {
    return if starttls_ok.is_some() {
      Ok(Redacted::Replaced {
        bytes: frame.to_vec(),
        hit: None,
        starttls_ok,
      })
    } else {
      Ok(Redacted::Same)
    };
  }
  let Some(diagnostic) = diagnostic_mut(&mut message.protocol_op) else {
    return Err(());
  };
  if !diagnostic.0.contains(&up.real) {
    return Err(());
  }
  diagnostic.0 = diagnostic.0.replace(&up.real, &up.fake);
  let encoded = rasn::ber::encode(&message).map_err(|_| ())?;
  if contains_bytes(&encoded, secret) {
    return Err(());
  }
  Ok(Redacted::Replaced {
    bytes: encoded,
    hit: Some(Hit {
      label: up.label.clone(),
      location: Location::Body,
    }),
    starttls_ok,
  })
}

/// Whether this message is the `StartTLS` extended response we are waiting for.
fn starttls_result(message: &LdapMessage, expect_id: Option<u32>) -> Option<bool> {
  let expect_id = expect_id?;
  if message.message_id != expect_id {
    return None;
  }
  match &message.protocol_op {
    ProtocolOp::ExtendedResp(response) => Some(response.result_code == ResultCode::Success),
    _ => Some(false),
  }
}

/// Diagnostic text of a result, when the operation carries one.
fn diagnostic_mut(op: &mut ProtocolOp) -> Option<&mut LdapString> {
  match op {
    ProtocolOp::BindResponse(response) => Some(&mut response.diagnostic_message),
    ProtocolOp::ExtendedResp(response) => Some(&mut response.diagnostic_message),
    ProtocolOp::SearchResDone(done) => Some(&mut done.0.diagnostic_message),
    ProtocolOp::ModifyResponse(response) => Some(&mut response.0.diagnostic_message),
    ProtocolOp::AddResponse(response) => Some(&mut response.0.diagnostic_message),
    ProtocolOp::DelResponse(response) => Some(&mut response.0.diagnostic_message),
    ProtocolOp::ModDnResponse(response) => Some(&mut response.0.diagnostic_message),
    ProtocolOp::CompareResponse(response) => Some(&mut response.0.diagnostic_message),
    _ => None,
  }
}

/// Take one complete LDAP message off `buf`. `Ok(None)` while it is short.
/// `Err` when the bytes cannot be a BER LDAP message.
fn take_message(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, ()> {
  let Some(&first) = buf.first() else {
    return Ok(None);
  };
  if first != 0x30 {
    return Err(());
  }
  let Some(len) = ber_value_len(buf)? else {
    return Ok(None);
  };
  if len > buf.len() {
    return Ok(None);
  }
  Ok(Some(buf.drain(..len).collect()))
}

/// Total length of one BER value, tag and length octets included.
/// `Ok(None)` while the header or contents are still short.
fn ber_value_len(input: &[u8]) -> Result<Option<usize>, ()> {
  ber_value_len_at(input, 0)
}

/// `depth` counts nested indefinite values.
fn ber_value_len_at(input: &[u8], depth: usize) -> Result<Option<usize>, ()> {
  if depth > MAX_DEPTH {
    return Err(());
  }
  let Some(&tag) = input.first() else {
    return Ok(None);
  };
  let mut index = 1usize;
  if tag & 0x1f == 0x1f {
    loop {
      let Some(&byte) = input.get(index) else {
        return Ok(None);
      };
      index = index.checked_add(1).ok_or(())?;
      if index > 8 {
        return Err(());
      }
      if byte & 0x80 == 0 {
        break;
      }
    }
  }
  let Some(&len_byte) = input.get(index) else {
    return Ok(None);
  };
  index = index.checked_add(1).ok_or(())?;
  if len_byte == 0x80 {
    if tag & 0x20 == 0 {
      return Err(());
    }
    return indefinite_end(input, index, depth);
  }
  let (content_len, header_end) = if len_byte < 0x80 {
    (usize::from(len_byte), index)
  } else {
    let octets = usize::from(len_byte & 0x7f);
    if octets == 0 || octets > 4 {
      return Err(());
    }
    let end = index.checked_add(octets).ok_or(())?;
    if input.len() < end {
      return Ok(None);
    }
    let mut len = 0usize;
    let bytes = input.get(index..end).ok_or(())?;
    for byte in bytes {
      len = len.checked_shl(8).ok_or(())?.checked_add(usize::from(*byte)).ok_or(())?;
    }
    (len, end)
  };
  let total = header_end.checked_add(content_len).ok_or(())?;
  if total > MAX_MESSAGE {
    return Err(());
  }
  if input.len() < total { Ok(None) } else { Ok(Some(total)) }
}

/// End offset of an indefinite-length value, including the end-of-contents.
fn indefinite_end(input: &[u8], mut index: usize, depth: usize) -> Result<Option<usize>, ()> {
  let nested = depth.checked_add(1).ok_or(())?;
  loop {
    if index > MAX_MESSAGE {
      return Err(());
    }
    let Some(&first) = input.get(index) else {
      return Ok(None);
    };
    let next = index.checked_add(1).ok_or(())?;
    if first == 0 {
      let Some(&second) = input.get(next) else {
        return Ok(None);
      };
      if second == 0 {
        return Ok(next.checked_add(1));
      }
    }
    let Some(rest) = input.get(index..) else {
      return Ok(None);
    };
    match ber_value_len_at(rest, nested)? {
      None => return Ok(None),
      Some(len) => index = index.checked_add(len).ok_or(())?,
    }
  }
}

/// `true` when `needle` occurs in `hay`. An empty needle never matches.
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
  let n = needle.len();
  if n == 0 || hay.len() < n {
    return false;
  }
  hay.windows(n).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, GuestTlsMode, LdapScope};
  use secrecy::SecretString;

  const FAKE_PW: &str = "arkham_fake_ldap_pass"; // betterleaks:allow
  const REAL_PW: &str = "arkham_real_ldap_pass_01"; // betterleaks:allow
  const DN: &str = "cn=Directory Manager";

  fn scope(downstream_dn: &str, upstream_dn: &str) -> LdapScope {
    LdapScope::from_strings(
      &format!("ldap://{}:{FAKE_PW}@ldap:389", encode_user(downstream_dn)),
      &format!("ldap://{}:{REAL_PW}@ldap:389", encode_user(upstream_dn)),
    )
    .unwrap()
  }

  fn encode_user(dn: &str) -> String {
    dn.replace('=', "%3D").replace(' ', "%20").replace(',', "%2C")
  }

  fn grant(downstream_dn: &str, upstream_dn: &str) -> Vec<Grant> {
    let parsed = scope(downstream_dn, upstream_dn);
    vec![Grant::Ldap {
      credential: Credential {
        label: "ldap".into(),
        fake: FAKE_PW.into(),
        value: SecretString::from(REAL_PW),
      },
      scope: Box::new(parsed),
    }]
  }

  fn down() -> Ldap {
    Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream)
  }

  fn up() -> Ldap {
    Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Upstream)
  }

  fn bind_frame(id: u32, dn: &str, password: &str) -> Vec<u8> {
    let message = LdapMessage::new(
      id,
      ProtocolOp::BindRequest(BindRequest::new(
        3,
        LdapString::from(dn),
        AuthenticationChoice::Simple(OctetString::from(password.as_bytes())),
      )),
    );
    rasn::ber::encode(&message).unwrap()
  }

  fn starttls_frame(id: u32) -> Vec<u8> {
    let message = LdapMessage::new(
      id,
      ProtocolOp::ExtendedReq(rasn_ldap::ExtendedRequest {
        request_name: OctetString::from_static(STARTTLS_OID),
        request_value: None,
      }),
    );
    rasn::ber::encode(&message).unwrap()
  }

  fn bind_response(id: u32, diagnostic: &str) -> Vec<u8> {
    let message = LdapMessage::new(
      id,
      ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
        ResultCode::InvalidCredentials,
        LdapString::from(""),
        LdapString::from(diagnostic),
        None,
        None,
      )),
    );
    rasn::ber::encode(&message).unwrap()
  }

  async fn emit(machine: &mut Ldap, chunk: &[u8]) -> Vec<u8> {
    match machine.feed(chunk).await.0 {
      Rewritten::Emit(bytes) => bytes.into_owned(),
      other => panic!("expected emit, got hold/close: {}", matches!(other, Rewritten::Hold)),
    }
  }

  #[tokio::test]
  async fn simple_bind_swaps_a_different_length_password() {
    let frame = bind_frame(1, DN, FAKE_PW);
    let mut machine = down();
    let out = emit(&mut machine, &frame).await;
    let message: LdapMessage = rasn::ber::decode(&out).unwrap();
    let ProtocolOp::BindRequest(request) = message.protocol_op else {
      panic!("bind");
    };
    let AuthenticationChoice::Simple(password) = request.authentication else {
      panic!("simple");
    };
    assert_eq!(password.as_ref(), REAL_PW.as_bytes());
    assert_ne!(frame.len(), out.len());
    assert!(!contains_bytes(&out, FAKE_PW.as_bytes()));
  }

  #[tokio::test]
  async fn bind_split_across_chunks_swaps_the_whole_password() {
    let frame = bind_frame(7, DN, FAKE_PW);
    for cut in 0..frame.len() {
      let mut machine = down();
      let (first, hits) = machine.feed(&frame[..cut]).await;
      assert!(hits.is_empty(), "cut {cut}");
      assert!(matches!(first, Rewritten::Hold), "cut {cut}");
      let out = emit(&mut machine, &frame[cut..]).await;
      let message: LdapMessage = rasn::ber::decode(&out).unwrap();
      let ProtocolOp::BindRequest(request) = message.protocol_op else {
        panic!("bind at cut {cut}");
      };
      let AuthenticationChoice::Simple(password) = request.authentication else {
        panic!("simple at cut {cut}");
      };
      assert_eq!(password.as_ref(), REAL_PW.as_bytes(), "cut {cut}");
    }
  }

  #[tokio::test]
  async fn non_matching_password_is_byte_identical() {
    let frame = bind_frame(1, DN, "not-the-decoy");
    let mut machine = down();
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn differing_dns_swap_with_the_password() {
    let mut machine = Ldap::new(&grant(DN, "cn=svc,dc=example,dc=com"), "ldap", 389, Direction::Downstream);
    let out = emit(&mut machine, &bind_frame(1, DN, FAKE_PW)).await;
    let message: LdapMessage = rasn::ber::decode(&out).unwrap();
    let ProtocolOp::BindRequest(request) = message.protocol_op else {
      panic!("bind");
    };
    assert_eq!(request.name.0, "cn=svc,dc=example,dc=com");
  }

  #[tokio::test]
  async fn starttls_request_is_byte_identical_and_stops_the_buffer() {
    let frame = starttls_frame(4);
    let extra = b"\x16handshake";
    let mut bytes = frame.clone();
    bytes.extend_from_slice(extra);
    let mut machine = down();
    let out = emit(&mut machine, &bytes).await;
    assert_eq!(out, frame);
    assert_eq!(machine.take_starttls(), Some(4));
    assert_eq!(machine.take_prefix(), extra);
  }

  #[tokio::test]
  async fn diagnostic_real_password_is_redacted() {
    let frame = bind_response(1, &format!("rejected {REAL_PW}"));
    let mut machine = up();
    let out = emit(&mut machine, &frame).await;
    assert!(!contains_bytes(&out, REAL_PW.as_bytes()));
    assert!(contains_bytes(&out, FAKE_PW.as_bytes()));
  }

  #[tokio::test]
  async fn starttls_success_is_reported() {
    let frame = {
      let message = LdapMessage::new(
        4,
        ProtocolOp::ExtendedResp(ExtendedResponse {
          result_code: ResultCode::Success,
          matched_dn: LdapString::from(""),
          diagnostic_message: LdapString::from(""),
          referral: None,
          response_name: Some(OctetString::from_static(STARTTLS_OID)),
          response_value: None,
        }),
      );
      rasn::ber::encode(&message).unwrap()
    };
    let mut machine = up();
    machine.expect_starttls(4);
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
    assert_eq!(machine.take_starttls_result(), Some(true));
  }

  fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    thread_local! {
      static RT: tokio::runtime::Runtime =
        tokio::runtime::Builder::new_current_thread().build().unwrap();
    }
    RT.with(|rt| rt.block_on(fut))
  }

  proptest::proptest! {
    #[test]
    fn arbitrary_bytes_do_not_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..128)) {
      let mut downstream = down();
      let mut upstream = up();
      block_on(async {
        let _ = downstream.feed(&bytes).await;
        let _ = upstream.feed(&bytes).await;
        let _ = downstream.feed(&[]).await;
        let _ = upstream.feed(&[]).await;
      });
    }
  }

  #[test]
  fn scope_fields_are_used() {
    let parsed = scope(DN, DN);
    assert_eq!(parsed.downstream.port, 389);
    assert!(!parsed.is_downstream_tls);
    let _ = parsed.guest_tls;
    assert_eq!(parsed.guest_tls, GuestTlsMode::Tls);
  }
}
