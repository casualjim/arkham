//! LDAP wire format: simple-bind password rewrite over BER.
//!
//! Downstream frames `LDAPMessage` values with a definite-length BER reader
//! (RFC 4511). A simple bind whose password is the decoy is re-encoded with
//! the real password only when `swap` is set, which the transport sets once
//! the upstream writer is TLS. A cleartext upstream keeps the decoy bytes.
//! The upstream bind DN is written when the two legs name different ones.
//! `StartTLS` is forwarded byte-identical either way. Upstream fully decodes
//! a message only when its bytes contain the real password or it is the
//! `StartTLS` reply being waited on. A diagnostic that still carries the
//! real password after redaction closes the leg.

use std::borrow::Cow;

use arkham_config::grants::Grant;
use rasn::prelude::OctetString;
use rasn_ldap::{AuthenticationChoice, BindRequest, ExtendedResponse, LdapMessage, LdapString, ProtocolOp, ResultCode};
use secrecy::ExposeSecret as _;

use crate::transports::engine::{Direction, Hit, Location, Rewritten, Wire};

/// Cap for one downstream LDAP message. A simple bind is tens of bytes;
/// anything past this is not a bind we will reframe. The cap is per message.
/// Upstream messages are not capped: a search result is buffered until it
/// is complete, then forwarded.
const MAX_MESSAGE: usize = 64 * 1024;

/// `StartTLS` extended operation OID (RFC 4511).
const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// `APPLICATION 0` constructed: `BindRequest`.
const BIND_REQUEST_TAG: u8 = 0x60;

/// `APPLICATION 23` constructed: `ExtendedRequest`.
const EXTENDED_REQUEST_TAG: u8 = 0x77;

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
  /// Rewrite a matching simple bind. False while the upstream writer is cleartext.
  swap: bool,
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
  /// Fresh leg. `swap` is downstream only: a simple bind is rewritten when
  /// the upstream writer is already TLS. A cleartext upstream keeps the decoy.
  /// Upstream always redacts a diagnostic that carries the real password.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction, swap: bool) -> Self {
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
          swap,
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
  fn feed<'a>(&mut self, chunk: &'a [u8]) -> impl Future<Output = (Rewritten<'a>, Vec<Hit>)> + Send {
    let rewritten = if self.down.is_some() {
      self.feed_down(chunk)
    } else if self.up.is_some() {
      self.feed_up(chunk)
    } else {
      (Rewritten::Emit(Cow::Borrowed(chunk)), Vec::new())
    };
    std::future::ready(rewritten)
  }
}

impl Ldap {
  /// Guest to upstream.
  fn feed_down<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
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
    let mut out = Vec::new();
    let mut hits = Vec::new();
    loop {
      let frame = match take_message(&mut down.buf, Some(MAX_MESSAGE)) {
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
  fn feed_up<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
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
    let mut out = Vec::new();
    let mut hits = Vec::new();
    loop {
      let frame = match take_message(&mut up.buf, None) {
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

/// Swap a simple bind, or notice `StartTLS`. Only those two operations are
/// fully decoded. Everything else, including a bind while `swap` is off,
/// stays the original bytes.
fn rewrite_down(frame: &[u8], down: &Down) -> Result<RewrittenDown, ()> {
  let Some(tag) = protocol_op_tag(frame) else {
    return Err(());
  };
  if tag == EXTENDED_REQUEST_TAG {
    return rewrite_extended(frame);
  }
  if tag == BIND_REQUEST_TAG && down.swap {
    let message: LdapMessage = rasn::ber::decode(frame).map_err(|_err| ())?;
    let ProtocolOp::BindRequest(request) = &message.protocol_op else {
      return Ok(RewrittenDown::Same);
    };
    return rewrite_bind(request, &message, down);
  }
  Ok(RewrittenDown::Same)
}

/// Notice a `StartTLS` extended request. Any other extended request is
/// forwarded as the original bytes.
fn rewrite_extended(frame: &[u8]) -> Result<RewrittenDown, ()> {
  let message: LdapMessage = rasn::ber::decode(frame).map_err(|_err| ())?;
  if let ProtocolOp::ExtendedReq(request) = &message.protocol_op
    && request.request_name.as_ref() == STARTTLS_OID
    && request.request_value.is_none()
  {
    return Ok(RewrittenDown::StartTls { id: message.message_id });
  }
  Ok(RewrittenDown::Same)
}

/// Re-encode a simple bind whose password is the decoy.
fn rewrite_bind(request: &BindRequest, message: &LdapMessage, down: &Down) -> Result<RewrittenDown, ()> {
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
  let mut encoded_message = LdapMessage::new(message.message_id, ProtocolOp::BindRequest(swapped));
  encoded_message.controls.clone_from(&message.controls);
  let encoded = rasn::ber::encode(&encoded_message).map_err(|_err| ())?;
  // The password field of the re-encoded bind must be the real password.
  // Comparing the whole encoding would reject a decoy that is a substring
  // of the DN or of the real password.
  let check: LdapMessage = rasn::ber::decode(&encoded).map_err(|_err| ())?;
  if check.controls != message.controls {
    return Err(());
  }
  let ProtocolOp::BindRequest(checked) = &check.protocol_op else {
    return Err(());
  };
  let AuthenticationChoice::Simple(checked_password) = &checked.authentication else {
    return Err(());
  };
  if checked_password.as_ref() != down.real.as_bytes() {
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
  let awaiting = match up.expect_id {
    Some(expect) => message_id(frame).is_none_or(|id| id == expect),
    None => false,
  };
  if !leaked && !awaiting {
    return Ok(Redacted::Same);
  }
  let mut message: LdapMessage = rasn::ber::decode(frame).map_err(|_err| ())?;
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
  let encoded = rasn::ber::encode(&message).map_err(|_err| ())?;
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

/// Take one complete LDAP message off `buf`. `cap` limits that one message;
/// `None` does not. `Ok(None)` while the header or contents are still short.
/// `Err` when the outer tag is not a definite-length `SEQUENCE`, the length
/// is illegal, or the message exceeds `cap`. RFC 4511 is definite-length only.
fn take_message(buf: &mut Vec<u8>, cap: Option<usize>) -> Result<Option<Vec<u8>>, ()> {
  let Some(&tag) = buf.first() else {
    return Ok(None);
  };
  if tag != 0x30 {
    return Err(());
  }
  let Some(&len_byte) = buf.get(1) else {
    return Ok(None);
  };
  if len_byte == 0x80 {
    return Err(());
  }
  let (content_len, header_end) = if len_byte < 0x80 {
    (usize::from(len_byte), 2usize)
  } else {
    let octets = usize::from(len_byte & 0x7f);
    if octets == 0 || octets > 4 {
      return Err(());
    }
    let end = 2usize.checked_add(octets).ok_or(())?;
    if buf.len() < end {
      return Ok(None);
    }
    let mut len = 0usize;
    let bytes = buf.get(2..end).ok_or(())?;
    for byte in bytes {
      len = len.checked_shl(8).ok_or(())?.checked_add(usize::from(*byte)).ok_or(())?;
    }
    (len, end)
  };
  let total = header_end.checked_add(content_len).ok_or(())?;
  if cap.is_some_and(|limit| total > limit) {
    return Err(());
  }
  if buf.len() < total {
    return Ok(None);
  }
  Ok(Some(buf.drain(..total).collect()))
}

/// Content of the outer definite-length `SEQUENCE`, when `frame` is one.
fn sequence_content(frame: &[u8]) -> Option<&[u8]> {
  let (&tag, rest) = frame.split_first()?;
  if tag != 0x30 {
    return None;
  }
  let (content_len, header) = definite_length(rest)?;
  let end = header.checked_add(content_len)?;
  rest.get(header..end)
}

/// `(content length, octets consumed from `rest`)`. `rest` starts at the
/// length byte. `None` for a short, indefinite, or illegal length.
fn definite_length(rest: &[u8]) -> Option<(usize, usize)> {
  let (&len_byte, _) = rest.split_first()?;
  if len_byte == 0x80 {
    return None;
  }
  if len_byte < 0x80 {
    return Some((usize::from(len_byte), 1));
  }
  let octets = usize::from(len_byte & 0x7f);
  if octets == 0 || octets > 4 {
    return None;
  }
  let header = 1usize.checked_add(octets)?;
  let bytes = rest.get(1..header)?;
  let mut len = 0usize;
  for byte in bytes {
    len = len.checked_shl(8)?.checked_add(usize::from(*byte))?;
  }
  Some((len, header))
}

/// `messageID`, the first `INTEGER` inside the outer `SEQUENCE`.
fn message_id(frame: &[u8]) -> Option<u32> {
  let content = sequence_content(frame)?;
  let (&tag, rest) = content.split_first()?;
  if tag != 0x02 {
    return None;
  }
  let (len, header) = definite_length(rest)?;
  if len == 0 || len > 4 {
    return None;
  }
  let bytes = rest.get(header..header.checked_add(len)?)?;
  let mut id = 0u32;
  for byte in bytes {
    id = id.checked_shl(8)?.checked_add(u32::from(*byte))?;
  }
  Some(id)
}

/// Tag of `protocolOp`, the value after `messageID`.
fn protocol_op_tag(frame: &[u8]) -> Option<u8> {
  let content = sequence_content(frame)?;
  let (&tag, rest) = content.split_first()?;
  if tag != 0x02 {
    return None;
  }
  let (len, header) = definite_length(rest)?;
  rest.get(header.checked_add(len)?).copied()
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
    Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream, true)
  }

  fn up() -> Ldap {
    Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Upstream, false)
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
  async fn cleartext_bind_forwards_the_decoy() {
    let frame = bind_frame(1, DN, FAKE_PW);
    let mut machine = Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream, false);
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn starttls_is_noticed_while_the_password_stays_put() {
    let mut bytes = bind_frame(1, DN, FAKE_PW);
    bytes.extend_from_slice(&starttls_frame(2));
    let mut machine = Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream, false);
    let out = emit(&mut machine, &bytes).await;
    assert_eq!(out, bytes);
    assert_eq!(machine.take_starttls(), Some(2));
  }

  #[tokio::test]
  async fn bind_controls_survive_the_swap() {
    let mut message = LdapMessage::new(
      3,
      ProtocolOp::BindRequest(BindRequest::new(
        3,
        LdapString::from(DN),
        AuthenticationChoice::Simple(OctetString::from(FAKE_PW.as_bytes())),
      )),
    );
    message.controls = Some(vec![rasn_ldap::Control::new(
      OctetString::from_static(b"1.2.840.113556.1.4.319"),
      true,
      Some(OctetString::from_static(b"page")),
    )]);
    let frame = rasn::ber::encode(&message).unwrap();
    let mut machine = down();
    let out = emit(&mut machine, &frame).await;
    let decoded: LdapMessage = rasn::ber::decode(&out).unwrap();
    assert_eq!(decoded.controls, message.controls);
    let ProtocolOp::BindRequest(request) = decoded.protocol_op else {
      panic!("bind");
    };
    let AuthenticationChoice::Simple(password) = request.authentication else {
      panic!("simple");
    };
    assert_eq!(password.as_ref(), REAL_PW.as_bytes());
  }

  #[tokio::test]
  async fn decoy_that_is_a_substring_of_the_dn_still_swaps() {
    let dn = "cn=Directory Manager";
    let fake = "cn";
    let real = "cn-real-secret";
    let parsed = LdapScope::from_strings(
      &format!("ldap://{}:{fake}@ldap:389", encode_user(dn)),
      &format!("ldap://{}:{real}@ldap:389", encode_user(dn)),
    )
    .unwrap();
    let grants = vec![Grant::Ldap {
      credential: Credential {
        label: "ldap".into(),
        fake: fake.into(),
        value: SecretString::from(real),
      },
      scope: Box::new(parsed),
    }];
    let mut machine = Ldap::new(&grants, "ldap", 389, Direction::Downstream, true);
    let out = emit(&mut machine, &bind_frame(1, dn, fake)).await;
    let message: LdapMessage = rasn::ber::decode(&out).unwrap();
    let ProtocolOp::BindRequest(request) = message.protocol_op else {
      panic!("bind");
    };
    let AuthenticationChoice::Simple(password) = request.authentication else {
      panic!("simple");
    };
    assert_eq!(password.as_ref(), real.as_bytes());
    assert_eq!(request.name.0, dn);
  }

  #[tokio::test]
  async fn many_small_messages_past_the_cap_still_forward() {
    let frame = bind_frame(1, DN, "not-the-decoy");
    let mut bytes = Vec::new();
    while bytes.len() <= MAX_MESSAGE {
      bytes.extend_from_slice(&frame);
    }
    let mut machine = down();
    let out = emit(&mut machine, &bytes).await;
    assert_eq!(out, bytes);
    assert!(out.len() > MAX_MESSAGE);
  }

  #[tokio::test]
  async fn downstream_message_over_the_cap_closes() {
    let header = [0x30, 0x84, 0x00, 0x01, 0x00, 0x01];
    let mut machine = down();
    let (rewritten, _) = machine.feed(&header).await;
    assert!(matches!(rewritten, Rewritten::Close));
  }

  #[tokio::test]
  async fn indefinite_length_closes() {
    let mut machine = down();
    let (rewritten, _) = machine.feed(&[0x30, 0x80]).await;
    assert!(matches!(rewritten, Rewritten::Close));
  }

  #[tokio::test]
  async fn upstream_message_larger_than_a_bind_is_forwarded() {
    let content_len = MAX_MESSAGE + 1;
    let mut frame = vec![0x30, 0x84];
    let len = u32::try_from(content_len).unwrap();
    frame.extend_from_slice(&len.to_be_bytes());
    frame.resize(frame.len() + content_len, 0x00);
    let mut machine = up();
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn upstream_announced_length_is_buffered() {
    let header = [0x30, 0x84, 0x01, 0x00, 0x00, 0x01];
    let mut machine = up();
    let (rewritten, _) = machine.feed(&header).await;
    assert!(matches!(rewritten, Rewritten::Hold));
  }

  #[tokio::test]
  async fn upstream_non_secret_message_is_not_decoded() {
    let frame = [0x30, 0x06, 0x02, 0x01, 0x01, 0x42, 0x01, 0x00];
    let mut machine = up();
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn unreadable_starttls_response_closes() {
    let frame = [0x30, 0x06, 0x02, 0x01, 0x04, 0x42, 0x01, 0x00];
    let mut machine = up();
    machine.expect_starttls(4);
    let (rewritten, _) = machine.feed(&frame).await;
    assert!(matches!(rewritten, Rewritten::Close));
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
    let mut machine = Ldap::new(&grant(DN, "cn=svc,dc=example,dc=com"), "ldap", 389, Direction::Downstream, true);
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
