//! NATS wire format: one [`Framer`] cuts both directions into command lines
//! and counted payloads.
//!
//! Downstream, CONNECT is the only buffered command. When the server leg is
//! already TLS, its `user`/`pass` or `auth_token` carry the real values, and
//! only when every one of those fields holds the decoy. Every other byte,
//! including PUB and HPUB payloads, streams as it arrives.
//!
//! Upstream, delimited lines (INFO, -ERR, +OK, PING, PONG) redact the real
//! value back to the decoy. MSG and HMSG payloads are counted down and never
//! rewritten: a payload that carries the real value closes the leg.

use std::borrow::Cow;
use std::collections::BTreeMap;

use arkham_config::grants::{Grant, NatsAuth, NatsPair, Scheme};
use secrecy::ExposeSecret as _;
use serde_json::{Map, Value};
use strum::{EnumIter, EnumString, IntoEnumIterator as _, IntoStaticStr};

use crate::transports::engine::{
  CredentialPair, Direction, Hit, Location, Raw, Rewritten, Wire, eligible_pairs, find_new_match, max_tail_size, needle_prefix_suffix_len,
};

/// Longest CONNECT line the downstream leg buffers. A longer one closes.
pub(crate) const MAX_COMMAND: usize = 16 * 1024;

/// The two bytes that must follow every counted payload.
const CRLF: &[u8] = b"\r\n";

/// Commands a client sends.
#[derive(Debug, Clone, Copy, EnumIter, EnumString, IntoStaticStr)]
#[strum(serialize_all = "UPPERCASE", ascii_case_insensitive)]
enum ClientVerb {
  Connect,
  Pub,
  Hpub,
  Sub,
  Unsub,
  Ping,
  Pong,
}

impl ClientVerb {
  fn framing(self) -> Framing {
    match self {
      Self::Connect => Framing::Credential,
      Self::Pub | Self::Hpub => Framing::Counted,
      Self::Sub | Self::Unsub | Self::Ping | Self::Pong => Framing::Line,
    }
  }
}

/// Commands a server sends.
#[derive(Debug, Clone, Copy, EnumIter, EnumString, IntoStaticStr)]
#[strum(serialize_all = "UPPERCASE", ascii_case_insensitive)]
enum ServerVerb {
  Info,
  Msg,
  Hmsg,
  #[strum(serialize = "+OK")]
  Ok,
  #[strum(serialize = "-ERR")]
  Err,
  Ping,
  Pong,
}

impl ServerVerb {
  fn framing(self) -> Framing {
    match self {
      Self::Msg | Self::Hmsg => Framing::Counted,
      Self::Info | Self::Ok | Self::Err | Self::Ping | Self::Pong => Framing::Line,
    }
  }
}

/// How the bytes after a verb are cut.
#[derive(Debug, Clone, Copy)]
enum Framing {
  /// CONNECT: one line, held whole so the swap sees every field.
  Credential,
  /// A head line whose last token counts the payload bytes after it.
  Counted,
  /// One line through LF. An unknown verb is a line.
  Line,
}

/// Which verb set a framer reads.
#[derive(Debug, Clone, Copy)]
enum Side {
  Client,
  Server,
}

impl Side {
  fn framing(self, verb: &[u8]) -> Framing {
    let Ok(verb) = std::str::from_utf8(verb) else {
      return Framing::Line;
    };
    match self {
      Self::Client => verb.parse::<ClientVerb>().map_or(Framing::Line, ClientVerb::framing),
      Self::Server => verb.parse::<ServerVerb>().map_or(Framing::Line, ServerVerb::framing),
    }
  }

  fn longest_verb(self) -> usize {
    match self {
      Self::Client => ClientVerb::iter().map(|verb| <&str>::from(verb).len()).max(),
      Self::Server => ServerVerb::iter().map(|verb| <&str>::from(verb).len()).max(),
    }
    .unwrap_or_default()
  }
}

fn is_delimiter(byte: u8) -> bool {
  matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// The last token of a counted head, read as the line streams.
#[derive(Debug, Default)]
struct TrailingCount {
  token: Token,
  /// The last finished token, `None` when it was not a decimal count.
  last: Option<u64>,
}

#[derive(Debug, Default, Clone, Copy)]
enum Token {
  #[default]
  Between,
  Digits(u64),
  Word,
}

impl TrailingCount {
  fn push(&mut self, byte: u8) {
    if is_delimiter(byte) {
      match self.token {
        Token::Between => {}
        Token::Digits(value) => self.last = Some(value),
        Token::Word => self.last = None,
      }
      self.token = Token::Between;
      return;
    }
    let digit = char::from(byte).to_digit(10).map(u64::from);
    self.token = match (self.token, digit) {
      (Token::Between, Some(digit)) => Token::Digits(digit),
      (Token::Digits(value), Some(digit)) => value
        .checked_mul(10)
        .and_then(|value| value.checked_add(digit))
        .map_or(Token::Word, Token::Digits),
      (_, None) | (Token::Word, Some(_)) => Token::Word,
    };
  }
}

/// Where the framer is inside the current command.
#[derive(Debug)]
enum FramePhase {
  /// Verb bytes before the first delimiter. Never longer than the longest verb.
  Head(Vec<u8>),
  /// The rest of a command line, through LF.
  Line { framing: Framing, count: TrailingCount },
  /// Payload bytes a counted command still owes.
  Body(u64),
  /// The part of the CRLF after a payload not yet seen.
  Trailer(&'static [u8]),
}

/// One cut of the input.
#[derive(Debug)]
enum Piece<'a> {
  /// Command-line bytes. `end` once the LF is included.
  Line { framing: Framing, bytes: Cow<'a, [u8]>, end: bool },
  /// Payload or trailer bytes of a counted command. `end` once the trailer is complete.
  Body { bytes: &'a [u8], end: bool },
}

#[derive(Debug)]
enum Next<'a> {
  Piece(Piece<'a>),
  /// The input is consumed.
  Spent,
  /// A counted head without a count, or a payload not followed by CRLF.
  Malformed,
}

/// NATS framing for one direction. Only the verb is held; lines and payloads
/// are cut out of the caller's input.
#[derive(Debug)]
struct Framer {
  side: Side,
  /// Longest verb `side` knows. A longer head is an unknown verb.
  bound: usize,
  phase: FramePhase,
}

impl Framer {
  fn new(side: Side) -> Self {
    Self {
      side,
      bound: side.longest_verb(),
      phase: FramePhase::Head(Vec::new()),
    }
  }

  /// Cut the next piece off `input`.
  fn next_piece<'a>(&mut self, input: &mut &'a [u8]) -> Next<'a> {
    if input.is_empty() {
      return Next::Spent;
    }
    match std::mem::replace(&mut self.phase, FramePhase::Head(Vec::new())) {
      FramePhase::Head(head) => self.head(head, input),
      FramePhase::Line { framing, count } => self.line(framing, count, input),
      FramePhase::Body(left) => self.body(left, input),
      FramePhase::Trailer(want) => self.trailer(want, input),
    }
  }

  fn head<'a>(&mut self, mut head: Vec<u8>, input: &mut &'a [u8]) -> Next<'a> {
    let room = self.bound.saturating_sub(head.len());
    let window = input.get(..room.saturating_add(1)).unwrap_or(input);
    let delimiter = window.iter().position(|byte| is_delimiter(*byte));
    let overflow = delimiter.is_none() && window.len() > room;
    let take = delimiter.unwrap_or_else(|| room.min(input.len()));
    let Some((verb, rest)) = input.split_at_checked(take) else {
      return Next::Malformed;
    };
    head.extend_from_slice(verb);
    *input = rest;
    let framing = if delimiter.is_some() {
      self.side.framing(&head)
    } else if overflow {
      Framing::Line
    } else {
      self.phase = FramePhase::Head(head);
      return Next::Spent;
    };
    self.phase = FramePhase::Line {
      framing,
      count: TrailingCount::default(),
    };
    Next::Piece(Piece::Line {
      framing,
      bytes: Cow::Owned(head),
      end: false,
    })
  }

  fn line<'a>(&mut self, framing: Framing, mut count: TrailingCount, input: &mut &'a [u8]) -> Next<'a> {
    let newline = input.iter().position(|byte| *byte == b'\n');
    let take = newline.map_or(input.len(), |at| at.saturating_add(1));
    let Some((bytes, rest)) = input.split_at_checked(take) else {
      return Next::Malformed;
    };
    *input = rest;
    if matches!(framing, Framing::Counted) {
      for byte in bytes {
        count.push(*byte);
      }
    }
    let end = newline.is_some();
    if !end {
      self.phase = FramePhase::Line { framing, count };
    } else if matches!(framing, Framing::Counted) {
      self.phase = match count.last {
        Some(0) => FramePhase::Trailer(CRLF),
        Some(left) => FramePhase::Body(left),
        None => return Next::Malformed,
      };
    }
    Next::Piece(Piece::Line {
      framing,
      bytes: Cow::Borrowed(bytes),
      end,
    })
  }

  fn body<'a>(&mut self, left: u64, input: &mut &'a [u8]) -> Next<'a> {
    let take = usize::try_from(left).map_or(input.len(), |left| left.min(input.len()));
    let Some((bytes, rest)) = input.split_at_checked(take) else {
      return Next::Malformed;
    };
    let Some(left) = u64::try_from(take).ok().and_then(|took| left.checked_sub(took)) else {
      return Next::Malformed;
    };
    *input = rest;
    self.phase = if left == 0 {
      FramePhase::Trailer(CRLF)
    } else {
      FramePhase::Body(left)
    };
    Next::Piece(Piece::Body { bytes, end: false })
  }

  fn trailer<'a>(&mut self, want: &'static [u8], input: &mut &'a [u8]) -> Next<'a> {
    let take = want.len().min(input.len());
    let (Some((got, rest)), Some((expected, more))) = (input.split_at_checked(take), want.split_at_checked(take)) else {
      return Next::Malformed;
    };
    if got != expected {
      return Next::Malformed;
    }
    *input = rest;
    let end = more.is_empty();
    if !end {
      self.phase = FramePhase::Trailer(more);
    }
    Next::Piece(Piece::Body { bytes: got, end })
  }

  fn at_boundary(&self) -> bool {
    matches!(&self.phase, FramePhase::Head(head) if head.is_empty())
  }

  fn take_head(&mut self) -> Vec<u8> {
    match &mut self.phase {
      FramePhase::Head(head) => std::mem::take(head),
      FramePhase::Line { .. } | FramePhase::Body(_) | FramePhase::Trailer(_) => Vec::new(),
    }
  }
}

/// The leg must close: a malformed frame, an oversized CONNECT, or the real
/// value inside a payload.
#[derive(Debug)]
struct CloseLeg;

/// One NATS direction leg.
pub(crate) enum Nats {
  Down(Down),
  Up(Up),
  /// A leg that closed stays closed.
  Closed,
}

impl Nats {
  /// Guest-to-server leg. `swap` is true only when the server writer is
  /// already TLS. A cleartext server leg keeps the decoy.
  pub(crate) fn downstream(grants: &[Grant], host: &str, port: u16, swap: bool) -> Self {
    let policy = if swap {
      grants
        .iter()
        .find_map(|grant| {
          let scope = grant.nats(Some(host), port)?;
          let label = grant.credential()?.label.clone();
          Some(Policy::Swap {
            label,
            auth: scope.auth.clone(),
          })
        })
        .unwrap_or(Policy::Forward)
    } else {
      Policy::Forward
    };
    Self::Down(Down {
      framer: Framer::new(Side::Client),
      policy,
      connect: Vec::new(),
    })
  }

  /// Server-to-guest leg. Lines redact the real value. Payloads close on it.
  pub(crate) fn upstream(grants: &[Grant], host: &str, port: u16) -> Self {
    let pairs = eligible_pairs(grants, Scheme::Nats, host, port, Direction::Upstream);
    Self::Up(Up {
      framer: Framer::new(Side::Server),
      lines: Raw::length_changing(grants, Scheme::Nats, host, port, Direction::Upstream),
      guard: Guard {
        bound: max_tail_size(&pairs),
        pairs,
        held: Vec::new(),
      },
    })
  }
}

impl Wire for Nats {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let mut hits = Vec::new();
    let result = match self {
      Self::Down(down) => down.feed(chunk, &mut hits),
      Self::Up(up) => up.feed(chunk, &mut hits).await,
      Self::Closed => Err(CloseLeg),
    };
    match result {
      Ok(out) if out.is_empty() => (Rewritten::Hold, hits),
      Ok(out) => (Rewritten::Emit(Cow::Owned(out)), hits),
      Err(CloseLeg) => {
        *self = Self::Closed;
        (Rewritten::Close, hits)
      }
    }
  }
}

/// Whether CONNECT carries the real values.
#[derive(Debug)]
enum Policy {
  /// The server leg is cleartext: CONNECT keeps the decoy.
  Forward,
  /// The server leg is TLS.
  Swap { label: String, auth: NatsAuth },
}

impl Policy {
  fn swap(&self, line: &[u8]) -> Option<(Vec<u8>, Hit)> {
    let Self::Swap { label, auth } = self else {
      return None;
    };
    let swapped = swap_connect(line, auth)?;
    Some((
      swapped,
      Hit {
        label: label.clone(),
        location: Location::Header,
      },
    ))
  }
}

/// The CONNECT fields one auth kind owns.
fn auth_fields(auth: &NatsAuth) -> Vec<(&'static str, &NatsPair)> {
  match auth {
    NatsAuth::UserPass { user, pass } => vec![("user", user), ("pass", pass)],
    NatsAuth::Token(token) => vec![("auth_token", token)],
  }
}

/// `line` with the real values, when its JSON parses and every auth field
/// holds the decoy. `None` forwards the line unchanged.
fn swap_connect(line: &[u8], auth: &NatsAuth) -> Option<Vec<u8>> {
  let body = line.strip_suffix(b"\n")?;
  let body = body.strip_suffix(b"\r").unwrap_or(body);
  let ending = line.get(body.len()..)?;
  let verb_end = body.iter().position(|byte| is_delimiter(*byte))?;
  let (verb, args) = body.split_at_checked(verb_end)?;
  let json_at = args.iter().position(|byte| !is_delimiter(*byte))?;
  let (gap, json) = args.split_at_checked(json_at)?;
  let mut fields: Map<String, Value> = serde_json::from_slice(json).ok()?;
  let pairs = auth_fields(auth);
  let all_decoys = pairs
    .iter()
    .all(|(field, pair)| fields.get(*field).and_then(Value::as_str) == Some(pair.fake.as_str()));
  if !all_decoys {
    return None;
  }
  for (field, pair) in pairs {
    fields.insert(field.to_string(), Value::String(pair.real.expose_secret().to_string()));
  }
  // fnox pulls in serde_json `preserve_order` for workspace builds only, so
  // the key order is fixed here instead of depending on feature unification.
  let sorted: BTreeMap<&str, &Value> = fields.iter().map(|(key, value)| (key.as_str(), value)).collect();
  let json = serde_json::to_vec(&sorted).ok()?;
  let mut out = Vec::with_capacity(line.len().saturating_add(json.len()));
  out.extend_from_slice(verb);
  out.extend_from_slice(gap);
  out.extend_from_slice(&json);
  out.extend_from_slice(ending);
  Some(out)
}

/// Guest-to-server state.
#[derive(Debug)]
pub(crate) struct Down {
  framer: Framer,
  policy: Policy,
  /// CONNECT bytes so far. The line leaves whole once its LF arrives.
  connect: Vec<u8>,
}

impl Down {
  /// Empty input is end of stream: a held verb or a partial CONNECT leaves
  /// unchanged. A partial CONNECT is never swapped.
  fn feed(&mut self, chunk: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, CloseLeg> {
    if chunk.is_empty() {
      let mut out = std::mem::take(&mut self.connect);
      out.append(&mut self.framer.take_head());
      return Ok(out);
    }
    let mut input = chunk;
    let mut out = Vec::new();
    loop {
      match self.framer.next_piece(&mut input) {
        Next::Spent => return Ok(out),
        Next::Malformed => return Err(CloseLeg),
        Next::Piece(Piece::Line {
          framing: Framing::Credential,
          bytes,
          end,
        }) => {
          if self.connect.len().saturating_add(bytes.len()) > MAX_COMMAND {
            return Err(CloseLeg);
          }
          self.connect.extend_from_slice(&bytes);
          if end {
            let line = std::mem::take(&mut self.connect);
            match self.policy.swap(&line) {
              Some((swapped, hit)) => {
                out.extend_from_slice(&swapped);
                hits.push(hit);
              }
              None => out.extend_from_slice(&line),
            }
          }
        }
        Next::Piece(Piece::Line {
          framing: Framing::Counted | Framing::Line,
          bytes,
          ..
        }) => out.extend_from_slice(&bytes),
        Next::Piece(Piece::Body { bytes, .. }) => out.extend_from_slice(bytes),
      }
    }
  }
}

/// Server-to-guest state.
pub(crate) struct Up {
  framer: Framer,
  /// Delimited lines, flushed at each LF.
  lines: Raw,
  /// Counted heads and payloads.
  guard: Guard,
}

impl Up {
  /// Empty input is end of stream: nothing is held at a frame boundary, and
  /// a stream that ends mid-frame closes.
  async fn feed(&mut self, chunk: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, CloseLeg> {
    if chunk.is_empty() {
      return if self.framer.at_boundary() { Ok(Vec::new()) } else { Err(CloseLeg) };
    }
    let mut input = chunk;
    let mut out = Vec::new();
    loop {
      match self.framer.next_piece(&mut input) {
        Next::Spent => return Ok(out),
        Next::Malformed => return Err(CloseLeg),
        Next::Piece(Piece::Line {
          framing: Framing::Counted,
          bytes,
          ..
        }) => self.guard.push(&bytes, &mut out)?,
        Next::Piece(Piece::Line {
          framing: Framing::Line | Framing::Credential,
          bytes,
          end,
        }) => {
          if !bytes.is_empty() {
            redact(&mut self.lines, &bytes, &mut out, hits).await?;
          }
          if end {
            redact(&mut self.lines, &[], &mut out, hits).await?;
          }
        }
        Next::Piece(Piece::Body { bytes, end }) => {
          self.guard.push(bytes, &mut out)?;
          if end {
            self.guard.release(&mut out);
          }
        }
      }
    }
  }
}

/// Feed one line piece through the redactor. Empty `bytes` flushes it.
async fn redact(lines: &mut Raw, bytes: &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), CloseLeg> {
  let (rewritten, found) = lines.feed(bytes).await;
  hits.extend(found);
  match rewritten {
    Rewritten::Emit(emitted) => {
      out.extend_from_slice(&emitted);
      Ok(())
    }
    Rewritten::Hold => Ok(()),
    Rewritten::Close => Err(CloseLeg),
  }
}

/// Needle scan over counted bytes. A payload is the publisher's data, so it
/// is never rewritten: the real value there closes the leg.
struct Guard {
  pairs: Vec<CredentialPair>,
  bound: usize,
  /// Suffix that could still grow into a real value.
  held: Vec<u8>,
}

impl Guard {
  fn push(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), CloseLeg> {
    if data.is_empty() {
      return Ok(());
    }
    let mut combined = std::mem::take(&mut self.held);
    combined.extend_from_slice(data);
    if self.pairs.iter().any(|pair| find_new_match(&combined, &pair.needle, 0)) {
      return Err(CloseLeg);
    }
    let hold = needle_prefix_suffix_len(&combined, &self.pairs, self.bound);
    let emit = combined.len().saturating_sub(hold);
    self.held = combined.split_off(emit);
    out.append(&mut combined);
    Ok(())
  }

  /// The frame ended, so its held suffix cannot grow.
  fn release(&mut self, out: &mut Vec<u8>) {
    out.append(&mut self.held);
  }
}

#[cfg(test)]
pub(crate) mod tests {
  use arkham_config::grants::{Credential, Grant, NatsAuth, NatsScope};
  use pretty_assertions::assert_eq;

  use super::{MAX_COMMAND, Nats};
  use crate::transports::engine::{Rewritten, Wire};

  const FAKE_PASS: &str = "arkham_fake_nats_pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-nats-pass-is-longer"; // betterleaks:allow
  const FAKE_TOKEN: &str = "arkham_fake_nats_token"; // betterleaks:allow
  const REAL_TOKEN: &str = "real-nats-token"; // betterleaks:allow

  pub(crate) fn nats_grants(fake: &str, real: &str) -> Vec<Grant> {
    let scope = NatsScope::from_strings(fake, real).expect("nats strings");
    let secret = match &scope.auth {
      NatsAuth::UserPass { pass, .. } => pass,
      NatsAuth::Token(token) => token,
    };
    vec![Grant::Nats {
      credential: Credential {
        label: "nats".into(),
        fake: secret.fake.clone(),
        value: secret.real.clone(),
      },
      scope: Box::new(scope),
    }]
  }

  fn user_pass() -> Vec<Grant> {
    nats_grants(
      &format!("nats://agent:{FAKE_PASS}@nats.internal:4222"),
      &format!("tls://agent:{REAL_PASS}@nats.upstream:4222"),
    )
  }

  fn token() -> Vec<Grant> {
    nats_grants(
      &format!("nats://{FAKE_TOKEN}@nats.internal:4222"),
      &format!("tls://{REAL_TOKEN}@nats.upstream:4222"),
    )
  }

  fn down(grants: &[Grant], swap: bool) -> Nats {
    Nats::downstream(grants, "nats.internal", 4222, swap)
  }

  fn up(grants: &[Grant]) -> Nats {
    Nats::upstream(grants, "nats.internal", 4222)
  }

  #[derive(Debug, PartialEq, Eq)]
  enum Out {
    Emit(String),
    Hold,
    Close,
  }

  /// One feed, as the relay sees it: what reaches the peer and how many hits.
  async fn feed(machine: &mut Nats, chunk: &[u8]) -> (Out, usize) {
    let (rewritten, hits) = machine.feed(chunk).await;
    let out = match rewritten {
      Rewritten::Emit(bytes) => Out::Emit(String::from_utf8_lossy(&bytes).into_owned()),
      Rewritten::Hold => Out::Hold,
      Rewritten::Close => Out::Close,
    };
    (out, hits.len())
  }

  fn emit(text: &str) -> Out {
    Out::Emit(text.to_string())
  }

  fn user_connect(user: &str, pass: &str) -> String {
    format!("CONNECT {{\"verbose\":false,\"user\":\"{user}\",\"pass\":\"{pass}\",\"name\":\"agent-app\"}}\r\n")
  }

  #[tokio::test]
  async fn cleartext_upstream_forwards_the_decoy_connect() {
    let grants = user_pass();
    let mut machine = down(&grants, false);
    let connect = user_connect("agent", FAKE_PASS);
    assert_eq!(feed(&mut machine, connect.as_bytes()).await, (emit(&connect), 0));
  }

  #[tokio::test]
  async fn tls_upstream_swaps_user_and_pass_in_connect() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let input = format!("{}PING\r\n", user_connect("agent", FAKE_PASS));
    let swapped = format!("CONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\nPING\r\n");
    assert_eq!(feed(&mut machine, input.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn tls_upstream_swaps_the_auth_token_with_a_lowercase_verb() {
    let grants = token();
    let mut machine = down(&grants, true);
    let input = format!("connect {{\"auth_token\":\"{FAKE_TOKEN}\",\"jwt\":\"eyJ0\",\"sig\":\"c2ln\"}}\r\n");
    let swapped = format!("connect {{\"auth_token\":\"{REAL_TOKEN}\",\"jwt\":\"eyJ0\",\"sig\":\"c2ln\"}}\r\n");
    assert_eq!(feed(&mut machine, input.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn connect_swaps_only_when_every_auth_field_is_the_decoy() {
    let grants = user_pass();
    for connect in [
      user_connect("someone-else", FAKE_PASS),
      format!("CONNECT {{\"user\":\"agent\",\"pass\":\"typed\",\"name\":\"{FAKE_PASS}\"}}\r\n"),
      format!("CONNECT {{\"user\":\"agent\",\"pass\":\"{FAKE_PASS}\"\r\n"),
    ] {
      let mut machine = down(&grants, true);
      assert_eq!(feed(&mut machine, connect.as_bytes()).await, (emit(&connect), 0), "{connect}");
    }
  }

  #[tokio::test]
  async fn partial_connect_at_eof_is_forwarded_unswapped() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let partial = format!("CONNECT {{\"user\":\"agent\",\"pass\":\"{FAKE_PASS}\"}}");
    assert_eq!(feed(&mut machine, partial.as_bytes()).await, (Out::Hold, 0));
    assert_eq!(feed(&mut machine, &[]).await, (emit(&partial), 0));
  }

  #[tokio::test]
  async fn pub_payload_streams_without_a_swap() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let payload = user_connect("agent", FAKE_PASS);
    let payload = payload.trim_end();
    let head = format!("PUB orders {}\r\n", payload.len());
    let (first, rest) = payload.split_at(20);
    assert_eq!(
      feed(&mut machine, format!("{head}{first}").as_bytes()).await,
      (emit(&format!("{head}{first}")), 0)
    );
    assert_eq!(
      feed(&mut machine, format!("{rest}\r\n").as_bytes()).await,
      (emit(&format!("{rest}\r\n")), 0)
    );
    let hpub = format!("HPUB orders 12 14\r\nNATS/1.0\r\n\r\nhi\r\n{}", user_connect("agent", FAKE_PASS));
    let swapped = format!(
      "HPUB orders 12 14\r\nNATS/1.0\r\n\r\nhi\r\nCONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\n"
    );
    assert_eq!(feed(&mut machine, hpub.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn message_holding_the_real_password_closes_the_server_leg() {
    let grants = user_pass();
    let mut machine = up(&grants);
    let head = format!("MSG orders 1 {}\r\n", REAL_PASS.len());
    let (first, rest) = REAL_PASS.split_at(9);
    assert_eq!(feed(&mut machine, format!("{head}{first}").as_bytes()).await, (emit(&head), 0));
    assert_eq!(feed(&mut machine, format!("{rest}\r\n").as_bytes()).await, (Out::Close, 0));
    assert_eq!(feed(&mut machine, b"PING\r\n").await, (Out::Close, 0));
    let mut machine = up(&grants);
    let hmsg = format!("HMSG orders 1 12 {}\r\nNATS/1.0\r\n\r\n{REAL_PASS}\r\n", 12 + REAL_PASS.len());
    assert_eq!(feed(&mut machine, hmsg.as_bytes()).await, (Out::Close, 0));
  }

  #[tokio::test]
  async fn server_lines_redact_the_real_password_and_messages_pass() {
    let grants = user_pass();
    let mut machine = up(&grants);
    let info = "INFO {\"server_id\":\"N1\",\"tls_required\":true}\r\n";
    assert_eq!(feed(&mut machine, info.as_bytes()).await, (emit(info), 0));
    let err = format!("-ERR 'bad pass {REAL_PASS}'\r\n");
    assert_eq!(
      feed(&mut machine, err.as_bytes()).await,
      (emit(&format!("-ERR 'bad pass {FAKE_PASS}'\r\n")), 1)
    );
    let msg = format!("MSG orders 1 {}\r\n{FAKE_PASS}\r\n+OK\r\n", FAKE_PASS.len());
    assert_eq!(feed(&mut machine, msg.as_bytes()).await, (emit(&msg), 0));
  }

  #[tokio::test]
  async fn eof_flushes_a_held_head_downstream_and_closes_mid_frame_upstream() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    assert_eq!(feed(&mut machine, b"PU").await, (Out::Hold, 0));
    assert_eq!(feed(&mut machine, &[]).await, (emit("PU"), 0));
    let mut machine = up(&grants);
    assert_eq!(feed(&mut machine, b"+OK\r\n").await, (emit("+OK\r\n"), 0));
    assert_eq!(feed(&mut machine, &[]).await, (Out::Hold, 0));
    let mut machine = up(&grants);
    assert_eq!(feed(&mut machine, b"MSG orders 1 5\r\nhe").await, (emit("MSG orders 1 5\r\nhe"), 0));
    assert_eq!(feed(&mut machine, &[]).await, (Out::Close, 0));
  }

  #[tokio::test]
  async fn counted_body_not_followed_by_crlf_closes() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let smuggled = format!("PUB orders 2\r\n{}", user_connect("agent", FAKE_PASS));
    assert_eq!(feed(&mut machine, smuggled.as_bytes()).await, (Out::Close, 0));
    let mut machine = up(&grants);
    assert_eq!(feed(&mut machine, b"MSG orders 1 2\r\nokXX").await, (Out::Close, 0));
    let mut machine = down(&grants, true);
    assert_eq!(feed(&mut machine, b"PUB orders\r\n").await, (Out::Close, 0));
  }

  #[tokio::test]
  async fn connect_longer_than_the_cap_closes() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let long = format!("CONNECT {{\"name\":\"{}\"", "a".repeat(MAX_COMMAND));
    assert_eq!(feed(&mut machine, long.as_bytes()).await, (Out::Close, 0));
  }
}
