//! SMTP wire format: AUTH credential rewrite, then line relay.
//!
//! Downstream client commands are CRLF lines. `AUTH PLAIN`, `AUTH LOGIN`,
//! `AUTH XOAUTH2`, and `AUTH OAUTHBEARER` reframe to the upstream spelling
//! at any length, inline or on the continuation line after a `334`. Every
//! other command relays unchanged. Upstream redacts the real password from
//! replies, including a base64 `334` challenge, so a refusal cannot carry
//! it back to the guest. The username is not a secret and is left as the
//! server wrote it. A `250` reply advertising `CHUNKING` loses that line,
//! so a client falls back to `DATA`; the session still splices a `BDAT`
//! payload when one arrives.
//!
//! `AUTH CRAM-MD5` and `AUTH DIGEST-MD5` are challenge-response mechanisms
//! and are relayed unchanged.

use std::borrow::Cow;

use arkham_config::grants::Grant;
use base64::Engine as _;
use secrecy::ExposeSecret as _;

use crate::transports::engine::{Direction, Hit, Location, Rewritten, Wire};

/// Cap for one buffered line. A real AUTH command is a few kilobytes;
/// anything past this is a drip or an attack, never an auth command.
const MAX_LINE: usize = 16 * 1024;

/// SASL field separator used by XOAUTH2 and OAUTHBEARER (RFC 7628).
const SASL_SEP: u8 = 0x01;

/// SMTP verbs that end an AUTH continuation when the client sends one
/// instead of a payload (the server refused, and the client moved on).
const COMMANDS: &[&[u8]] = &[
  b"EHLO",
  b"HELO",
  b"MAIL",
  b"RCPT",
  b"DATA",
  b"RSET",
  b"NOOP",
  b"QUIT",
  b"VRFY",
  b"EXPN",
  b"HELP",
  b"STARTTLS",
  b"AUTH",
  // The command line only. The session splices the following octet count.
  b"BDAT",
];

/// One SMTP direction leg.
pub(crate) struct Smtp {
  /// Parse state. `None` on a direction this leg does not own.
  down: Option<Down>,
  /// Response redaction. `None` on the request leg.
  up: Option<Up>,
}

/// Downstream parse state.
struct Down {
  buf: Vec<u8>,
  phase: Phase,
  /// AUTH payloads are rewritten. False while a `starttls=required`
  /// upstream is still in cleartext: the decoy is forwarded as-is.
  protected: bool,
  creds: Creds,
  closed: bool,
}

/// Upstream redaction state.
struct Up {
  buf: Vec<u8>,
  /// Lines of the current reply, held until the final line so a trailing
  /// `CHUNKING` advertisement can be dropped without leaving a `250-`.
  held: Vec<u8>,
  creds: Creds,
  closed: bool,
}

/// Where the next client line sits in an AUTH exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
  /// A command verb.
  Command,
  /// Base64 SASL PLAIN payload after a bare `AUTH PLAIN`.
  Plain,
  /// Base64 username after a bare `AUTH LOGIN`.
  LoginUser,
  /// Base64 password after the LOGIN username.
  LoginPass,
  /// Base64 XOAUTH2 or OAUTHBEARER payload after a bare `AUTH`.
  Bearer,
}

/// The credential pair one grant contributes to this connection.
struct Creds {
  fake_user: Vec<u8>,
  real_user: Vec<u8>,
  fake_pass: Vec<u8>,
  real_pass: Vec<u8>,
  label: String,
}

impl Smtp {
  /// Fresh leg. A direction with no covering grant splices.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    let creds = grants.iter().find_map(|grant| {
      let scope = grant.smtp(Some(host), port)?;
      Some(Creds {
        fake_user: scope.downstream.user.as_bytes().to_vec(),
        real_user: scope.upstream.user.as_bytes().to_vec(),
        fake_pass: scope.downstream.password.expose_secret().as_bytes().to_vec(),
        real_pass: scope.upstream.password.expose_secret().as_bytes().to_vec(),
        label: grant.credential().map(|credential| credential.label.clone()).unwrap_or_default(),
      })
    });
    match dir {
      Direction::Downstream => Self {
        down: creds.map(|creds| Down {
          buf: Vec::new(),
          phase: Phase::Command,
          protected: true,
          creds,
          closed: false,
        }),
        up: None,
      },
      Direction::Upstream => Self {
        down: None,
        up: creds.map(|creds| Up {
          buf: Vec::new(),
          held: Vec::new(),
          creds,
          closed: false,
        }),
      },
    }
  }

  /// Allow or withhold AUTH rewriting. A `starttls=required` session
  /// starts unprotected and becomes protected once the upstream leg is
  /// encrypted.
  pub(crate) fn set_protected(&mut self, protected: bool) {
    if let Some(down) = self.down.as_mut() {
      down.protected = protected;
    }
  }

  /// Feed one downstream chunk through the line parser.
  fn feed_down<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    let Some(down) = self.down.as_mut() else {
      return (Cow::Borrowed(chunk), Vec::new());
    };
    if chunk.is_empty() {
      let rest = std::mem::take(&mut down.buf);
      if rest.is_empty() {
        return (Cow::Borrowed(&[]), Vec::new());
      }
      let (line, hits) = rewrite_down_line(&rest, down);
      return (Cow::Owned(line), hits);
    }
    down.buf.extend_from_slice(chunk);
    if down.buf.len() > MAX_LINE && line_end(&down.buf).is_none() {
      down.closed = true;
      return (Cow::Borrowed(&[]), Vec::new());
    }
    let mut out = Vec::new();
    let mut hits = Vec::new();
    while let Some(end) = line_end(&down.buf) {
      let line: Vec<u8> = down.buf.drain(..end).collect();
      let (rewritten, found) = rewrite_down_line(&line, down);
      out.extend_from_slice(&rewritten);
      hits.extend(found);
      if down.closed {
        return (Cow::Owned(out), hits);
      }
    }
    (Cow::Owned(out), hits)
  }

  /// Feed one upstream chunk through response redaction.
  fn feed_up<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    let Some(up) = self.up.as_mut() else {
      return (Cow::Borrowed(chunk), Vec::new());
    };
    if chunk.is_empty() {
      let mut pending = std::mem::take(&mut up.held);
      pending.append(&mut up.buf);
      if pending.is_empty() {
        return (Cow::Borrowed(&[]), Vec::new());
      }
      let (line, hits) = redact_reply(&pending, &up.creds);
      return (Cow::Owned(line), hits);
    }
    up.buf.extend_from_slice(chunk);
    if up.buf.len() > MAX_LINE && line_end(&up.buf).is_none() {
      up.closed = true;
      return (Cow::Borrowed(&[]), Vec::new());
    }
    let mut out = Vec::new();
    let mut hits = Vec::new();
    while let Some(end) = line_end(&up.buf) {
      let line: Vec<u8> = up.buf.drain(..end).collect();
      let finished = is_final_reply_line(&line);
      up.held.extend_from_slice(&line);
      if finished {
        let reply = std::mem::take(&mut up.held);
        let (redacted, found) = redact_reply(&reply, &up.creds);
        out.extend_from_slice(&redacted);
        hits.extend(found);
      }
    }
    (Cow::Owned(out), hits)
  }
}

impl Wire for Smtp {
  fn feed<'a>(&mut self, chunk: &'a [u8]) -> impl Future<Output = (Rewritten<'a>, Vec<Hit>)> + Send {
    let (out, hits) = if self.down.is_some() {
      self.feed_down(chunk)
    } else if self.up.is_some() {
      self.feed_up(chunk)
    } else {
      (Cow::Borrowed(chunk), Vec::new())
    };
    let closed = self.down.as_ref().is_some_and(|down| down.closed) || self.up.as_ref().is_some_and(|up| up.closed);
    let rewritten = if closed {
      Rewritten::Close
    } else if out.is_empty() && !chunk.is_empty() {
      Rewritten::Hold
    } else {
      Rewritten::Emit(out)
    };
    std::future::ready((rewritten, hits))
  }
}

/// Rewrite one complete downstream line and advance the AUTH phase.
fn rewrite_down_line(line: &[u8], down: &mut Down) -> (Vec<u8>, Vec<Hit>) {
  let body = line_body(line);
  if body == b"*" {
    down.phase = Phase::Command;
    return (line.to_vec(), Vec::new());
  }
  if down.phase != Phase::Command && is_command(body) {
    down.phase = Phase::Command;
  }
  match down.phase {
    Phase::Plain => {
      down.phase = Phase::Command;
      rewrite_plain_line(line, &down.creds, down.protected)
    }
    Phase::LoginUser => {
      down.phase = Phase::LoginPass;
      rewrite_token_line(line, &down.creds.fake_user, &down.creds.real_user, &down.creds, down.protected)
    }
    Phase::LoginPass => {
      down.phase = Phase::Command;
      rewrite_token_line(line, &down.creds.fake_pass, &down.creds.real_pass, &down.creds, down.protected)
    }
    Phase::Bearer => {
      down.phase = Phase::Command;
      rewrite_bearer_line(line, &down.creds, down.protected)
    }
    Phase::Command => rewrite_command(line, down),
  }
}

/// A command line, or an `AUTH` line with its mechanism and initial response.
fn rewrite_command(line: &[u8], down: &mut Down) -> (Vec<u8>, Vec<Hit>) {
  let body = line_body(line);
  let ending = line_ending(line);
  let tokens = tokens(body);
  let Some(verb) = tokens.first() else {
    return (line.to_vec(), Vec::new());
  };
  if !verb.eq_ignore_ascii_case(b"AUTH") {
    return (line.to_vec(), Vec::new());
  }
  let Some(mech) = tokens.get(1) else {
    return (line.to_vec(), Vec::new());
  };
  let initial = tokens.get(2).copied().filter(|arg| *arg != b"=");
  if mech.eq_ignore_ascii_case(b"PLAIN") {
    let Some(arg) = initial else {
      down.phase = Phase::Plain;
      return (line.to_vec(), Vec::new());
    };
    return rewrite_auth_arg(line, mech, arg, ending, &down.creds, down.protected, rewrite_plain_raw);
  }
  if mech.eq_ignore_ascii_case(b"LOGIN") {
    let Some(arg) = initial else {
      down.phase = Phase::LoginUser;
      return (line.to_vec(), Vec::new());
    };
    let (rewritten, hits) = rewrite_token_line(
      &join_line(arg, ending),
      &down.creds.fake_user,
      &down.creds.real_user,
      &down.creds,
      down.protected,
    );
    down.phase = Phase::LoginPass;
    let arg_body = line_body(&rewritten);
    return (join_auth(mech, Some(arg_body), ending), hits);
  }
  if mech.eq_ignore_ascii_case(b"XOAUTH2") || mech.eq_ignore_ascii_case(b"OAUTHBEARER") {
    let Some(arg) = initial else {
      down.phase = Phase::Bearer;
      return (line.to_vec(), Vec::new());
    };
    return rewrite_auth_arg(line, mech, arg, ending, &down.creds, down.protected, rewrite_bearer_raw);
  }
  (line.to_vec(), Vec::new())
}

/// Replace the initial-response argument of an `AUTH` line.
fn rewrite_auth_arg(
  line: &[u8],
  mech: &[u8],
  arg: &[u8],
  ending: &[u8],
  creds: &Creds,
  protected: bool,
  rewrite: fn(&[u8], &Creds, bool) -> Option<Vec<u8>>,
) -> (Vec<u8>, Vec<Hit>) {
  let Some(raw) = b64_decode(arg) else {
    return (line.to_vec(), Vec::new());
  };
  let Some(rewritten) = rewrite(&raw, creds, protected) else {
    return (line.to_vec(), Vec::new());
  };
  (join_auth(mech, Some(&b64_encode(&rewritten)), ending), vec![hit(creds)])
}

/// A continuation line carrying a SASL PLAIN payload.
fn rewrite_plain_line(line: &[u8], creds: &Creds, protected: bool) -> (Vec<u8>, Vec<Hit>) {
  let body = line_body(line);
  let Some(raw) = b64_decode(body) else {
    return (line.to_vec(), Vec::new());
  };
  let Some(rewritten) = rewrite_plain_raw(&raw, creds, protected) else {
    return (line.to_vec(), Vec::new());
  };
  let mut out = b64_encode(&rewritten);
  out.extend_from_slice(line_ending(line));
  (out, vec![hit(creds)])
}

/// A continuation line whose whole payload is one token (LOGIN user or password).
fn rewrite_token_line(line: &[u8], from: &[u8], to: &[u8], creds: &Creds, protected: bool) -> (Vec<u8>, Vec<Hit>) {
  if !protected || from == to {
    return (line.to_vec(), Vec::new());
  }
  let Some(raw) = b64_decode(line_body(line)) else {
    return (line.to_vec(), Vec::new());
  };
  if raw.as_slice() != from {
    return (line.to_vec(), Vec::new());
  }
  let mut out = b64_encode(to);
  out.extend_from_slice(line_ending(line));
  (out, vec![hit(creds)])
}

/// A continuation line carrying an XOAUTH2 or OAUTHBEARER payload.
fn rewrite_bearer_line(line: &[u8], creds: &Creds, protected: bool) -> (Vec<u8>, Vec<Hit>) {
  let Some(raw) = b64_decode(line_body(line)) else {
    return (line.to_vec(), Vec::new());
  };
  let Some(rewritten) = rewrite_bearer_raw(&raw, creds, protected) else {
    return (line.to_vec(), Vec::new());
  };
  let mut out = b64_encode(&rewritten);
  out.extend_from_slice(line_ending(line));
  (out, vec![hit(creds)])
}

/// SASL PLAIN: `authzid NUL authcid NUL password`.
fn rewrite_plain_raw(raw: &[u8], creds: &Creds, protected: bool) -> Option<Vec<u8>> {
  if !protected {
    return None;
  }
  let (zid, cid, pass) = split_plain(raw)?;
  let mut cid_out = cid.to_vec();
  let mut pass_out = pass.to_vec();
  let mut hit = false;
  if pass == creds.fake_pass.as_slice() && creds.fake_pass != creds.real_pass {
    pass_out.clone_from(&creds.real_pass);
    hit = true;
  }
  if cid == creds.fake_user.as_slice() && creds.fake_user != creds.real_user {
    cid_out.clone_from(&creds.real_user);
    hit = true;
  }
  if !hit {
    return None;
  }
  let mut out = Vec::with_capacity(
    zid
      .len()
      .saturating_add(cid_out.len())
      .saturating_add(pass_out.len())
      .saturating_add(2),
  );
  out.extend_from_slice(zid);
  out.push(0);
  out.extend_from_slice(&cid_out);
  out.push(0);
  out.extend_from_slice(&pass_out);
  Some(out)
}

/// XOAUTH2 (`user=…\x01auth=Bearer …\x01\x01`) and OAUTHBEARER
/// (`n,a=…,\x01…auth=Bearer …\x01\x01`). The bearer token is the password.
fn rewrite_bearer_raw(raw: &[u8], creds: &Creds, protected: bool) -> Option<Vec<u8>> {
  if !protected {
    return None;
  }
  let mut spans: Vec<(usize, usize, Vec<u8>)> = Vec::new();
  if creds.fake_pass != creds.real_pass
    && let Some(pos) = find_sub(raw, b"auth=Bearer ")
  {
    let start = pos.saturating_add(b"auth=Bearer ".len());
    let end = raw[start..]
      .iter()
      .position(|byte| *byte == SASL_SEP)
      .map_or(raw.len(), |at| start.saturating_add(at));
    if raw.get(start..end) == Some(creds.fake_pass.as_slice()) {
      spans.push((start, end, creds.real_pass.clone()));
    }
  }
  if creds.fake_user != creds.real_user {
    if let Some(pos) = find_sub(raw, b"user=") {
      let start = pos.saturating_add(b"user=".len());
      let end = raw[start..]
        .iter()
        .position(|byte| *byte == SASL_SEP)
        .map_or(raw.len(), |at| start.saturating_add(at));
      if raw.get(start..end) == Some(creds.fake_user.as_slice()) {
        spans.push((start, end, creds.real_user.clone()));
      }
    }
    if let Some(pos) = find_sub(raw, b"n,a=") {
      let start = pos.saturating_add(b"n,a=".len());
      let end = raw[start..]
        .iter()
        .position(|byte| *byte == b',' || *byte == SASL_SEP)
        .map_or(raw.len(), |at| start.saturating_add(at));
      if raw.get(start..end) == Some(creds.fake_user.as_slice()) {
        spans.push((start, end, creds.real_user.clone()));
      }
    }
  }
  if spans.is_empty() {
    return None;
  }
  spans.sort_by_key(|(start, _, _)| *start);
  let mut out = raw.to_vec();
  for (start, end, repl) in spans.into_iter().rev() {
    if start <= end && end <= out.len() {
      out.splice(start..end, repl);
    }
  }
  Some(out)
}

/// Redact one complete reply. `CHUNKING` is dropped first so the final
/// line still uses a space separator, then each line redacts the password.
fn redact_reply(reply: &[u8], creds: &Creds) -> (Vec<u8>, Vec<Hit>) {
  let stripped = strip_chunking(reply);
  let mut out = Vec::with_capacity(stripped.len());
  let mut hits = Vec::new();
  let mut rest = stripped.as_slice();
  while !rest.is_empty() {
    let end = line_end(rest).unwrap_or(rest.len());
    let Some(line_bytes) = rest.get(..end) else {
      break;
    };
    let (line, found) = redact_line(line_bytes, creds);
    out.extend_from_slice(&line);
    hits.extend(found);
    if end == rest.len() {
      break;
    }
    rest = rest.get(end..).unwrap_or(&[]);
  }
  (out, hits)
}

/// Drop `250 CHUNKING` advertisements. When the dropped line was the
/// final one, the new last line's `-` becomes a space so the reply ends.
fn strip_chunking(reply: &[u8]) -> Vec<u8> {
  let mut lines = Vec::new();
  let mut rest = reply;
  while !rest.is_empty() {
    let end = line_end(rest).unwrap_or(rest.len());
    let line = rest.get(..end).unwrap_or(&[]);
    if !is_chunking_advertisement(line) {
      lines.push(line.to_vec());
    }
    if end == rest.len() {
      break;
    }
    rest = rest.get(end..).unwrap_or(&[]);
  }
  if lines.is_empty() {
    return reply.to_vec();
  }
  if let Some(last) = lines.last_mut()
    && let Some(separator) = last.get_mut(3)
    && *separator == b'-'
  {
    *separator = b' ';
  }
  let mut out = Vec::with_capacity(reply.len());
  for line in &lines {
    out.extend_from_slice(line);
  }
  out
}

/// `250 CHUNKING` or `250-CHUNKING`, and nothing else on the line.
fn is_chunking_advertisement(line: &[u8]) -> bool {
  let body = line_body(line);
  if body.get(..3) != Some(b"250".as_slice()) {
    return false;
  }
  let rest = body.get(4..).unwrap_or(b"");
  let keyword = rest
    .split(|byte| *byte == b' ' || *byte == b'\t')
    .find(|part| !part.is_empty())
    .unwrap_or(b"");
  keyword.eq_ignore_ascii_case(b"CHUNKING")
}

/// A reply line is final when it is not a `DDD-` continuation.
fn is_final_reply_line(line: &[u8]) -> bool {
  line_body(line).get(3) != Some(&b'-')
}

/// Redact one server line. A `334` challenge is base64; the password is
/// replaced inside the payload and the line is re-encoded.
fn redact_line(line: &[u8], creds: &Creds) -> (Vec<u8>, Vec<Hit>) {
  let body = line_body(line);
  let ending = line_ending(line);
  if let Some(payload) = body.strip_prefix(b"334 ").filter(|payload| !payload.is_empty())
    && let Some(decoded) = b64_decode(payload)
  {
    let (redacted, found) = replace_secrets(&decoded, creds);
    if found {
      let mut out = b"334 ".to_vec();
      out.extend_from_slice(&b64_encode(&redacted));
      out.extend_from_slice(ending);
      return (out, vec![hit(creds)]);
    }
  }
  let (redacted, found) = replace_secrets(line, creds);
  if found {
    (redacted, vec![hit(creds)])
  } else {
    (line.to_vec(), Vec::new())
  }
}

/// Replace the real password. The username is not redacted: a short or
/// common one would rewrite unrelated reply text.
fn replace_secrets(buf: &[u8], creds: &Creds) -> (Vec<u8>, bool) {
  let mut out = buf.to_vec();
  let found = creds.real_pass != creds.fake_pass && replace_into(&mut out, &creds.real_pass, &creds.fake_pass);
  (out, found)
}

/// Replace every non-overlapping occurrence. Returns whether any matched.
fn replace_into(buf: &mut Vec<u8>, needle: &[u8], replacement: &[u8]) -> bool {
  if needle.is_empty() || find_sub(buf, needle).is_none() {
    return false;
  }
  let mut out = Vec::with_capacity(buf.len());
  let mut index = 0;
  while let Some(at) = find_sub(&buf[index..], needle) {
    let pos = index.saturating_add(at);
    out.extend_from_slice(&buf[index..pos]);
    out.extend_from_slice(replacement);
    index = pos.saturating_add(needle.len());
  }
  out.extend_from_slice(&buf[index..]);
  *buf = out;
  true
}

fn hit(creds: &Creds) -> Hit {
  Hit {
    label: creds.label.clone(),
    location: Location::BasicAuth,
  }
}

/// Three NUL-separated SASL PLAIN fields.
fn split_plain(raw: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
  let mut parts = raw.split(|byte| *byte == 0);
  let zid = parts.next()?;
  let cid = parts.next()?;
  let pass = parts.next()?;
  parts.next().is_none().then_some((zid, cid, pass))
}

fn b64_decode(text: &[u8]) -> Option<Vec<u8>> {
  let text = trim_ascii(text);
  if text.is_empty() || text == b"=" {
    return None;
  }
  base64::engine::general_purpose::STANDARD
    .decode(text)
    .ok()
    .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text).ok())
}

fn b64_encode(raw: &[u8]) -> Vec<u8> {
  base64::engine::general_purpose::STANDARD.encode(raw).into_bytes()
}

fn join_auth(mech: &[u8], arg: Option<&[u8]>, ending: &[u8]) -> Vec<u8> {
  let mut out = b"AUTH ".to_vec();
  out.extend_from_slice(mech);
  if let Some(arg) = arg {
    out.push(b' ');
    out.extend_from_slice(arg);
  }
  out.extend_from_slice(ending);
  out
}

fn join_line(body: &[u8], ending: &[u8]) -> Vec<u8> {
  let mut out = body.to_vec();
  out.extend_from_slice(ending);
  out
}

fn tokens(body: &[u8]) -> Vec<&[u8]> {
  body
    .split(|byte| *byte == b' ' || *byte == b'\t')
    .filter(|token| !token.is_empty())
    .collect()
}

fn is_command(body: &[u8]) -> bool {
  let verb = tokens(body).into_iter().next().unwrap_or_default();
  COMMANDS.iter().any(|command| verb.eq_ignore_ascii_case(command))
}

/// Index just past the line ending, when `buf` holds one.
fn line_end(buf: &[u8]) -> Option<usize> {
  buf.iter().position(|byte| *byte == b'\n').map(|at| at.saturating_add(1))
}

fn line_body(line: &[u8]) -> &[u8] {
  line.strip_suffix(b"\r\n").or_else(|| line.strip_suffix(b"\n")).unwrap_or(line)
}

fn line_ending(line: &[u8]) -> &[u8] {
  if line.ends_with(b"\r\n") {
    b"\r\n"
  } else if line.ends_with(b"\n") {
    b"\n"
  } else {
    b""
  }
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || hay.len() < needle.len() {
    return None;
  }
  hay.windows(needle.len()).position(|window| window == needle)
}

fn trim_ascii(text: &[u8]) -> &[u8] {
  let start = text.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(text.len());
  let end = text
    .iter()
    .rposition(|byte| !byte.is_ascii_whitespace())
    .map_or(start, |at| at.saturating_add(1));
  text.get(start..end).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, GuestTlsMode, SmtpLeg, SmtpScope};
  use secrecy::SecretString;

  const FAKE_USER: &str = "agent@demo.test";
  const REAL_USER: &str = "agent@demo.test";
  const FAKE_PASS: &str = "fake-smtp-pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-smtp-pass"; // betterleaks:allow

  fn scope(fake_user: &str, real_user: &str) -> SmtpScope {
    SmtpScope {
      downstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: fake_user.into(),
        password: SecretString::from(FAKE_PASS),
      },
      is_downstream_tls: false,
      upstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: real_user.into(),
        password: SecretString::from(REAL_PASS),
      },
      is_upstream_tls: false,
      starttls_required: true,
      root_cert: None,
      client_cert: None,
      client_key: None,
      guest_tls: GuestTlsMode::default(),
    }
  }

  fn grant(fake_user: &str, real_user: &str) -> Vec<Grant> {
    vec![Grant::Smtp {
      credential: Credential {
        label: "smtp".into(),
        fake: FAKE_PASS.into(),
        value: SecretString::from(REAL_PASS),
      },
      scope: Box::new(scope(fake_user, real_user)),
    }]
  }

  fn down() -> Smtp {
    let mut machine = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Downstream);
    machine.set_protected(true);
    machine
  }

  fn up() -> Smtp {
    Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Upstream)
  }

  async fn emit(machine: &mut Smtp, chunk: &[u8]) -> (Vec<u8>, usize) {
    match machine.feed(chunk).await {
      (Rewritten::Emit(bytes), hits) => (bytes.into_owned(), hits.len()),
      (Rewritten::Hold, hits) => (Vec::new(), hits.len()),
      (Rewritten::Close, _) => panic!("line closed the machine"),
    }
  }

  fn plain(user: &str, pass: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"))
  }

  #[tokio::test]
  async fn plain_inline_swaps_the_password() {
    let mut machine = down();
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("AUTH PLAIN {}\r\n", plain(REAL_USER, REAL_PASS)).into_bytes());
  }

  #[tokio::test]
  async fn plain_inline_swaps_a_different_user() {
    let mut machine = Smtp::new(&grant("guest@demo.test", "real@demo.test"), "mail", 587, Direction::Downstream);
    machine.set_protected(true);
    let line = format!("AUTH PLAIN {}\r\n", plain("guest@demo.test", FAKE_PASS));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("AUTH PLAIN {}\r\n", plain("real@demo.test", REAL_PASS)).into_bytes());
  }

  #[tokio::test]
  async fn plain_continuation_swaps_the_second_line() {
    let mut machine = down();
    let (cmd, hits) = emit(&mut machine, b"AUTH PLAIN\r\n").await;
    assert_eq!(cmd, b"AUTH PLAIN\r\n");
    assert_eq!(hits, 0);
    let payload = format!("{}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (out, hits) = emit(&mut machine, payload.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("{}\r\n", plain(REAL_USER, REAL_PASS)).into_bytes());
  }

  #[tokio::test]
  async fn plain_before_protect_is_forwarded_unchanged() {
    let mut machine = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Downstream);
    machine.set_protected(false);
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_eq!(out, line.as_bytes());
  }

  #[tokio::test]
  async fn login_two_step_swaps_the_password_line() {
    let mut machine = down();
    let (cmd, _) = emit(&mut machine, b"AUTH LOGIN\r\n").await;
    assert_eq!(cmd, b"AUTH LOGIN\r\n");
    let user = base64::engine::general_purpose::STANDARD.encode(FAKE_USER);
    let (user_out, user_hits) = emit(&mut machine, format!("{user}\r\n").as_bytes()).await;
    assert_eq!(user_hits, 0, "the same user is not a hit");
    assert_eq!(user_out, format!("{user}\r\n").into_bytes());
    let pass = base64::engine::general_purpose::STANDARD.encode(FAKE_PASS);
    let (out, hits) = emit(&mut machine, format!("{pass}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let real = base64::engine::general_purpose::STANDARD.encode(REAL_PASS);
    assert_eq!(out, format!("{real}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn login_inline_username_then_password() {
    let mut machine = down();
    let user = base64::engine::general_purpose::STANDARD.encode(FAKE_USER);
    let (cmd, _) = emit(&mut machine, format!("AUTH LOGIN {user}\r\n").as_bytes()).await;
    assert_eq!(cmd, format!("AUTH LOGIN {user}\r\n").into_bytes());
    let pass = base64::engine::general_purpose::STANDARD.encode(FAKE_PASS);
    let (out, hits) = emit(&mut machine, format!("{pass}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let real = base64::engine::general_purpose::STANDARD.encode(REAL_PASS);
    assert_eq!(out, format!("{real}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn xoauth2_swaps_the_bearer() {
    let mut machine = down();
    let raw = format!("user={FAKE_USER}\x01auth=Bearer {FAKE_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    let (out, hits) = emit(&mut machine, format!("AUTH XOAUTH2 {encoded}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let expect = format!("user={REAL_USER}\x01auth=Bearer {REAL_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(expect.as_bytes());
    assert_eq!(out, format!("AUTH XOAUTH2 {encoded}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn oauthbearer_swaps_the_bearer() {
    let mut machine = Smtp::new(&grant("guest@demo.test", "real@demo.test"), "mail", 587, Direction::Downstream);
    machine.set_protected(true);
    let raw = format!("n,a=guest@demo.test,\x01host=mail\x01auth=Bearer {FAKE_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    let (out, hits) = emit(&mut machine, format!("AUTH OAUTHBEARER {encoded}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let expect = format!("n,a=real@demo.test,\x01host=mail\x01auth=Bearer {REAL_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(expect.as_bytes());
    assert_eq!(out, format!("AUTH OAUTHBEARER {encoded}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn wrong_password_is_unchanged() {
    let mut machine = down();
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, "not-the-decoy"));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_eq!(out, line.as_bytes());
    assert!(!out.windows(REAL_PASS.len()).any(|window| window == REAL_PASS.as_bytes()));
  }

  #[tokio::test]
  async fn cram_md5_is_forwarded() {
    let mut machine = down();
    let line = b"AUTH CRAM-MD5\r\n";
    let (out, hits) = emit(&mut machine, line).await;
    assert_eq!(hits, 0);
    assert_eq!(out, line);
  }

  #[tokio::test]
  async fn star_cancels_and_the_next_command_is_a_command() {
    let mut machine = down();
    let _ = emit(&mut machine, b"AUTH PLAIN\r\n").await;
    let (cancel, _) = emit(&mut machine, b"*\r\n").await;
    assert_eq!(cancel, b"*\r\n");
    let (ehlo, hits) = emit(&mut machine, b"EHLO client\r\n").await;
    assert_eq!(hits, 0);
    assert_eq!(ehlo, b"EHLO client\r\n");
  }

  #[tokio::test]
  async fn response_redacts_the_real_password() {
    let mut machine = up();
    let line = format!("535 5.7.8 authentication failed for {REAL_PASS}\r\n");
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("535 5.7.8 authentication failed for {FAKE_PASS}\r\n").into_bytes());
    assert!(!out.windows(REAL_PASS.len()).any(|window| window == REAL_PASS.as_bytes()));
  }

  #[tokio::test]
  async fn response_redacts_the_password_and_leaves_the_username() {
    let mut machine = Smtp::new(&grant("guest@demo.test", "a"), "mail", 587, Direction::Upstream);
    let line = format!("535 5.7.8 a rejected {REAL_PASS}\r\n");
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("535 5.7.8 a rejected"), "{text}");
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(REAL_PASS), "{text}");
  }

  #[tokio::test]
  async fn ehlo_reply_drops_chunking_and_keeps_a_final_line() {
    let mut machine = up();
    let reply = b"250-mail.demo.test\r\n250-PIPELINING\r\n250 CHUNKING\r\n";
    let (out, hits) = emit(&mut machine, reply).await;
    assert_eq!(hits, 0);
    assert_eq!(out, b"250-mail.demo.test\r\n250 PIPELINING\r\n");
  }

  #[tokio::test]
  async fn chunking_in_the_middle_of_ehlo_is_dropped() {
    let mut machine = up();
    let (held, _) = emit(&mut machine, b"250-CHUNKING\r\n").await;
    assert_eq!(held, b"");
    let (out, _) = emit(&mut machine, b"250 AUTH PLAIN LOGIN\r\n").await;
    assert_eq!(out, b"250 AUTH PLAIN LOGIN\r\n");
  }

  #[tokio::test]
  async fn challenge_334_redacts_a_base64_token() {
    let mut machine = up();
    let payload = format!("{{\"status\":\"400\",\"scope\":\"{REAL_PASS}\"}}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let (out, hits) = emit(&mut machine, format!("334 {encoded}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let text = String::from_utf8(out).unwrap();
    let b64 = text.trim().strip_prefix("334 ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    let decoded = String::from_utf8(decoded).unwrap();
    assert!(decoded.contains(FAKE_PASS), "{decoded}");
    assert!(!decoded.contains(REAL_PASS), "{decoded}");
  }

  #[tokio::test]
  async fn a_command_split_across_chunks_rewrites_whole() {
    let mut machine = down();
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (first, _) = emit(&mut machine, &line.as_bytes()[..8]).await;
    assert_eq!(first.as_slice(), b"");
    let (rest, hits) = emit(&mut machine, &line.as_bytes()[8..]).await;
    assert_eq!(hits, 1);
    assert_eq!(rest, format!("AUTH PLAIN {}\r\n", plain(REAL_USER, REAL_PASS)).into_bytes());
  }

  mod arbitrary {
    use super::*;
    use proptest::prelude::*;

    proptest! {
      #[test]
      fn arbitrary_bytes_do_not_panic(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..80), 0..6)) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
          let mut down = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Downstream);
          down.set_protected(true);
          let mut up_leg = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Upstream);
          for chunk in &chunks {
            let _ = down.feed(chunk).await;
            let _ = up_leg.feed(chunk).await;
          }
          let _ = down.feed(&[]).await;
          let _ = up_leg.feed(&[]).await;
        });
      }
    }
  }
}
