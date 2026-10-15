//! Generated SMTP sessions through the two machines.
//!
//! One session is a list of downstream and upstream chunks. The same list
//! fed whole, at arbitrary cuts, and one byte at a time must emit the same
//! bytes. Guest-bound output never contains the real password. A reply cut
//! at any offset, including the old 16 KiB line boundary, still leaves the
//! next server reply for the following read.

use std::io::Cursor;

use arkham_config::grants::{Credential, Grant, GuestTlsMode, SmtpLeg, SmtpScope};
use base64::Engine as _;
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use secrecy::SecretString;

use super::machine::{MAX_COMMAND, Smtp};
use super::session::{GuestLeg, acceptance_reply, plain_guest};
use crate::transports::engine::{Direction, Rewritten, Wire};

const FAKE_USER: &str = "guest@demo.test";
const REAL_USER: &str = "owner@demo.test";

#[derive(Clone, Copy, Debug)]
enum Mech {
  Plain,
  Login,
  Xoauth2,
  Bearer,
}

enum Step {
  Down(Vec<u8>),
  Up(Vec<u8>),
}

struct Session {
  steps: Vec<Step>,
  real: String,
  fake: String,
  /// Bytes the swapped AUTH must place on the upstream wire.
  swapped: Vec<u8>,
  /// AUTH line planted in the DATA body. It must pass unchanged.
  body_line: Vec<u8>,
  bdat: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Feed<'a> {
  Whole,
  Cuts(&'a [usize]),
  Bytes,
}

fn cases(n: u32) -> ProptestConfig {
  let mut config = ProptestConfig::with_cases(n);
  config.max_shrink_iters = 32;
  config
}

fn block_on<F>(fut: F) -> F::Output
where
  F: Future,
{
  thread_local! {
    static RT: tokio::runtime::Runtime =
      tokio::runtime::Builder::new_current_thread().build().expect("test runtime");
  }
  RT.with(|rt| rt.block_on(fut))
}

fn b64(raw: &[u8]) -> String {
  base64::engine::general_purpose::STANDARD.encode(raw)
}

fn plain_token(user: &str, pass: &str) -> String {
  b64(format!("\0{user}\0{pass}").as_bytes())
}

fn xoauth_token(user: &str, pass: &str) -> String {
  b64(format!("user={user}\u{1}auth=Bearer {pass}\u{1}\u{1}").as_bytes())
}

fn bearer_token(user: &str, pass: &str) -> String {
  b64(format!("n,a={user},\u{1}host=mail\u{1}auth=Bearer {pass}\u{1}\u{1}").as_bytes())
}

fn line(text: &str) -> Vec<u8> {
  let mut out = text.as_bytes().to_vec();
  out.extend_from_slice(b"\r\n");
  out
}

fn grant(fake_pass: &str, real_pass: &str) -> Vec<Grant> {
  let scope = SmtpScope {
    downstream: SmtpLeg {
      host: "mail".into(),
      port: 587,
      user: FAKE_USER.into(),
      password: SecretString::from(fake_pass),
    },
    is_downstream_tls: false,
    upstream: SmtpLeg {
      host: "mail".into(),
      port: 587,
      user: REAL_USER.into(),
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

fn machines(fake_pass: &str, real_pass: &str) -> (Smtp, Smtp) {
  let grants = grant(fake_pass, real_pass);
  let mut down = Smtp::new(&grants, "mail", 587, Direction::Downstream);
  down.set_protected(true);
  let mut up = Smtp::new(&grants, "mail", 587, Direction::Upstream);
  Smtp::share_data_gate(&down, &mut up);
  (down, up)
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
  if needle.is_empty() || hay.len() < needle.len() {
    return 0;
  }
  hay.windows(needle.len()).filter(|window| *window == needle).count()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
  count(hay, needle) > 0
}

/// `q…` is the decoy and `z…` is the real password, so neither collides with SMTP verbs.
fn tagged(prefix: char, chars: &[char]) -> String {
  let mut out = String::with_capacity(chars.len().saturating_add(1));
  out.push(prefix);
  for ch in chars {
    out.push(*ch);
  }
  out
}

fn session(
  mech: Mech,
  inline: bool,
  fake_chars: &[char],
  real_chars: &[char],
  body_len: usize,
  bdat_len: usize,
  multiline_354: bool,
) -> Session {
  let fake = tagged('q', fake_chars);
  let real = tagged('z', real_chars);
  let mut steps = Vec::new();
  steps.push(Step::Down(line("EHLO mail.example")));
  steps.push(Step::Up(line(&format!("250-{real}"))));
  steps.push(Step::Up(line("250 mail")));
  let swapped = auth_steps(&mut steps, mech, inline, &fake, &real);
  steps.push(Step::Up(line(&format!("535 5.7.8 {real}"))));
  steps.push(Step::Down(line("DATA")));
  if multiline_354 {
    steps.push(Step::Up(line("354-go")));
  }
  steps.push(Step::Up(line("354 go")));
  let body_token = plain_token(FAKE_USER, &fake);
  let body_line = line(&format!("AUTH PLAIN {body_token}"));
  let mut body = vec![b'n'; body_len];
  body.extend_from_slice(&body_line);
  body.extend_from_slice(b".\r\n");
  steps.push(Step::Down(body));
  steps.push(Step::Up(line("250 queued")));
  let bdat = vec![0x7f; bdat_len];
  let mut bdat_step = line(&format!("BDAT {bdat_len}"));
  bdat_step.extend_from_slice(&bdat);
  bdat_step.extend_from_slice(&line("NOOP"));
  steps.push(Step::Down(bdat_step));
  Session {
    steps,
    real,
    fake,
    swapped,
    body_line,
    bdat,
  }
}

fn auth_steps(steps: &mut Vec<Step>, mech: Mech, inline: bool, fake: &str, real: &str) -> Vec<u8> {
  let user_b64 = b64(FAKE_USER.as_bytes());
  let pass_b64 = b64(fake.as_bytes());
  let real_user_b64 = b64(REAL_USER.as_bytes());
  let real_pass_b64 = b64(real.as_bytes());
  match (mech, inline) {
    (Mech::Plain, true) => {
      steps.push(Step::Down(line(&format!("AUTH PLAIN {}", plain_token(FAKE_USER, fake)))));
      plain_token(REAL_USER, real).into_bytes()
    }
    (Mech::Plain, false) => {
      steps.push(Step::Down(line("AUTH PLAIN")));
      steps.push(Step::Up(line("334 go")));
      steps.push(Step::Down(line(&plain_token(FAKE_USER, fake))));
      plain_token(REAL_USER, real).into_bytes()
    }
    (Mech::Login, true) => {
      steps.push(Step::Down(line(&format!("AUTH LOGIN {user_b64}"))));
      steps.push(Step::Up(line("334 go")));
      steps.push(Step::Down(line(&pass_b64)));
      format!("{real_user_b64}\r\n{real_pass_b64}").into_bytes()
    }
    (Mech::Login, false) => {
      steps.push(Step::Down(line("AUTH LOGIN")));
      steps.push(Step::Up(line("334 go")));
      steps.push(Step::Down(line(&user_b64)));
      steps.push(Step::Up(line("334 go")));
      steps.push(Step::Down(line(&pass_b64)));
      format!("{real_user_b64}\r\n{real_pass_b64}").into_bytes()
    }
    (Mech::Xoauth2, true) => {
      steps.push(Step::Down(line(&format!("AUTH XOAUTH2 {}", xoauth_token(FAKE_USER, fake)))));
      xoauth_token(REAL_USER, real).into_bytes()
    }
    (Mech::Xoauth2, false) => {
      steps.push(Step::Down(line("AUTH XOAUTH2")));
      steps.push(Step::Up(line("334 go")));
      steps.push(Step::Down(line(&xoauth_token(FAKE_USER, fake))));
      xoauth_token(REAL_USER, real).into_bytes()
    }
    (Mech::Bearer, true) => {
      steps.push(Step::Down(line(&format!("AUTH OAUTHBEARER {}", bearer_token(FAKE_USER, fake)))));
      bearer_token(REAL_USER, real).into_bytes()
    }
    (Mech::Bearer, false) => {
      steps.push(Step::Down(line("AUTH OAUTHBEARER")));
      steps.push(Step::Up(line("334 go")));
      steps.push(Step::Down(line(&bearer_token(FAKE_USER, fake))));
      bearer_token(REAL_USER, real).into_bytes()
    }
  }
}

struct Emitted {
  down: Vec<u8>,
  up: Vec<u8>,
  closed: bool,
}

fn emit(session: &Session, feed: Feed<'_>) -> Emitted {
  block_on(async {
    let (mut down, mut up) = machines(&session.fake, &session.real);
    let mut out = Emitted {
      down: Vec::new(),
      up: Vec::new(),
      closed: false,
    };
    for step in &session.steps {
      match step {
        Step::Down(bytes) => feed_piece(&mut down, bytes, feed, &mut out.down, &mut out.closed).await,
        Step::Up(bytes) => feed_piece(&mut up, bytes, feed, &mut out.up, &mut out.closed).await,
      }
      if out.closed {
        break;
      }
    }
    out
  })
}

async fn feed_piece(machine: &mut Smtp, data: &[u8], feed: Feed<'_>, out: &mut Vec<u8>, closed: &mut bool) {
  match feed {
    Feed::Whole => take(machine, data, out, closed).await,
    Feed::Cuts(cuts) => {
      let mut points: Vec<usize> = cuts.iter().copied().filter(|cut| *cut > 0 && *cut < data.len()).collect();
      points.sort_unstable();
      points.dedup();
      let mut prev = 0;
      for cut in points {
        take(machine, &data[prev..cut], out, closed).await;
        if *closed {
          return;
        }
        prev = cut;
      }
      take(machine, &data[prev..], out, closed).await;
    }
    Feed::Bytes => {
      for byte in data.chunks(1) {
        take(machine, byte, out, closed).await;
        if *closed {
          return;
        }
      }
    }
  }
  if !*closed {
    take(machine, &[], out, closed).await;
  }
}

async fn take(machine: &mut Smtp, chunk: &[u8], out: &mut Vec<u8>, closed: &mut bool) {
  match machine.feed(chunk).await {
    (Rewritten::Emit(bytes), _) => out.extend_from_slice(&bytes),
    (Rewritten::Hold, _) => {}
    (Rewritten::Close, _) => *closed = true,
  }
}

fn first_diff(left: &[u8], right: &[u8]) -> Option<usize> {
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
/// `at` is an offset in the final line. `220 ` is the first four bytes, so
/// `MAX_COMMAND - 4` puts the password across the old per-line cut.
fn greeting(continuations: u8, at: usize, pass: &str) -> (Vec<u8>, usize) {
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

struct Opening {
  code: Option<[u8; 3]>,
  guest: Vec<u8>,
  at: usize,
}

fn read_opening(up: &mut Smtp, reader: &mut Cursor<Vec<u8>>) -> Result<Opening, crate::Error> {
  block_on(async {
    let mut guest = plain_guest(Cursor::new(Vec::new()));
    let code = acceptance_reply(reader, up, &mut guest).await?;
    let at = usize::try_from(reader.position()).unwrap_or(usize::MAX);
    let guest = match guest {
      GuestLeg::Plain(cursor) => cursor.into_inner(),
      GuestLeg::Tls(_) => Vec::new(),
    };
    Ok(Opening { code, guest, at })
  })
}

fn distinct(fake: &[char], real: &[char]) -> bool {
  let fake = tagged('q', fake);
  let real = tagged('z', real);
  fake != real && !fake.contains(real.as_str()) && !real.contains(fake.as_str())
}

proptest! {
  #![proptest_config(cases(32))]

  /// AUTH, a multiline reply, DATA, and BDAT survive every arrival split.
  /// The real password is absent from guest-bound bytes. It may be shorter
  /// or longer than the decoy.
  #[test]
  fn prop_session_chunks_match_and_hide_the_real_password(
    mech in prop_oneof![Just(Mech::Plain), Just(Mech::Login), Just(Mech::Xoauth2), Just(Mech::Bearer)],
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
    prop_assume!(distinct(&fake_chars, &real_chars));
    let session = session(mech, inline, &fake_chars, &real_chars, body_len, bdat_len, multiline_354);
    let whole = emit(&session, Feed::Whole);
    let split = emit(&session, Feed::Cuts(&cuts));
    let bytes = emit(&session, Feed::Bytes);
    prop_assert!(!whole.closed && !split.closed && !bytes.closed, "a generated session closed the machine");
    prop_assert_eq!(first_diff(&whole.down, &split.down), None, "downstream split diverged, lens {} {}", whole.down.len(), split.down.len());
    prop_assert_eq!(first_diff(&whole.up, &split.up), None, "upstream split diverged, lens {} {}", whole.up.len(), split.up.len());
    prop_assert_eq!(first_diff(&whole.down, &bytes.down), None, "downstream bytes diverged, lens {} {}", whole.down.len(), bytes.down.len());
    prop_assert_eq!(first_diff(&whole.up, &bytes.up), None, "upstream bytes diverged, lens {} {}", whole.up.len(), bytes.up.len());
    let real = session.real.as_bytes();
    let fake = session.fake.as_bytes();
    prop_assert!(!contains(&whole.up, real), "real password reached the guest");
    prop_assert!(!contains(&split.up, real), "real password reached the guest on a split");
    prop_assert!(!contains(&bytes.up, real), "real password reached the guest one byte at a time");
    prop_assert_eq!(count(&whole.up, fake), 2, "both reply copies of the password should become the decoy");
    prop_assert!(contains(&whole.down, &session.swapped), "AUTH did not swap onto the upstream wire");
    prop_assert!(contains(&whole.down, &session.body_line), "DATA body was rewritten");
    prop_assert!(session.bdat.is_empty() || contains(&whole.down, &session.bdat), "BDAT octets were dropped");
  }
}

proptest! {
  #![proptest_config(cases(12))]

  /// A reply cut at any offset, including the old 16 KiB boundary, is still
  /// one opening reply. The next status line stays unread until the next read.
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
    prop_assume!(distinct(&fake_chars, &real_chars));
    let fake = tagged('q', &fake_chars);
    let real = tagged('z', &real_chars);
    let at = if straddling { MAX_COMMAND.saturating_sub(4) } else { 4usize.saturating_add(small_pad) };
    let (greet, pass_at) = greeting(continuations, at, &real);
    let line_cut = pass_at.saturating_sub(at).saturating_add(MAX_COMMAND);
    prop_assume!(pass_at < greet.len());
    let mut cuts = cuts;
    cuts.push(line_cut);
    cuts.push(pass_at);
    cuts.push(pass_at.saturating_add(1));

    let whole = block_on(async {
      let mut up = machines(&fake, &real).1;
      let mut out = Vec::new();
      let mut closed = false;
      feed_piece(&mut up, &greet, Feed::Whole, &mut out, &mut closed).await;
      (out, closed)
    });
    let split = block_on(async {
      let mut up = machines(&fake, &real).1;
      let mut out = Vec::new();
      let mut closed = false;
      feed_piece(&mut up, &greet, Feed::Cuts(&cuts), &mut out, &mut closed).await;
      (out, closed)
    });
    let bytes = block_on(async {
      let mut up = machines(&fake, &real).1;
      let mut out = Vec::new();
      let mut closed = false;
      feed_piece(&mut up, &greet, Feed::Bytes, &mut out, &mut closed).await;
      (out, closed)
    });
    prop_assert!(!whole.1 && !split.1 && !bytes.1, "the reply closed the upstream machine");
    prop_assert_eq!(first_diff(&whole.0, &split.0), None, "reply split diverged at the cut");
    prop_assert_eq!(first_diff(&whole.0, &bytes.0), None, "reply bytes diverged");
    prop_assert!(!contains(&whole.0, real.as_bytes()), "real password survived a whole reply");
    prop_assert!(!contains(&split.0, real.as_bytes()), "real password survived a cut");
    prop_assert!(!contains(&bytes.0, real.as_bytes()), "real password survived one-byte reads");
    prop_assert!(contains(&whole.0, fake.as_bytes()), "the decoy did not replace the password");

    let mut stream = greet.clone();
    stream.extend_from_slice(b"250 ok\r\n");
    let (mut down, mut up) = machines(&fake, &real);
    let mut cursor = Cursor::new(stream);
    let first = read_opening(&mut up, &mut cursor).expect("greeting");
    prop_assert_eq!(first.code, Some(*b"220"), "the final line decides the opening");
    prop_assert_eq!(first.at, greet.len(), "the cut consumed the next reply or stopped early");
    prop_assert!(!contains(&first.guest, real.as_bytes()), "guest saw the real password");
    prop_assert!(contains(&first.guest, fake.as_bytes()), "guest missed the decoy");
    let second = read_opening(&mut up, &mut cursor).expect("next reply");
    prop_assert_eq!(second.code, Some(*b"250"), "the following reply was no longer in sync");
    prop_assert_eq!(second.at, cursor.get_ref().len(), "the following reply was not consumed whole");

    let mut data_out = Vec::new();
    let mut closed = false;
    block_on(async {
      feed_piece(&mut down, b"DATA\r\n", Feed::Whole, &mut data_out, &mut closed).await;
      feed_piece(&mut up, b"354 go\r\n", Feed::Whole, &mut Vec::new(), &mut closed).await;
      let mut body = b"AUTH PLAIN ".to_vec();
      body.extend_from_slice(plain_token(FAKE_USER, &fake).as_bytes());
      body.extend_from_slice(b"\r\n.\r\n");
      feed_piece(&mut down, &body, Feed::Whole, &mut data_out, &mut closed).await;
      (body, )
    });
    let body_marker = plain_token(FAKE_USER, &fake);
    prop_assert!(!closed, "DATA after the opening closed the machine");
    prop_assert!(contains(&data_out, body_marker.as_bytes()), "DATA after the opening was parsed as AUTH");
  }
}
