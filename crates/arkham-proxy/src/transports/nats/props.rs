//! NATS property tests. 256 cases. Every run ends with the empty EOF flush
//! from the shared harness.

use proptest::prelude::*;

use crate::transports::engine::harness::{CutPend, block_on, run_split_parts};
use crate::transports::nats::machine::tests::nats_grants;
use crate::transports::nats::machine::{MAX_COMMAND as NATS_MAX_COMMAND, Nats};
use crate::transports::nats::server_info;

fn count_bytes(hay: &[u8], needle: &[u8]) -> usize {
  if needle.is_empty() || hay.len() < needle.len() {
    return 0;
  }
  hay.windows(needle.len()).filter(|window| *window == needle).count()
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
  count_bytes(hay, needle) > 0
}

/// NATS decoy and real passwords. Lengths differ on purpose. Both hold an
/// `a`, which [`nats_word`] never produces.
const NATS_FAKE: &str = "arkham_fake_nats_pass"; // betterleaks:allow
const NATS_REAL: &str = "arkham_real_nats_pass_01"; // betterleaks:allow
const NATS_HOST: &str = "nats.internal";
const NATS_PORT: u16 = 4222;

/// One direction the NATS properties drive. Guest-bound output is [`NatsLeg::Up`].
#[derive(Clone, Copy, Debug)]
enum NatsLeg {
  DownSwap,
  DownClear,
  Up,
}

fn nats_leg(leg: NatsLeg) -> Nats {
  let grants = nats_grants(
    &format!("nats://agent:{NATS_FAKE}@{NATS_HOST}:{NATS_PORT}"),
    &format!("tls://agent:{NATS_REAL}@nats.upstream:{NATS_PORT}"),
  );
  match leg {
    NatsLeg::DownSwap => Nats::downstream(&grants, NATS_HOST, NATS_PORT, true),
    NatsLeg::DownClear => Nats::downstream(&grants, NATS_HOST, NATS_PORT, false),
    NatsLeg::Up => Nats::upstream(&grants, NATS_HOST, NATS_PORT),
  }
}

struct NatsFed {
  out: Vec<u8>,
  hits: usize,
  closed: bool,
}

/// [`run_split_parts`] over a fresh `leg`, ending with the empty EOF flush.
fn run_nats(leg: NatsLeg, data: &[u8], cuts: &[usize]) -> NatsFed {
  let mut machine = nats_leg(leg);
  let (out, hits, closed) = run_split_parts(&mut machine, data, cuts);
  NatsFed { out, hits, closed }
}

/// Random cuts scaled into `data` and sorted ascending.
fn nats_cuts(cuts: &[usize], data: &[u8]) -> Vec<usize> {
  let mut scaled: Vec<usize> = cuts.iter().map(|cut| cut % data.len().max(1)).collect();
  scaled.sort_unstable();
  scaled
}

/// One shot, `cuts`, and one byte at a time.
fn nats_runs(leg: NatsLeg, data: &[u8], cuts: &[usize]) -> [NatsFed; 3] {
  let byte_cuts: Vec<usize> = (1..data.len()).collect();
  [run_nats(leg, data, &[]), run_nats(leg, data, cuts), run_nats(leg, data, &byte_cuts)]
}

/// Every arrival agrees on the bytes and the hits, and the leg stays open.
fn nats_splits_match(leg: NatsLeg, data: &[u8], cuts: &[usize]) -> Result<NatsFed, TestCaseError> {
  let [once, split, byte] = nats_runs(leg, data, cuts);
  prop_assert_eq!(&once.out, &split.out);
  prop_assert_eq!(&once.out, &byte.out);
  prop_assert_eq!(once.hits, split.hits);
  prop_assert_eq!(once.hits, byte.hits);
  prop_assert!(
    !once.closed && !split.closed && !byte.closed,
    "an accepted stream closed the {:?} leg",
    leg
  );
  Ok(once)
}

/// Subjects, names, and error text that cannot spell either password.
fn nats_word() -> impl Strategy<Value = String> {
  proptest::string::string_regex("[b-z]{1,8}").expect("nats word")
}

fn nats_payload() -> impl Strategy<Value = Vec<u8>> {
  proptest::collection::vec(any::<u8>(), 0..16)
}

fn nats_connect(pass: &str, name: &str, lower: bool) -> Vec<u8> {
  let verb = if lower { "connect" } else { "CONNECT" };
  format!("{verb} {{\"verbose\":false,\"user\":\"agent\",\"pass\":\"{pass}\",\"name\":\"{name}\"}}\r\n").into_bytes()
}

/// A counted command. `head` is everything before the counts; a header
/// block, when there is one, leads the payload.
fn nats_counted(head: &str, headers: bool, payload: &[u8]) -> Vec<u8> {
  let block: &[u8] = if headers { b"NATS/1.0\r\n\r\n" } else { b"" };
  let total = block.len().saturating_add(payload.len());
  let counts = if headers {
    format!("{} {total}", block.len())
  } else {
    total.to_string()
  };
  let mut out = format!("{head} {counts}\r\n").into_bytes();
  out.extend_from_slice(block);
  out.extend_from_slice(payload);
  out.extend_from_slice(b"\r\n");
  out
}

fn nats_client_message() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    (nats_word(), any::<bool>()).prop_map(|(name, lower)| nats_connect(NATS_FAKE, &name, lower)),
    (nats_word(), any::<bool>()).prop_map(|(name, lower)| nats_connect("guest-pass", &name, lower)),
    (nats_word(), any::<bool>(), nats_payload()).prop_map(|(subject, headers, payload)| {
      let verb = if headers { "HPUB" } else { "PUB" };
      nats_counted(&format!("{verb} {subject}"), headers, &payload)
    }),
    (nats_word(), 1u16..1000).prop_map(|(subject, sid)| format!("SUB {subject} {sid}\r\n").into_bytes()),
    (1u16..1000).prop_map(|sid| format!("UNSUB {sid}\r\n").into_bytes()),
    Just(b"PING\r\n".to_vec()),
    Just(b"PONG\r\n".to_vec()),
  ]
}

/// Server frames that keep the leg open. The real password appears only
/// where the leg redacts it, or as a proper prefix inside a payload.
fn nats_server_message() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    nats_word().prop_map(|id| format!("INFO {{\"server_id\":\"{id}\",\"tls_required\":true}}\r\n").into_bytes()),
    nats_word().prop_map(|text| format!("-ERR '{text}'\r\n").into_bytes()),
    nats_word().prop_map(|text| format!("-ERR '{text} {NATS_REAL}'\r\n").into_bytes()),
    (1usize..NATS_REAL.len()).prop_map(|k| format!("-ERR '{}'\r\n", NATS_REAL.get(..k).unwrap_or(NATS_REAL)).into_bytes()),
    Just(b"+OK\r\n".to_vec()),
    Just(b"PING\r\n".to_vec()),
    Just(b"PONG\r\n".to_vec()),
    (nats_word(), 1u16..1000, any::<bool>(), nats_payload()).prop_map(|(subject, sid, headers, payload)| {
      let verb = if headers { "HMSG" } else { "MSG" };
      nats_counted(&format!("{verb} {subject} {sid}"), headers, &payload)
    }),
    (nats_word(), 1u16..1000, 1usize..NATS_REAL.len()).prop_map(|(subject, sid, k)| {
      let prefix = NATS_REAL.get(..k).unwrap_or(NATS_REAL);
      nats_counted(&format!("MSG {subject} {sid}"), false, prefix.as_bytes())
    }),
    (nats_word(), 1u16..1000).prop_map(|(subject, sid)| nats_counted(&format!("MSG {subject} {sid}"), false, NATS_FAKE.as_bytes())),
  ]
}

/// Where the real password sits in a server frame.
#[derive(Clone, Debug)]
enum NatsSecret {
  /// Inside a delimited line: redacted to the decoy.
  Line { info: bool, pre: String, post: String },
  /// Inside a counted payload: the leg closes.
  Payload { headers: bool, pre: Vec<u8>, post: Vec<u8> },
  /// As a MSG subject: the leg closes.
  Subject { sid: u16 },
}

fn nats_secret_frame(place: &NatsSecret) -> Vec<u8> {
  match place {
    NatsSecret::Line { info: true, pre, post } => format!("INFO {{\"server_id\":\"{pre}{NATS_REAL}{post}\"}}\r\n").into_bytes(),
    NatsSecret::Line { info: false, pre, post } => format!("-ERR '{pre}{NATS_REAL}{post}'\r\n").into_bytes(),
    NatsSecret::Payload { headers, pre, post } => {
      let mut payload = pre.clone();
      payload.extend_from_slice(NATS_REAL.as_bytes());
      payload.extend_from_slice(post);
      let verb = if *headers { "HMSG" } else { "MSG" };
      nats_counted(&format!("{verb} orders 1"), *headers, &payload)
    }
    NatsSecret::Subject { sid } => nats_counted(&format!("MSG {NATS_REAL} {sid}"), false, b"hi"),
  }
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// Any cut of an accepted NATS stream, including one byte at a time,
  /// matches one shot. A cleartext server leg changes nothing; a TLS one
  /// swaps each decoy CONNECT; guest-bound bytes never hold the real password.
  #[test]
  fn prop_nats_split_output_is_identical(
    client in proptest::collection::vec(nats_client_message(), 1..4),
    server in proptest::collection::vec(nats_server_message(), 1..4),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let client = client.concat();
    let server = server.concat();
    let client_cuts = nats_cuts(&cuts, &client);
    let clear = nats_splits_match(NatsLeg::DownClear, &client, &client_cuts)?;
    prop_assert_eq!(&clear.out, &client, "a cleartext server leg changed guest bytes");
    let swapped = nats_splits_match(NatsLeg::DownSwap, &client, &client_cuts)?;
    let decoys = count_bytes(&client, format!("\"pass\":\"{NATS_FAKE}\"").as_bytes());
    prop_assert_eq!(count_bytes(&swapped.out, format!("\"pass\":\"{NATS_REAL}\"").as_bytes()), decoys);
    prop_assert_eq!(swapped.hits, decoys);
    let up = nats_splits_match(NatsLeg::Up, &server, &nats_cuts(&cuts, &server))?;
    prop_assert!(!contains_bytes(&up.out, NATS_REAL.as_bytes()), "the real password reached the guest");
  }

  /// The real password stays out of guest-bound NATS output for every cut.
  /// A line carries the decoy instead; a payload or subject closes the leg.
  #[test]
  fn prop_nats_guest_output_hides_the_real_password(
    place in prop_oneof![
      (any::<bool>(), nats_word(), nats_word()).prop_map(|(info, pre, post)| NatsSecret::Line { info, pre, post }),
      (any::<bool>(), nats_payload(), nats_payload()).prop_map(|(headers, pre, post)| NatsSecret::Payload { headers, pre, post }),
      (1u16..1000).prop_map(|sid| NatsSecret::Subject { sid }),
    ],
    lead in proptest::collection::vec(nats_server_message(), 0..3),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let mut data = lead.concat();
    data.extend(nats_secret_frame(&place));
    let scaled = nats_cuts(&cuts, &data);
    let runs = nats_runs(NatsLeg::Up, &data, &scaled);
    for run in &runs {
      prop_assert!(!contains_bytes(&run.out, NATS_REAL.as_bytes()), "the real password reached the guest");
    }
    if matches!(place, NatsSecret::Line { .. }) {
      let once = nats_splits_match(NatsLeg::Up, &data, &scaled)?;
      prop_assert!(contains_bytes(&once.out, NATS_FAKE.as_bytes()), "the line lost its decoy");
    } else {
      for run in &runs {
        prop_assert!(run.closed, "a frame holding the real password stayed open");
      }
    }
  }

  /// INFO cut at any offset is still one line to the guest. The read that
  /// holds its LF may end there or run into the bytes after it, TLS records
  /// or the next NATS line, which are left for the next reader.
  #[test]
  fn prop_nats_info_cut_leaves_the_rest_unread(
    id in nats_word(),
    secret in any::<bool>(),
    handshake in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..32)),
    past_newline in 0usize..4,
    cuts in proptest::collection::vec(any::<usize>(), 0..4),
  ) {
    let real = if secret { NATS_REAL } else { "" };
    let info = format!("INFO {{\"server_id\":\"{id}{real}\",\"tls_required\":true}}\r\n").into_bytes();
    let tail = match &handshake {
      Some(record) => [&[0x16, 0x03, 0x01], record.as_slice()].concat(),
      None => b"PING\r\n".to_vec(),
    };
    let stream = [info.as_slice(), tail.as_slice()].concat();
    let mut cuts: Vec<usize> = cuts.iter().map(|cut| cut % stream.len()).collect();
    cuts.push(info.len().saturating_add(past_newline));
    let expected = run_nats(NatsLeg::Up, &info, &[]).out;
    let mut clear_reader = CutPend::new(stream.clone(), &cuts);
    let mut clear_up = nats_leg(NatsLeg::Up);
    let mut clear_guest = Vec::new();
    let err = block_on(server_info(&mut clear_reader, &mut clear_up, &mut clear_guest, true))
      .expect_err("cleartext INFO with tls_required must close");
    prop_assert!(
      matches!(
        err,
        crate::Error::NatsTlsRequired {
          tls_available: false,
          tls_verify: false
        }
      ),
      "cleartext close was {err}"
    );
    prop_assert!(!clear_guest.contains(&b'\n'), "the read that held LF was written on a cleartext close");
    prop_assert!(
      !contains_bytes(&clear_guest, NATS_REAL.as_bytes()),
      "INFO carried the real password to the guest"
    );
    let mut reader = CutPend::new(stream, &cuts);
    let mut up = nats_leg(NatsLeg::Up);
    let mut guest = Vec::new();
    let read = block_on(server_info(&mut reader, &mut up, &mut guest, false)).expect("info read");
    let Some(mut rest) = read else {
      return Err(TestCaseError::fail("the INFO reader closed"));
    };
    prop_assert_eq!(&guest, &expected, "cut INFO reached the guest differently");
    prop_assert!(!contains_bytes(&guest, NATS_REAL.as_bytes()), "INFO carried the real password to the guest");
    rest.extend_from_slice(reader.data.get(reader.at..).unwrap_or_default());
    prop_assert_eq!(&rest, &tail, "bytes past INFO were consumed or lost");
    if handshake.is_none() {
      let (next, _, closed) = run_split_parts(&mut up, &rest, &[]);
      prop_assert!(!closed, "the line after INFO closed the leg");
      prop_assert_eq!(next, tail, "the leg lost its framing after INFO");
    }
  }

  /// A proper prefix at EOF: the guest leg flushes it unchanged, the server
  /// leg closes, and every cut agrees.
  #[test]
  fn prop_nats_truncated_prefix_at_eof(
    client in nats_client_message(),
    server in nats_server_message(),
    keep in any::<usize>(),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let end = 1 + keep % (client.len() - 1);
    let prefix = &client[..end];
    for leg in [NatsLeg::DownSwap, NatsLeg::DownClear] {
      for run in nats_runs(leg, prefix, &nats_cuts(&cuts, prefix)) {
        prop_assert_eq!(run.out.as_slice(), prefix, "a partial guest command changed at EOF");
        prop_assert!(!run.closed, "a partial guest command closed the leg");
      }
    }
    let end = 1 + keep % (server.len() - 1);
    let prefix = &server[..end];
    let [once, split, byte] = nats_runs(NatsLeg::Up, prefix, &nats_cuts(&cuts, prefix));
    prop_assert!(once.closed && split.closed && byte.closed, "a partial server frame stayed open at EOF");
    prop_assert_eq!(&once.out, &split.out);
    prop_assert_eq!(&once.out, &byte.out);
  }

  /// A CONNECT past the cap is forwarded byte-identical. One shot and the
  /// random cuts each end with the empty EOF flush. A TLS leg does not swap
  /// it, and the command after it keeps the session open. One byte at a time
  /// stays in the unit tests: this line is longer than the cap, and walking
  /// every byte for 256 cases would pass the slow-test deadline.
  #[test]
  fn prop_nats_oversize_connect_is_forwarded(
    extra in 0usize..64,
    lower in any::<bool>(),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let verb = if lower { "connect" } else { "CONNECT" };
    let name = "b".repeat(NATS_MAX_COMMAND.saturating_add(extra));
    let line = format!("{verb} {{\"verbose\":false,\"user\":\"agent\",\"pass\":\"{NATS_FAKE}\",\"name\":\"{name}\"}}\r\n");
    prop_assert!(line.len() > NATS_MAX_COMMAND);
    let mut data = line.into_bytes();
    data.extend_from_slice(b"PING\r\n");
    let scaled = nats_cuts(&cuts, &data);
    for leg in [NatsLeg::DownSwap, NatsLeg::DownClear] {
      let once = run_nats(leg, &data, &[]);
      let split = run_nats(leg, &data, &scaled);
      prop_assert!(!once.closed && !split.closed, "an oversize CONNECT closed the {leg:?} leg");
      prop_assert_eq!(&once.out, &data);
      prop_assert_eq!(&split.out, &data);
      prop_assert_eq!(once.hits, 0);
      prop_assert_eq!(split.hits, 0);
    }
  }

  /// Crash resistance: arbitrary bytes, one cut, any leg, then EOF; and the
  /// same bytes through the INFO reader.
  #[test]
  fn prop_nats_arbitrary_no_panic(
    data in proptest::collection::vec(any::<u8>(), 0..1024),
    cut in 0usize..1024,
    leg in prop_oneof![Just(NatsLeg::DownSwap), Just(NatsLeg::DownClear), Just(NatsLeg::Up)],
  ) {
    let _ = run_nats(leg, &data, &[cut.min(data.len())]);
    let mut reader = CutPend::new(data, &[cut]);
    let mut up = nats_leg(NatsLeg::Up);
    let _ = block_on(server_info(&mut reader, &mut up, &mut Vec::new(), false));
  }
}
