//! nftables rule installation for TPROXY capture (pure netlink, no
//! external tools): one inet table, two base chains, three rules.
//!
//! Equivalent ruleset (`nft -f` shape):
//!
//! ```text
//! table inet arkham_tproxy {
//!   chain output {
//!     type route hook output priority mangle;
//!     meta l4proto tcp oifname != "lo" meta mark != <fwmark> meta mark set <fwmark>
//!     meta l4proto udp udp dport 443 drop
//!   }
//!   chain prerouting {
//!     type filter hook prerouting priority mangle;
//!     meta mark <fwmark> meta l4proto tcp tproxy to :<port> meta mark set <fwmark>
//!   }
//! }
//! ```
//!
//! The tproxy statement has no typed variant in `netlink-packet-netfilter`
//! (verified 0.4.0), so it rides the `Other` expression escape hatch with
//! raw NLAs (`NFTA_TPROXY_FAMILY`, `NFTA_TPROXY_PORT`).

use std::net::Ipv4Addr;

use netlink_packet_core::{DefaultNla, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
  NetfilterHeader, NetfilterMessage, NetfilterProtoFamily,
  nftables::{
    ChainAttribute, ChainMessage, Cmp, DataAttribute, Expressions, Hook, HookNumber, Immediate, InetHookNumber, Meta, MetaKey,
    NfTablesMessage, Operator, Payload, Register, RuleAttribute, RuleMessage, TableAttribute, TableMessage, Verdict, VerdictAttribute,
  },
};

/// `NFNL_SUBSYS_NFTABLES`, the logical value: the crate's header emit
/// applies `to_be()` itself, and the kernel reads it back through `ntohs`.
pub(super) const SUBSYS_NFTABLES: u16 = 10;
/// `NFT_PAYLOAD_NETWORK_HEADER` / `NFT_PAYLOAD_TRANSPORT_HEADER`.
const PAYLOAD_BASE_NETWORK: u32 = 1;
const PAYLOAD_BASE_TRANSPORT: u32 = 2;
/// IPv4 header offsets: daddr at byte 16; UDP dport at transport byte 2.
const IPV4_OFFSET_DADDR: u32 = 16;
const UDP_OFFSET_DPORT: u32 = 2;
/// nft mangle priority (-150) in its u32 wire form.
const PRIORITY_MANGLE: u32 = (-150i32).cast_unsigned();
/// Kernel ABI constants at their fixed wire widths.
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
/// `NFTA_TPROXY_FAMILY` / `NFTA_TPROXY_PORT` attribute kinds.
const NFTA_TPROXY_FAMILY: u16 = 1;
const NFTA_TPROXY_PORT: u16 = 3;
/// `NF_DROP` as its wire-representable width (kernel ABI constant).
const NF_DROP: u32 = 0; // libc::NF_DROP

/// Rule-shape parameters for the capture table.
#[derive(Debug, Clone)]
pub(crate) struct CaptureConfig {
  /// Port the transparent listener accepts on (`tproxy to :port`).
  pub listen_port: u16,
  /// Mark identifying captured traffic (set by the OUTPUT rule, routed to
  /// the local table, consumed by the prerouting tproxy rule).
  pub fwmark: u32,
  /// Mark arkham presets on its own upstream dials; the OUTPUT rule skips
  /// packets carrying it so the dial keeps normal routing.
  pub egress_mark: u32,
  /// Optional exact destination-IP scope (live tests only: restrict the
  /// OUTPUT mark rule to one address so the host is untouched).
  pub scope: Option<Ipv4Addr>,
  /// nft table name.
  pub table: String,
}

impl CaptureConfig {
  /// Messages to atomically create the table, chains, and rules.
  #[must_use]
  pub fn install_messages(&self) -> Vec<NetlinkMessage<NetfilterMessage>> {
    let mut msgs = vec![self.table_message()];
    msgs.extend(self.chain_messages());
    msgs.extend(self.rule_messages());
    msgs
  }

  /// Message to flush the whole table (chains and rules go with it).
  #[must_use]
  pub fn teardown_message(&self) -> NetlinkMessage<NetfilterMessage> {
    Self::wrap(NfTablesMessage::DeleteTable(TableMessage {
      attributes: vec![TableAttribute::Name(self.table.clone())],
    }))
  }

  fn table_message(&self) -> NetlinkMessage<NetfilterMessage> {
    Self::wrap(NfTablesMessage::NewTable(TableMessage {
      attributes: vec![TableAttribute::Name(self.table.clone())],
    }))
  }

  fn chain_messages(&self) -> Vec<NetlinkMessage<NetfilterMessage>> {
    vec![
      Self::wrap(NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
          ChainAttribute::Table(self.table.clone()),
          ChainAttribute::Name("output".into()),
          ChainAttribute::Hook(vec![
            Hook::Number(HookNumber::Inet(InetHookNumber::LocalOut)),
            Hook::Priority(PRIORITY_MANGLE),
          ]),
          ChainAttribute::Type("route".into()),
        ],
      })),
      Self::wrap(NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
          ChainAttribute::Table(self.table.clone()),
          ChainAttribute::Name("prerouting".into()),
          ChainAttribute::Hook(vec![
            Hook::Number(HookNumber::Inet(InetHookNumber::PreRouting)),
            Hook::Priority(PRIORITY_MANGLE),
          ]),
          ChainAttribute::Type("filter".into()),
        ],
      })),
    ]
  }

  fn rule_messages(&self) -> Vec<NetlinkMessage<NetfilterMessage>> {
    // Optional exact-destination scope: when set, the daddr match replaces
    // the loopback exemption (a scoped rule is narrower than oifname != lo),
    // and every expression pair stays intact — a cmp without its load is
    // rejected by the kernel at rule validation.
    let daddr_match: Vec<Expressions> = self.scope.map_or_else(Vec::new, |addr| {
      vec![
        Expressions::Payload(vec![
          Payload::Base(PAYLOAD_BASE_NETWORK),
          Payload::Offset(IPV4_OFFSET_DADDR),
          Payload::Len(4),
          Payload::DestinationRegister(Register::Reg1),
        ]),
        cmp_eq(addr.octets().to_vec()),
      ]
    });

    let mut output_mark = daddr_match.clone();
    output_mark.extend([meta_load(MetaKey::L4Proto), cmp_eq(u32_bytes(IPPROTO_TCP))]);
    if self.scope.is_none() {
      output_mark.extend([meta_load(MetaKey::Oifname), cmp_ne(ifname_bytes("lo"))]);
    }
    output_mark.extend([
      meta_load(MetaKey::Mark),
      cmp_ne(u32_bytes(self.fwmark)),
      meta_load(MetaKey::Mark),
      cmp_ne(u32_bytes(self.egress_mark)),
      imm_u32(self.fwmark),
      meta_store(MetaKey::Mark),
    ]);

    let mut output_drop = daddr_match;
    output_drop.extend([
      meta_load(MetaKey::L4Proto),
      cmp_eq(u32_bytes(IPPROTO_UDP)),
      Expressions::Payload(vec![
        Payload::Base(PAYLOAD_BASE_TRANSPORT),
        Payload::Offset(UDP_OFFSET_DPORT),
        Payload::Len(2),
        Payload::DestinationRegister(Register::Reg1),
      ]),
      cmp_eq(port_bytes(443)),
      imm_drop(),
    ]);

    vec![
      // output: mark outbound TCP for the transparent listener; arkham's own
      // marked sockets are exempt, and loopback-delivered traffic too
      // unless the rule is already scoped to one destination.
      self.rule("output", output_mark),
      // output: drop QUIC. Nothing here terminates QUIC, so a captured
      // HTTP/3 flow could only be relayed with the decoy intact; dropping it
      // makes the client fall back to TCP, where TLS is terminated and the
      // substitution happens. Unscoped, this is every destination: QUIC on
      // 443 is defeated machine-wide, not only for granted hosts.
      self.rule("output", output_drop),
      // prerouting: hand marked TCP to the transparent listener, keep the
      // mark so replies route back through the same table.
      self.rule(
        "prerouting",
        vec![
          meta_load(MetaKey::Mark),
          cmp_eq(u32_bytes(self.fwmark)),
          meta_load(MetaKey::L4Proto),
          cmp_eq(u32_bytes(IPPROTO_TCP)),
          tproxy_port_load(self.listen_port),
          tproxy_reg_port(),
          imm_u32(self.fwmark),
          meta_store(MetaKey::Mark),
        ],
      ),
    ]
  }

  fn rule(&self, chain: &str, exprs: Vec<Expressions>) -> NetlinkMessage<NetfilterMessage> {
    Self::wrap(NfTablesMessage::NewRule(RuleMessage {
      attributes: vec![
        RuleAttribute::Table(self.table.clone()),
        RuleAttribute::Chain(chain.into()),
        RuleAttribute::Expressions(exprs.into_iter().map(Into::into).collect()),
      ],
    }))
  }

  fn wrap(inner: NfTablesMessage) -> NetlinkMessage<NetfilterMessage> {
    let mut msg = NetlinkMessage::new(
      netlink_packet_core::NetlinkHeader::default(),
      NetlinkPayload::InnerMessage(NetfilterMessage::new(NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0), inner)),
    );
    msg.header.flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    msg
  }
}

fn meta_load(key: MetaKey) -> Expressions {
  Expressions::Meta(vec![Meta::Key(key), Meta::DestinationRegister(Register::Reg1)])
}

fn meta_store(key: MetaKey) -> Expressions {
  Expressions::Meta(vec![Meta::SourceRegister(Register::Reg1), Meta::Key(key)])
}

fn cmp_eq(data: Vec<u8>) -> Expressions {
  cmp(Operator::Equal, data)
}

fn cmp_ne(data: Vec<u8>) -> Expressions {
  cmp(Operator::NotEqual, data)
}

fn cmp(op: Operator, data: Vec<u8>) -> Expressions {
  Expressions::Cmp(vec![
    Cmp::SourceRegister(Register::Reg1),
    Cmp::Op(op),
    Cmp::Data(DataAttribute::Value(data)),
  ])
}

fn imm_u32(value: u32) -> Expressions {
  Expressions::Immediate(vec![
    Immediate::DestinationRegister(Register::Reg1),
    Immediate::Data(DataAttribute::Value(u32_bytes(value))),
  ])
}

fn imm_drop() -> Expressions {
  Expressions::Immediate(vec![
    Immediate::DestinationRegister(Register::Verdict),
    Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(Verdict::Other(NF_DROP))])),
  ])
}

/// `tproxy to :<port>`: the port is loaded into Reg1 (network-order u16 in
/// a 4-byte slot) by a preceding immediate, and the statement itself is
/// `{FAMILY: u32be=UNSPEC, REG_PORT: u32be=1}`. Raw NLAs because the crate
/// has no typed tproxy variant (verified against `nft -f` wire bytes).
fn tproxy_port_load(port: u16) -> Expressions {
  Expressions::Immediate(vec![
    Immediate::DestinationRegister(Register::Reg1),
    Immediate::Data(DataAttribute::Value(port_bytes(port))),
  ])
}

fn tproxy_reg_port() -> Expressions {
  Expressions::Other {
    expression_type: "tproxy".into(),
    attributes: vec![
      DefaultNla::new(NFTA_TPROXY_FAMILY, 0u32.to_be_bytes().to_vec()),
      DefaultNla::new(NFTA_TPROXY_PORT, 1u32.to_be_bytes().to_vec()),
    ],
  }
}

/// Integer meta/cmp values travel as native-order u32 (nft stores them
/// host-endian; verified against `nft -f` wire bytes).
fn u32_bytes(value: u32) -> Vec<u8> {
  value.to_ne_bytes().to_vec()
}

/// Ports travel as network-order u16 in a 4-byte slot.
fn port_bytes(port: u16) -> Vec<u8> {
  let [hi, lo] = port.to_be_bytes();
  vec![hi, lo, 0, 0]
}

/// Interface names travel NUL-padded to IFNAMSIZ.
fn ifname_bytes(name: &str) -> Vec<u8> {
  let mut bytes = name.as_bytes().to_vec();
  bytes.resize(16, 0);
  bytes
}

#[cfg(test)]
mod tests {
  use super::*;
  use netlink_packet_netfilter::NetfilterMessageInner;
  use netlink_packet_netfilter::nftables::{ExpressionAttribute, ListAttribute};

  fn config() -> CaptureConfig {
    CaptureConfig {
      listen_port: 15000,
      fwmark: 0x88,
      egress_mark: 0x89,
      scope: None,
      table: "arkham_tproxy_test".into(),
    }
  }

  #[test]
  fn install_messages_round_trip_through_netlink_wire_format() {
    for mut msg in config().install_messages() {
      msg.finalize();
      let mut buf = vec![0u8; msg.buffer_len()];
      msg.serialize(&mut buf);
      let parsed = NetlinkMessage::<NetfilterMessage>::deserialize(&buf).expect("deserialize");
      assert_eq!(parsed, msg, "wire round-trip must preserve the message");
    }
  }

  #[test]
  fn teardown_message_round_trips() {
    let mut msg = config().teardown_message();
    msg.finalize();
    let mut buf = vec![0u8; msg.buffer_len()];
    msg.serialize(&mut buf);
    let parsed = NetlinkMessage::<NetfilterMessage>::deserialize(&buf).expect("deserialize");
    assert_eq!(parsed, msg);
  }

  #[test]
  fn install_messages_shape() {
    let msgs = config().install_messages();
    assert_eq!(msgs.len(), 6, "table + two chains + three rules");
    let kinds = msgs.iter().map(|m| match &m.payload {
      netlink_packet_core::NetlinkPayload::InnerMessage(inner) => match &inner.inner {
        NetfilterMessageInner::NfTables(NfTablesMessage::NewTable(_)) => "table",
        NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(c)) => c
          .attributes
          .iter()
          .find_map(|a| match a {
            ChainAttribute::Name(name) => Some(name.as_str()),
            _ => None,
          })
          .unwrap_or("chain"),
        NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(_)) => "rule",
        other => panic!("unexpected message: {other:?}"),
      },
      other => panic!("unexpected payload: {other:?}"),
    });
    assert_eq!(
      kinds.collect::<Vec<_>>(),
      vec!["table", "output", "prerouting", "rule", "rule", "rule"]
    );
  }

  #[test]
  fn scoped_install_matches_exact_daddr_first() {
    let mut cfg = config();
    cfg.scope = Some(Ipv4Addr::new(198, 51, 100, 7));
    let msgs = cfg.install_messages();
    let rules: Vec<&RuleMessage> = msgs_rules(&msgs);
    let first = rules.first().expect("mark rule exists");
    let RuleAttribute::Expressions(exprs) = &first.attributes[2] else {
      panic!("rule carries expressions");
    };
    let ListAttribute::Element(attrs) = &exprs[0] else {
      panic!("first expression is scoped daddr match");
    };
    assert!(
      attrs
        .iter()
        .any(|a| matches!(a, ExpressionAttribute::Name(name) if name == "payload")),
      "first expression must be the payload (daddr) match"
    );
  }

  fn msgs_rules(msgs: &[NetlinkMessage<NetfilterMessage>]) -> Vec<&RuleMessage> {
    msgs
      .iter()
      .filter_map(|m| match &m.payload {
        netlink_packet_core::NetlinkPayload::InnerMessage(inner) => match &inner.inner {
          NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(rule)) => Some(rule),
          _ => None,
        },
        _ => None,
      })
      .collect()
  }
}
