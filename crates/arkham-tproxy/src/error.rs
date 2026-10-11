//! Typed errors for kernel TPROXY capture setup, serving, and teardown.

use std::error::Error as StdError;
use std::io::Error as IoError;

use netlink_packet_core::ErrorMessage;
use rtnetlink::Error as RtnetlinkError;
use tokio::task::JoinError;

/// Every way TPROXY capture setup, serving, and teardown can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A network-namespace path cannot be statted.
  #[error("stat {path}: {origin}")]
  Stat {
    /// Namespace path that could not be statted.
    path: String,
    /// Underlying I/O failure.
    #[source]
    origin: IoError,
  },
  /// The rtnetlink connection cannot be established.
  #[error("netlink: {origin}")]
  Netlink {
    /// Underlying connection failure.
    #[source]
    origin: IoError,
  },
  /// A link lookup by name fails.
  #[error("link get {name}: {origin}")]
  LinkGet {
    /// Interface name that was looked up.
    name: String,
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// No interface with the requested name exists.
  #[error("interface {name} not found")]
  InterfaceNotFound {
    /// Interface name that was looked up.
    name: String,
  },
  /// A local route cannot be installed.
  #[error("local route add: {origin}")]
  LocalRouteAdd {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// A fib rule cannot be installed.
  #[error("rule add pref {pref}: {origin}")]
  RuleAdd {
    /// Rule priority that was installed.
    pref: u32,
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// Installed fib rules cannot be listed (teardown).
  #[error("rule list: {origin}")]
  RuleList {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// A fib rule cannot be deleted (teardown).
  #[error("rule del pref {pref}: {origin}")]
  RuleDel {
    /// Rule priority that was deleted.
    pref: u32,
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// Installed routes cannot be listed (teardown).
  #[error("route list: {origin}")]
  RouteList {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// A route cannot be deleted (teardown).
  #[error("route del: {origin}")]
  RouteDel {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// Unscoped capture in the host network namespace is refused.
  #[error(
    "refusing to install unscoped TPROXY capture rules in the host network namespace: every outbound TCP packet \
     would be rerouted into arkham until the process exits cleanly. Run inside a network namespace (bubblewrap / ip \
     netns / VM) or pass --tproxy-allow-root-netns (env ARKHAM_TPROXY_ALLOW_ROOT_NETNS=1) if this machine is disposable"
  )]
  UnscopedCapture,
  /// A raw I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
  /// The receive timeout cannot be set on the nft netlink socket.
  #[error("SO_RCVTIMEO on nft socket: {origin}")]
  SetsockoptTimeout {
    /// Underlying I/O failure.
    #[source]
    origin: IoError,
  },
  /// The transparent listener address cannot be read back.
  #[error("tproxy local addr: {origin}")]
  TproxyLocalAddr {
    /// Underlying I/O failure.
    #[source]
    origin: IoError,
  },
  /// A captured connection cannot be accepted.
  #[error("tproxy accept: {origin}")]
  TproxyAccept {
    /// Underlying I/O failure.
    #[source]
    origin: IoError,
  },
  /// The transparent listener cannot be bound.
  #[error("tproxy bind: {source}")]
  TproxyBind {
    /// Underlying bind failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The nft install task fails to join.
  #[error("nft install task: {source}")]
  NftInstallTask {
    /// Underlying join failure.
    #[source]
    source: JoinError,
  },
  /// A netfilter reply cannot be deserialized.
  #[error("{source} (raw {len} bytes: {hex})")]
  NftDeserialize {
    /// Underlying deserialization failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
    /// Rejected reply length in bytes.
    len: usize,
    /// First bytes of the rejected reply, hex.
    hex: String,
  },
  /// The kernel rejects the nft batch.
  #[error("nft batch failed: {reply}")]
  NftBatchFailed {
    /// The kernel's error reply (a payload, not a std error).
    reply: ErrorMessage,
  },
  /// The kernel answers the nft batch with an unexpected reply.
  #[error("unexpected nft batch reply: {detail}")]
  UnexpectedNftReply {
    /// Debug rendering of the unexpected payload.
    detail: String,
  },
  /// A captured connection fails downstream (proxy leg preserves its own message).
  #[error(transparent)]
  TransparentStream(#[from] arkham_proxy::Error),
}
