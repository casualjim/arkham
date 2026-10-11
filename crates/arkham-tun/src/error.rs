//! Typed errors for TUN capture setup and policy routing.

use std::io::Error as IoError;

use rtnetlink::Error as RtnetlinkError;
use tun::Error as TunError;

/// Every way TUN capture setup and policy routing can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A raw I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
  /// The rtnetlink connection cannot be established.
  #[error("netlink: {origin}")]
  Netlink {
    /// Underlying connection failure.
    #[source]
    origin: IoError,
  },
  /// A link lookup by name fails.
  #[error("link {name}: {origin}")]
  LinkGet {
    /// Interface name that was looked up.
    name: String,
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// No interface with the requested name exists.
  #[error("no interface {name}")]
  InterfaceNotFound {
    /// Interface name that was looked up.
    name: String,
  },
  /// Installed routes cannot be listed.
  #[error("route list: {origin}")]
  RouteList {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// A capture-table route cannot be installed.
  #[error("route add: {origin}")]
  RouteAdd {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// A capture-table route cannot be deleted (teardown).
  #[error("route del: {origin}")]
  RouteDel {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// A fib rule cannot be installed.
  #[error("rule add: {origin}")]
  RuleAdd {
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
  #[error("rule del: {origin}")]
  RuleDel {
    /// Underlying rtnetlink failure.
    #[source]
    origin: RtnetlinkError,
  },
  /// The TUN device cannot be created.
  #[error("TUN create: {origin}")]
  TunCreate {
    /// Underlying device failure.
    #[source]
    origin: TunError,
  },
  /// The in-process stack route table is full.
  #[error("route table full")]
  RouteTableFull,
}
