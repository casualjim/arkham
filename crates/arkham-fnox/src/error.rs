//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::path::PathBuf;

use arkham_config::Error as ConfigError;
use fnox_core::FnoxError;

/// Every way fnox discovery and secret resolution can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// fnox discovery fails.
  #[error("fnox discovery failed: {source}")]
  Discovery {
    /// Underlying discovery failure.
    #[source]
    source: Box<FnoxError>,
  },
  /// Active profiles do not resolve.
  #[error("fnox profiles: {source}")]
  Profiles {
    /// Underlying profile failure.
    #[source]
    source: Box<FnoxError>,
  },
  /// Declared secrets cannot be listed.
  #[error("fnox: cannot list secrets: {source}")]
  ListSecrets {
    /// Underlying listing failure.
    #[source]
    source: Box<FnoxError>,
  },
  /// One config file does not load.
  #[error("fnox config {}: {source}", path.display())]
  ConfigFile {
    /// File that did not load.
    path: PathBuf,
    /// Underlying load failure.
    #[source]
    source: Box<FnoxError>,
  },
  /// One secret does not read.
  #[error("fnox secret `{key}`: {source}")]
  Secret {
    /// Secret key.
    key: String,
    /// Underlying read failure.
    #[source]
    source: Box<FnoxError>,
  },
  /// A declared key resolves to no value.
  #[error("fnox key `{key}` is declared but resolves to no value")]
  DeclaredNoValue {
    /// Secret key.
    key: String,
  },
  /// A declared key resolves to an empty value.
  #[error("fnox key `{key}` is declared but resolves to an empty value")]
  DeclaredEmpty {
    /// Secret key.
    key: String,
  },
  /// A rule resolves to no usable grant.
  #[error("rule `{label}` (env {env}): {detail}")]
  UnresolvedRule {
    /// Rule label.
    label: String,
    /// Rule env name.
    env: String,
    /// Why the rule drops.
    detail: String,
  },
  /// A registry error passes through from `arkham-config`.
  #[error(transparent)]
  Registry(Box<ConfigError>),
}

impl From<ConfigError> for Error {
  fn from(source: ConfigError) -> Self {
    Self::Registry(Box::new(source))
  }
}
