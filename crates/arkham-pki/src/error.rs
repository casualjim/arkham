//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::error::Error as StdError;
use std::io::Error as IoError;
use std::path::PathBuf;
use std::str::Utf8Error;

use rcgen::Error as RcgenError;
use russh::keys::Error as RusshKeysError;
use russh::keys::ssh_key::Error as SshKeyError;
use rustls::Error as RustlsError;
use rustls::pki_types::pem::Error as PemError;

/// Every way CA and leaf certificate handling can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A CA key pair does not generate.
  #[error("failed to generate CA key pair: {source}")]
  Keygen {
    /// Underlying generation failure.
    #[source]
    source: RcgenError,
  },
  /// A CA certificate does not self-sign.
  #[error("failed to self-sign CA certificate: {source}")]
  SelfSign {
    /// Underlying signing failure.
    #[source]
    source: RcgenError,
  },
  /// CA cert bytes are not valid UTF-8.
  #[error("invalid cert PEM: {source}")]
  InvalidCertPem {
    /// Underlying UTF-8 failure.
    #[source]
    source: Utf8Error,
  },
  /// CA key bytes are not valid UTF-8.
  #[error("invalid key PEM: {source}")]
  InvalidKeyPem {
    /// Underlying UTF-8 failure.
    #[source]
    source: Utf8Error,
  },
  /// A CA key does not parse.
  #[error("failed to parse CA key: {source}")]
  ParseKey {
    /// Underlying parse failure.
    #[source]
    source: RcgenError,
  },
  /// A CA cert does not parse.
  #[error("failed to parse CA cert: {source}")]
  ParseCert {
    /// Underlying parse failure.
    #[source]
    source: RcgenError,
  },
  /// PEM bytes do not parse.
  #[error("failed to parse PEM: {source}")]
  ParsePem {
    /// Underlying parse failure.
    #[source]
    source: PemError,
  },
  /// CA cert DER is not a valid boring X509.
  #[error("CA cert DER is not a valid boring X509: {source}")]
  BoringCert {
    /// Underlying parse failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A CA key is not a valid boring PKCS8 key.
  #[error("CA key is not a valid boring PKCS8 key: {source}")]
  BoringKey {
    /// Underlying parse failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// An I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
  /// A CA file lacks its private-key PEM block.
  #[error("{}: no private-key PEM block", path.display())]
  NoKeyBlock {
    /// File missing the key block.
    path: PathBuf,
  },
  /// A raced CA file never becomes readable.
  #[error("{}: CA file never became readable", path.display())]
  NeverReadable {
    /// File that stayed unparseable.
    path: PathBuf,
  },
  /// A domain is not a valid SAN.
  #[error("bad SNI: {source}")]
  BadSni {
    /// Underlying parameter failure.
    #[source]
    source: RcgenError,
  },
  /// A leaf key pair does not generate.
  #[error("keygen: {source}")]
  LeafKeygen {
    /// Underlying generation failure.
    #[source]
    source: RcgenError,
  },
  /// A leaf certificate does not sign.
  #[error("sign: {source}")]
  LeafSign {
    /// Underlying signing failure.
    #[source]
    source: RcgenError,
  },
  /// rustls rejects the built server config.
  #[error("server config: {source}")]
  ServerConfig {
    /// Underlying rustls failure.
    #[source]
    source: RustlsError,
  },
  /// A guest directory cannot be created.
  #[error("create {}: {source}", dir.display())]
  CreateGuestDir {
    /// Directory that could not be created.
    dir: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A guest certificate cannot be written.
  #[error("write {}: {source}", path.display())]
  WriteGuestCert {
    /// File that could not be written.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A guest key cannot be opened.
  #[error("open {}: {source}", path.display())]
  OpenGuestKey {
    /// File that could not be opened.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A guest key cannot be written.
  #[error("write {}: {source}", path.display())]
  WriteGuestKey {
    /// File that could not be written.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// An SSH key pair does not generate.
  #[error("ssh keygen: {source}")]
  SshKeygen {
    /// Underlying generation failure.
    #[source]
    source: SshKeyError,
  },
  /// SSH key material does not parse or encode.
  #[error("ssh key material: {source}")]
  SshKeys {
    /// Underlying russh keys failure.
    #[source]
    source: RusshKeysError,
  },
}
