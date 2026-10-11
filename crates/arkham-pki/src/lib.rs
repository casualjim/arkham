//! PKI: the signing CA and per-domain leaf certificates for test stubs.

pub mod ca;
mod error;
pub mod ssh;

pub use ca::{CertAuthority, DomainCert, install_crypto_provider, load_or_generate};
pub use error::Error;
pub use ssh::{SshKey, known_hosts_line, known_hosts_line_for_public, load_or_generate_host_key};
