//! LDAP vertical: the protocol's scope types, its own connection-string
//! law (each string's scheme states how that leg opens), and the
//! rule-to-scope assembly.

use std::path::PathBuf;

use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use super::{Credential, Grant, GuestTlsMode, RootCert, Scheme};
use crate::config::RuleCfg;
use crate::error::Error;

/// One leg of an LDAP rule: the connection facts of one connection string.
#[derive(Debug, Clone)]
pub struct LdapLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// Bind DN this leg presents.
  pub dn: String,
  /// Simple-bind password this leg presents.
  pub password: SecretString,
}

/// An LDAP rule's scope: both legs of its one connection-string mapping.
/// Each string states how its leg opens: `ldap://` is cleartext (and may
/// upgrade with `StartTLS`), `ldaps://` is TLS from the first byte. Trust
/// and identity ride the real string's query (`sslrootcert`,
/// `sslcert`/`sslkey`); the rule's `tls` table states the guest leg's
/// mode, keyed by the rule's env name.
#[derive(Debug, Clone)]
pub struct LdapScope {
  /// The guest's leg, from the rule's stated fake connection string.
  pub downstream: LdapLeg,
  /// Whether the guest leg is TLS from the first byte (an `ldaps://` fake string).
  pub is_downstream_tls: bool,
  /// The server's leg, from the resolved real connection string.
  pub upstream: LdapLeg,
  /// Whether the upstream leg is TLS from the first byte (an `ldaps://` real string).
  pub is_upstream_tls: bool,
  /// Trust anchor for upstream verification, when the real string names one.
  /// `StartTLS` uses it after the upgrade; LDAPS uses it on connect.
  pub root_cert: Option<RootCert>,
  /// PEM client certificate for upstream mTLS, when the real string names one.
  pub client_cert: Option<PathBuf>,
  /// PEM client key for upstream mTLS, when the real string names one.
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// One parsed `ldap://` or `ldaps://` string.
#[derive(Debug)]
struct LdapUri {
  scheme: Scheme,
  host: String,
  port: u16,
  dn: String,
  password: SecretString,
  query: Vec<(String, String)>,
}

impl LdapUri {
  /// Parse one LDAP connection string. The bind DN and password are
  /// required — a string with no credential maps nothing.
  fn parse(entry: &str) -> Result<Self, String> {
    let scheme = if entry.starts_with("ldaps://") {
      Scheme::Ldaps
    } else if entry.starts_with("ldap://") {
      Scheme::Ldap
    } else {
      return Err(format!("bad connection string `{entry}`: expected ldap:// or ldaps://"));
    };
    let url = Url::parse(entry).map_err(|err| format!("bad connection string `{entry}`: {err}"))?;
    let host = url
      .host()
      .map(|host| host.to_string())
      .ok_or_else(|| format!("bad connection string `{entry}`: empty host"))?;
    if url.username().is_empty() {
      return Err(format!(
        "bad connection string `{entry}`: the bind dn is required — a string with no credential maps nothing"
      ));
    }
    let dn = percent_decode(entry, "bind dn", url.username())?;
    if dn.is_empty() {
      return Err(format!(
        "bad connection string `{entry}`: the bind dn is required — a string with no credential maps nothing"
      ));
    }
    let password = url
      .password()
      .filter(|password| !password.is_empty())
      .ok_or_else(|| format!("bad connection string `{entry}`: the password is required — a string with no credential maps nothing"))?;
    let password = SecretString::new(percent_decode(entry, "password", password)?.into());
    if password.expose_secret().is_empty() {
      return Err(format!(
        "bad connection string `{entry}`: the password is required — a string with no credential maps nothing"
      ));
    }
    if !matches!(url.path(), "" | "/") {
      return Err(format!("bad connection string `{entry}`: an ldap string has no path"));
    }
    let port = url.port().unwrap_or(if scheme == Scheme::Ldaps { 636 } else { 389 });
    Ok(Self {
      scheme,
      host,
      port,
      dn,
      password,
      query: url.query_pairs().map(|(key, value)| (key.to_string(), value.to_string())).collect(),
    })
  }

  /// The leg a rule builds from this string.
  fn leg(self) -> LdapLeg {
    LdapLeg {
      host: self.host,
      port: self.port,
      dn: self.dn,
      password: self.password,
    }
  }
}

/// `username()` and `password()` keep the percent-encoding from the string.
/// The directory sees the decoded bind DN and password.
fn percent_decode(entry: &str, what: &str, raw: &str) -> Result<String, String> {
  let bytes = raw.as_bytes();
  let mut out = Vec::with_capacity(bytes.len());
  let mut index = 0usize;
  while index < bytes.len() {
    let Some(byte) = bytes.get(index).copied() else {
      return Err(format!("bad connection string `{entry}`: {what} is truncated"));
    };
    if byte != b'%' {
      out.push(byte);
      index = index
        .checked_add(1)
        .ok_or_else(|| format!("bad connection string `{entry}`: {what} is too long"))?;
      continue;
    }
    let hi_at = index
      .checked_add(1)
      .ok_or_else(|| format!("bad connection string `{entry}`: {what} is too long"))?;
    let lo_at = index
      .checked_add(2)
      .ok_or_else(|| format!("bad connection string `{entry}`: {what} is too long"))?;
    let (Some(hi), Some(lo)) = (bytes.get(hi_at).copied(), bytes.get(lo_at).copied()) else {
      return Err(format!("bad connection string `{entry}`: {what} has a truncated percent escape"));
    };
    let Some(value) = hex_byte(hi, lo) else {
      return Err(format!("bad connection string `{entry}`: {what} has a bad percent escape"));
    };
    out.push(value);
    index = lo_at
      .checked_add(1)
      .ok_or_else(|| format!("bad connection string `{entry}`: {what} is too long"))?;
  }
  String::from_utf8(out).map_err(|_utf8| format!("bad connection string `{entry}`: {what} is not utf-8"))
}

/// One decoded percent-escape byte.
fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
  let hi = hex_nibble(hi)?;
  let lo = hex_nibble(lo)?;
  hi.checked_shl(4)?.checked_add(lo)
}

/// One hex digit.
fn hex_nibble(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => byte.checked_sub(b'0'),
    b'a'..=b'f' => byte.checked_sub(b'a')?.checked_add(10),
    b'A'..=b'F' => byte.checked_sub(b'A')?.checked_add(10),
    _ => None,
  }
}

/// Trust and identity from one string's query. Both schemes may carry it:
/// `ldaps://` verifies on connect, and `ldap://` verifies after `StartTLS`.
struct LdapTls {
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

fn ldap_tls(entry: &str, uri: &LdapUri) -> Result<LdapTls, String> {
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in &uri.query {
    match key.as_str() {
      "sslmode" | "ssl" => {
        return Err(format!(
          "bad connection string `{entry}`: ldap strings state their transport in the scheme, never in `sslmode`"
        ));
      }
      "sslnegotiation" => {
        return Err(format!(
          "bad connection string `{entry}`: ldap strings state their transport in the scheme, never in `sslnegotiation`"
        ));
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslrootcert needs a path"));
        }
        root_cert = Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value))
        });
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslcert needs a path"));
        }
        client_cert = Some(PathBuf::from(value));
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslkey needs a path"));
        }
        client_key = Some(PathBuf::from(value));
      }
      _ => return Err(format!("bad connection string `{entry}`: unknown query `{key}`")),
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(format!("bad connection string `{entry}`: sslcert and sslkey come together"));
  }
  Ok(LdapTls {
    root_cert,
    client_cert,
    client_key,
  })
}

impl LdapScope {
  /// Both legs of an LDAP rule from its two connection strings.
  ///
  /// # Errors
  /// Either string is not an `ldap://` or `ldaps://` connection string,
  /// or its query breaks the ldap law above.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, String> {
    let downstream = LdapUri::parse(fake)?;
    let upstream = LdapUri::parse(real)?;
    let _ = ldap_tls(fake, &downstream)?;
    let LdapTls {
      root_cert,
      client_cert,
      client_key,
    } = ldap_tls(real, &upstream)?;
    Ok(Self {
      is_downstream_tls: downstream.scheme == Scheme::Ldaps,
      downstream: downstream.leg(),
      is_upstream_tls: upstream.scheme == Scheme::Ldaps,
      upstream: upstream.leg(),
      root_cert,
      client_cert,
      client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  pub(super) fn matches(scope: &Self, scheme: Scheme, host: &str, port: u16) -> bool {
    matches!(scheme, Scheme::Ldap | Scheme::Ldaps) && port == scope.downstream.port && scope.downstream.host.eq_ignore_ascii_case(host)
  }
}

/// Assemble one LDAP grant from its rule.
///
/// # Errors
///
/// Returns an error when either string fails the ldap law above, or when
/// a `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = LdapScope::from_strings(&fake, real).map_err(|err| Error::LdapScope {
    label: label.to_string(),
    detail: err,
  })?;
  for (key, tls) in &rule.tls {
    if key != &rule.env {
      return Err(Error::TlsEnvMismatch {
        label: label.to_string(),
        key: key.clone(),
        env: rule.env.clone(),
      });
    }
    if tls.client_cert.is_some() || tls.client_key.is_some() {
      return Err(Error::LdapIdentity { label: label.to_string() });
    }
    if tls.root_cert.is_some() {
      return Err(Error::LdapTrust { label: label.to_string() });
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Ldap {
    credential,
    scope: Box::new(scope),
  })
}
