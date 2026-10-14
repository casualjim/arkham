//! SMTP vertical: the protocol's scope types, its connection-string law,
//! and the rule-to-scope assembly.
//!
//! `smtp://` is a cleartext session that may upgrade with STARTTLS.
//! `smtps://` is implicit TLS from the first byte. The real password is
//! swapped only once the upstream leg is TLS. `starttls=required` on an
//! `smtp://` string is what submission (port 587) demands, and it is what
//! makes trust material legal on that scheme.

use std::path::PathBuf;

use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use super::{Credential, Grant, GuestTlsMode, RootCert, Scheme};
use crate::config::RuleCfg;
use crate::error::Error;

/// One leg of an SMTP rule: the connection facts of one connection string.
#[derive(Debug, Clone)]
pub struct SmtpLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// AUTH identity this leg presents.
  pub user: String,
  /// AUTH secret this leg presents.
  pub password: SecretString,
}

/// An SMTP rule's scope: both legs of its one connection-string mapping.
///
/// Each string states its own transport in its scheme. `smtp://` is
/// cleartext (STARTTLS when the peer asks, or when the real string says
/// `starttls=required`). `smtps://` is TLS from the first byte. Trust and
/// identity ride the real string's query (`sslrootcert`, `sslcert`/`sslkey`);
/// the rule's `tls` table states the guest leg's mode, keyed by the rule's
/// env name.
#[derive(Debug, Clone)]
pub struct SmtpScope {
  /// The guest's leg, from the rule's stated fake connection string.
  pub downstream: SmtpLeg,
  /// Whether the guest leg is implicit TLS (an `smtps://` fake string).
  pub is_downstream_tls: bool,
  /// The server's leg, from the resolved real connection string.
  pub upstream: SmtpLeg,
  /// Whether the upstream leg is implicit TLS (an `smtps://` real string).
  pub is_upstream_tls: bool,
  /// The real string says the server requires STARTTLS before AUTH.
  pub starttls_required: bool,
  /// Trust anchor for upstream verification, when the real string names one.
  pub root_cert: Option<RootCert>,
  /// PEM client certificate for upstream authentication, when named.
  pub client_cert: Option<PathBuf>,
  /// PEM client key, paired with [`Self::client_cert`].
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// One parsed `smtp://` or `smtps://` string.
#[derive(Debug)]
struct SmtpUri {
  scheme: Scheme,
  host: String,
  port: u16,
  user: String,
  password: SecretString,
  starttls_required: bool,
  query: Vec<(String, String)>,
}

impl SmtpUri {
  /// Parse one SMTP connection string. The user and the password are both
  /// required: a string with no AUTH identity maps nothing.
  fn parse(entry: &str) -> Result<Self, String> {
    let scheme = if entry.starts_with("smtps://") {
      Scheme::Smtps
    } else if entry.starts_with("smtp://") {
      Scheme::Smtp
    } else {
      return Err(format!("bad connection string `{entry}`: expected smtp:// or smtps://"));
    };
    let url = Url::parse(entry).map_err(|err| format!("bad connection string `{entry}`: {err}"))?;
    let host = url
      .host()
      .map(|host| host.to_string())
      .ok_or_else(|| format!("bad connection string `{entry}`: empty host"))?;
    // `Url` leaves userinfo percent-encoded. An SMTP user is an address,
    // so `@` is written `%40` and has to be decoded before AUTH.
    let user = userinfo_decode(entry, "user", url.username())?;
    if user.is_empty() {
      return Err(format!(
        "bad connection string `{entry}`: the user is required — a string with no AUTH identity maps nothing"
      ));
    }
    let password = match url.password().filter(|password| !password.is_empty()) {
      Some(password) => SecretString::new(userinfo_decode(entry, "password", password)?.into()),
      None => {
        return Err(format!(
          "bad connection string `{entry}`: the password is required — a string with no credential maps nothing"
        ));
      }
    };
    if url.path() != "" && url.path() != "/" {
      return Err(format!("bad connection string `{entry}`: an SMTP string has no path"));
    }
    let mut starttls_required = false;
    let mut query = Vec::new();
    for (key, value) in url.query_pairs() {
      if key == "starttls" {
        if scheme == Scheme::Smtps {
          return Err(format!(
            "bad connection string `{entry}`: smtps:// is already TLS; `starttls` belongs on smtp://"
          ));
        }
        if value != "required" {
          return Err(format!(
            "bad connection string `{entry}`: starttls is `required` or absent, not `{value}`"
          ));
        }
        starttls_required = true;
        continue;
      }
      query.push((key.to_string(), value.to_string()));
    }
    let default_port = if scheme == Scheme::Smtps { 465 } else { 25 };
    Ok(Self {
      scheme,
      host,
      port: url.port().unwrap_or(default_port),
      user,
      password,
      starttls_required,
      query,
    })
  }

  /// The leg a rule builds from this string.
  fn leg(self) -> SmtpLeg {
    SmtpLeg {
      host: self.host,
      port: self.port,
      user: self.user,
      password: self.password,
    }
  }
}

/// Trust and identity from the real string's query. Legal on `smtps://`
/// and on `smtp://` that requires STARTTLS; cleartext AUTH carries none.
struct SmtpTls {
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

/// Percent-decode one userinfo component. `+` stays a plus: userinfo is
/// not a query string.
fn userinfo_decode(entry: &str, label: &str, raw: &str) -> Result<String, String> {
  let bytes = raw.as_bytes();
  let mut out = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while let Some(byte) = bytes.get(index).copied() {
    if byte != b'%' {
      out.push(byte);
      index = index.saturating_add(1);
      continue;
    }
    let hi = bytes.get(index.saturating_add(1)).copied();
    let lo = bytes.get(index.saturating_add(2)).copied();
    let Some(value) = hi.zip(lo).and_then(|(hi, lo)| hex_byte(hi, lo)) else {
      return Err(format!(
        "bad connection string `{entry}`: the {label} is not valid percent-encoding"
      ));
    };
    out.push(value);
    index = index.saturating_add(3);
  }
  String::from_utf8(out).map_err(|_err| format!("bad connection string `{entry}`: the {label} is not valid UTF-8"))
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
  let hi = hex_nibble(hi)?;
  let lo = hex_nibble(lo)?;
  hi.checked_mul(16)?.checked_add(lo)
}

fn hex_nibble(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => byte.checked_sub(b'0'),
    b'a'..=b'f' => byte.checked_sub(b'a').and_then(|n| n.checked_add(10)),
    b'A'..=b'F' => byte.checked_sub(b'A').and_then(|n| n.checked_add(10)),
    _ => None,
  }
}

fn smtp_tls(entry: &str, tls_leg: bool, uri: &SmtpUri) -> Result<SmtpTls, String> {
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in &uri.query {
    let tls_material = match key.as_str() {
      "sslmode" | "ssl" | "sslnegotiation" => {
        return Err(format!(
          "bad connection string `{entry}`: smtp strings state their transport in the scheme, never in `{key}`"
        ));
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslrootcert needs a path"));
        }
        Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value))
        })
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslcert needs a path"));
        }
        client_cert = Some(PathBuf::from(value));
        None
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslkey needs a path"));
        }
        client_key = Some(PathBuf::from(value));
        None
      }
      _ => return Err(format!("bad connection string `{entry}`: unknown query `{key}`")),
    };
    if let Some(root) = tls_material {
      if !tls_leg {
        return Err(format!(
          "bad connection string `{entry}`: cleartext `smtp://` carries no TLS state; trust belongs on `smtps://` or `starttls=required`"
        ));
      }
      root_cert = Some(root);
    }
  }
  if !tls_leg && (client_cert.is_some() || client_key.is_some()) {
    return Err(format!(
      "bad connection string `{entry}`: cleartext `smtp://` carries no TLS state; identity belongs on `smtps://` or `starttls=required`"
    ));
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(format!("bad connection string `{entry}`: sslcert and sslkey come together"));
  }
  Ok(SmtpTls {
    root_cert,
    client_cert,
    client_key,
  })
}

impl SmtpScope {
  /// Both legs of an SMTP rule from its two connection strings: the fake
  /// the rule states, the real the secret source resolved.
  ///
  /// # Errors
  ///
  /// Either string is not an `smtp://` or `smtps://` connection string, or
  /// its query breaks the law above.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, String> {
    let downstream = SmtpUri::parse(fake)?;
    let upstream = SmtpUri::parse(real)?;
    let upstream_tls = upstream.scheme == Scheme::Smtps || upstream.starttls_required;
    let SmtpTls {
      root_cert,
      client_cert,
      client_key,
    } = smtp_tls(real, upstream_tls, &upstream)?;
    Ok(Self {
      is_downstream_tls: downstream.scheme == Scheme::Smtps,
      downstream: downstream.leg(),
      is_upstream_tls: upstream.scheme == Scheme::Smtps,
      starttls_required: upstream.starttls_required,
      upstream: upstream.leg(),
      root_cert,
      client_cert,
      client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  pub(super) fn matches(scope: &Self, scheme: Scheme, host: &str, port: u16) -> bool {
    matches!(scheme, Scheme::Smtp | Scheme::Smtps) && port == scope.downstream.port && scope.downstream.host.eq_ignore_ascii_case(host)
  }
}

/// Assemble one SMTP grant from its rule.
///
/// # Errors
///
/// Returns an error when either string fails the law above, or when a
/// `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = SmtpScope::from_strings(&fake, real).map_err(|err| Error::SmtpScope {
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
      return Err(Error::SmtpIdentity { label: label.to_string() });
    }
    if tls.root_cert.is_some() {
      return Err(Error::SmtpTrust { label: label.to_string() });
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  if !scope.is_upstream_tls && !scope.starttls_required {
    tracing::warn!(
      label,
      host = %scope.upstream.host,
      port = scope.upstream.port,
      "smtp:// upstream is cleartext; AUTH forwards the decoy until that leg is TLS"
    );
  }
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Smtp {
    credential,
    scope: Box::new(scope),
  })
}
