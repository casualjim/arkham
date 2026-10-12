//! Known-host registry: bundled host and decoy-shape table plus `rules.d`
//! overrides.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use url::{Host, Url};

use crate::config::{RuleCfg, validate_pattern};
use crate::error::Error;
use crate::grants::{EndpointScope, HostPat, Scheme, uri_match};

/// Bundled registry: environment names, API hosts, and token shapes.
const BUNDLED: &str = include_str!("../../../rules/registry.toml");

/// Which `OAuth2` flow a token issuer runs, per RFC 6749 and `OpenAPI`'s
/// `securitySchemes` vocabulary. The flow decides which response bodies
/// mint decoys and which fields are expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
  /// Machine-to-machine: `client_credentials` grant, `access_token` only.
  ClientCredentials,
  /// Browser-driven: `authorization_code` grant with an authorize endpoint.
  AuthorizationCode,
  /// Refresh-grant exchanges against a previously issued refresh token.
  Refresh,
}

/// One token issuer's `OAuth2` flow endpoints and expectations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthFlow {
  /// Which flow this entry describes.
  pub flow: FlowKind,
  /// Token endpoint authority, granted like `hosts`.
  pub token_url: String,
  /// Authorize endpoint authority (`authorization_code` only), granted like `hosts`.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub authorize_url: Option<String>,
  /// Refresh endpoint authority when it differs from `token_url`.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub refresh_url: Option<String>,
  /// The issuer rotates `refresh_token` on every refresh (RFC 6749 §6).
  #[serde(default)]
  pub rotates_refresh: bool,
  /// Response body fields to mint, overriding the RFC 6749 defaults.
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub token_fields: Vec<String>,
}

impl OAuthFlow {
  /// Field names minted from token responses for this flow shape.
  ///
  /// `access_token` and `refresh_token` are the credentials an agent can
  /// hold; `token_type` (`"Bearer"`) and `expires_in` (a number) are not
  /// secrets, so they pass through untouched.
  #[must_use]
  pub fn fields(&self) -> Vec<&str> {
    let mut fields = vec!["access_token"];
    if matches!(self.flow, FlowKind::AuthorizationCode) || self.rotates_refresh {
      fields.push("refresh_token");
    }
    fields
  }
}

/// What the registry knows about one environment name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHosts {
  /// Raw `scheme://host[:port]` entries, in declaration order.
  pub hosts: Vec<String>,
  /// Decoy template, if any entry supplies one.
  pub pattern: Option<String>,
  /// `OAuth2` token-issuer flow, if any entry declares one.
  pub oauth2: Option<OAuthFlow>,
}

/// Known hosts and decoy shapes: bundled table plus `rules.d` overrides.
#[derive(Debug, Clone, Default)]
pub struct Registry {
  /// Entry per uppercase environment name.
  names: BTreeMap<String, KnownHosts>,
  /// `contains` rules in load order.
  contains: Vec<ContainsRule>,
}

/// One `[providers.*].contains` rule: which provider declared it, the
/// lowercase substring matched against an env name, and the pattern it picks.
#[derive(Debug, Clone)]
struct ContainsRule {
  /// Provider that declared it; `replace = true` clears that provider's rules.
  provider: String,
  /// Lowercase substring tested against the env name.
  needle: String,
  /// Decoy template selected when the needle matches.
  pattern: String,
}

/// A registry file as written: `[providers.*]` and `[names.*]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
  /// Service-centric entries.
  #[serde(default)]
  providers: BTreeMap<String, ProviderEntry>,
  /// Exact environment-name entries.
  #[serde(default)]
  names: BTreeMap<String, NameEntry>,
}

/// One service entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEntry {
  /// Environment names this provider claims.
  #[serde(default)]
  env: Vec<String>,
  /// Hosts every claimed name may reach.
  #[serde(default)]
  hosts: Vec<String>,
  /// Decoy template for every claimed name.
  #[serde(default)]
  pattern: Option<String>,
  /// Environment-name substrings that select `pattern` only.
  #[serde(default)]
  contains: Vec<String>,
  /// Discard earlier layers for the keys this entry covers.
  #[serde(default)]
  replace: bool,
  /// `OAuth2` flow this provider's token issuer runs, if any.
  #[serde(default)]
  oauth2: Option<OAuthFlow>,
}

/// One exact environment-name entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameEntry {
  /// Hosts this name may reach.
  #[serde(default)]
  hosts: Vec<String>,
  /// Decoy template for this name.
  #[serde(default)]
  pattern: Option<String>,
  /// Discard earlier layers for this name.
  #[serde(default)]
  replace: bool,
  /// `OAuth2` flow this name's token issuer runs, if any.
  #[serde(default)]
  oauth2: Option<OAuthFlow>,
}

impl Registry {
  /// Load the bundled table, then one override directory.
  ///
  /// # Errors
  ///
  /// Returns an error when the bundled table is malformed, when the override
  /// directory cannot be read, or when an override does not parse.
  pub fn load(rules_dir: Option<&Path>) -> Result<Self, Error> {
    Self::load_union(rules_dir, None)
  }

  /// Load the bundled table, then the global override directory, then the
  /// project one: later files win, mirroring the `[rules]` label merge.
  ///
  /// # Errors
  ///
  /// Returns an error when the bundled table is malformed, when an override
  /// directory cannot be read, or when an override does not parse.
  pub fn load_union(global: Option<&Path>, project: Option<&Path>) -> Result<Self, Error> {
    let dirs = [global, project].into_iter().flatten().collect::<Vec<_>>();
    let mut registry = Self::default();
    registry.apply(BUNDLED, Path::new("<bundled>"))?;
    for dir in dirs.iter().filter(|dir| dir.is_dir()) {
      let mut files = fs::read_dir(dir)
        .map_err(|source| Error::ReadFile {
          path: dir.to_path_buf(),
          source,
        })?
        .map(|entry| {
          entry.map(|entry| entry.path()).map_err(|source| Error::ReadFile {
            path: dir.to_path_buf(),
            source,
          })
        })
        .collect::<Result<Vec<_>, Error>>()?;
      files.retain(|path| path.extension().is_some_and(|ext| ext == "toml"));
      files.sort();
      for path in files {
        let text = fs::read_to_string(&path).map_err(|source| Error::ReadFile {
          path: path.clone(),
          source,
        })?;
        registry.apply(&text, &path)?;
      }
    }
    Ok(registry)
  }

  /// Merge one registry file over what is already loaded.
  fn apply(&mut self, text: &str, source: &Path) -> Result<(), Error> {
    let file: RegistryFile = toml::from_str(text).map_err(|err| Error::ParseFile {
      path: source.to_path_buf(),
      source: Box::new(err),
    })?;
    // One file claiming the same name twice is a data bug; a later file
    // overriding an earlier one is the intended mechanism.
    let mut claimed: BTreeMap<String, &str> = BTreeMap::new();
    for (provider, entry) in &file.providers {
      for env in &entry.env {
        if let Some(previous) = claimed.insert(env.to_ascii_uppercase(), provider.as_str()) {
          return Err(Error::ClaimConflict {
            file: source.to_path_buf(),
            previous: previous.to_string(),
            provider: provider.clone(),
            env: env.clone(),
          });
        }
      }
    }
    for (provider, entry) in &file.providers {
      self.apply_provider(provider, entry, source)?;
    }
    for (env, entry) in &file.names {
      self.apply_name(env, entry, source)?;
    }
    Ok(())
  }

  /// Apply one `[providers.<name>]` entry.
  fn apply_provider(&mut self, provider: &str, entry: &ProviderEntry, source: &Path) -> Result<(), Error> {
    validate_hosts(&entry.hosts, source, "provider", provider)?;
    let pattern = entry.pattern.as_deref().filter(|pattern| !pattern.is_empty());
    validate_optional_pattern(pattern, source, "provider", provider)?;
    if let Some(flow) = &entry.oauth2 {
      validate_flow(flow, &source.display().to_string(), provider)?;
    }
    for env in &entry.env {
      let slot = self.names.entry(env.to_ascii_uppercase()).or_default();
      if entry.replace {
        slot.hosts.clear();
        slot.pattern = None;
        slot.oauth2 = None;
      }
      for host in &entry.hosts {
        if !slot.hosts.contains(host) {
          slot.hosts.push(host.clone());
        }
      }
      if let Some(pattern) = pattern {
        slot.pattern = Some(pattern.to_string());
      }
      if entry.oauth2.is_some() {
        slot.oauth2.clone_from(&entry.oauth2);
      }
    }
    if entry.replace {
      self.contains.retain(|rule| rule.provider != provider);
    }
    for needle in &entry.contains {
      if needle.is_empty() {
        return Err(Error::EmptyContains {
          file: source.to_path_buf(),
          provider: provider.to_string(),
        });
      }
      let Some(pattern) = pattern else {
        return Err(Error::ContainsNeedsPattern {
          file: source.to_path_buf(),
          provider: provider.to_string(),
        });
      };
      self.contains.push(ContainsRule {
        provider: provider.to_string(),
        needle: needle.to_ascii_lowercase(),
        pattern: pattern.to_string(),
      });
    }
    Ok(())
  }

  /// Apply one `[names.<ENV>]` entry.
  fn apply_name(&mut self, env: &str, entry: &NameEntry, source: &Path) -> Result<(), Error> {
    validate_hosts(&entry.hosts, source, "name", env)?;
    let pattern = entry.pattern.as_deref().filter(|pattern| !pattern.is_empty());
    validate_optional_pattern(pattern, source, "name", env)?;
    if let Some(flow) = &entry.oauth2 {
      validate_flow(flow, &source.display().to_string(), env)?;
    }
    let slot = self.names.entry(env.to_ascii_uppercase()).or_default();
    if entry.replace {
      slot.hosts.clear();
      slot.pattern = None;
      slot.oauth2 = None;
    }
    for host in &entry.hosts {
      if !slot.hosts.contains(host) {
        slot.hosts.push(host.clone());
      }
    }
    if let Some(pattern) = pattern {
      slot.pattern = Some(pattern.to_string());
    }
    if entry.oauth2.is_some() {
      slot.oauth2.clone_from(&entry.oauth2);
    }
    Ok(())
  }

  /// Known hosts and pattern for one environment name, `None` when absent.
  #[must_use]
  pub fn lookup(&self, env: &str) -> Option<&KnownHosts> {
    self.names.get(&env.to_ascii_uppercase())
  }

  /// Environment names whose registry hosts cover one endpoint, sorted by
  /// name. The reverse of [`Registry::lookup`]: the join a derived-rule
  /// source runs when it knows a host (a git remote) and needs the names
  /// that could substitute credentials for it.
  #[must_use]
  pub fn envs_for_host(&self, scheme: Scheme, host: &str, port: u16) -> Vec<String> {
    self
      .names
      .iter()
      .filter(|(_, known)| {
        known.hosts.iter().any(|entry| {
          entry
            .parse::<EndpointScope>()
            .is_ok_and(|scope| uri_match(std::slice::from_ref(&scope), scheme, host, port))
        })
      })
      .map(|(env, _)| env.clone())
      .collect()
  }

  /// Decoy template for one environment name: explicit, then registry, then default.
  #[must_use]
  pub fn template<'a>(&'a self, env: &str, explicit: Option<&'a str>) -> Cow<'a, str> {
    if let Some(pattern) = explicit.filter(|pattern| !pattern.is_empty()) {
      return Cow::Borrowed(pattern);
    }
    if let Some(pattern) = self.names.get(&env.to_ascii_uppercase()).and_then(|entry| entry.pattern.as_deref()) {
      return Cow::Borrowed(pattern);
    }
    let lower = env.to_ascii_lowercase();
    if let Some(rule) = self.contains.iter().find(|rule| lower.contains(rule.needle.as_str())) {
      return Cow::Borrowed(&rule.pattern);
    }
    Cow::Borrowed(crate::config::DEFAULT_PATTERN)
  }

  /// Deterministic decoy for one environment name.
  #[must_use]
  pub fn decoy(&self, env: &str, explicit: Option<&str>) -> String {
    crate::config::fake_for(env, Some(&self.template(env, explicit)))
  }

  /// Registry hosts for one rule, honoring `registry = false`.
  #[must_use]
  pub fn hosts_for(&self, rule: &RuleCfg) -> &[String] {
    if rule.registry == Some(false) {
      return &[];
    }
    self.lookup(&rule.env).map_or(&[], |known| known.hosts.as_slice())
  }

  /// `OAuth2` flow for one rule, honoring `registry = false` and a rule-level
  /// override.
  #[must_use]
  pub fn flow_for(&self, rule: &RuleCfg) -> Option<OAuthFlow> {
    if let Some(flow) = &rule.oauth2 {
      return Some(flow.clone());
    }
    if rule.registry == Some(false) {
      return None;
    }
    self.lookup(&rule.env).and_then(|known| known.oauth2.clone())
  }
}

/// Validate one `OAuth2` flow block: endpoint authorities parse, and the
/// required fields for the flow kind are present.
///
/// # Errors
///
/// Returns an error naming the rule when an endpoint URL does not parse
/// or the flow kind lacks its required endpoint.
pub fn validate_flow(flow: &OAuthFlow, source: &str, name: &str) -> Result<(), Error> {
  for url in [&Some(flow.token_url.clone()), &flow.authorize_url, &flow.refresh_url]
    .into_iter()
    .flatten()
  {
    let authority = flow_authority(url).map_err(|err| Error::BadOAuthUrl {
      origin: source.to_string(),
      name: name.to_string(),
      source: Box::new(err),
    })?;
    if matches!(authority, HostPat::Any) {
      tracing::warn!(
        entry = url,
        what = format!("`{name}` oauth2"),
        "grant matches any host; secret is exfil-risky"
      );
    }
  }
  if matches!(flow.flow, FlowKind::AuthorizationCode) && flow.authorize_url.is_none() {
    return Err(Error::FlowNeedsAuthorize {
      origin: source.to_string(),
      name: name.to_string(),
    });
  }
  for field in &flow.token_fields {
    if field.is_empty() {
      return Err(Error::EmptyTokenField {
        origin: source.to_string(),
        name: name.to_string(),
      });
    }
  }
  let mut seen = BTreeSet::new();
  for field in &flow.token_fields {
    if !seen.insert(field) {
      return Err(Error::DuplicateTokenField {
        origin: source.to_string(),
        name: name.to_string(),
        field: field.clone(),
      });
    }
  }
  Ok(())
}

/// Endpoint URLs are full URLs; grants are authority-only. Parse the URL,
/// then reduce it to its host pattern for the exfil-risk warning.
fn flow_authority(url: &str) -> Result<HostPat, Error> {
  let parsed = Url::parse(url).map_err(|source| Error::BadUrlParse {
    url: url.to_string(),
    source,
  })?;
  let host = match parsed.host() {
    Some(Host::Domain("*")) => HostPat::Any,
    Some(Host::Domain(domain)) if domain.starts_with("*.") => match domain.get(1..) {
      Some(pattern) => HostPat::Wildcard(pattern.to_string()),
      None => HostPat::Exact(domain.to_string()),
    },
    Some(Host::Domain(domain)) => HostPat::Exact(domain.to_string()),
    Some(Host::Ipv4(addr)) => HostPat::Exact(addr.to_string()),
    Some(Host::Ipv6(addr)) => HostPat::Exact(addr.to_string()),
    None => return Err(Error::BadUrlHost { url: url.to_string() }),
  };
  Ok(host)
}

/// Reduce a full endpoint URL to the authority-only grant grammar
/// (`scheme://host[:port]`), dropping path, query, and fragment.
///
/// # Errors
///
/// Returns an error when the URL does not parse or carries no host.
pub fn authority_of(url: &str) -> Result<String, Error> {
  let parsed = Url::parse(url).map_err(|source| Error::BadUrlParse {
    url: url.to_string(),
    source,
  })?;
  let host = parsed
    .host_str()
    .ok_or_else(|| Error::BadUrlHost { url: url.to_string() })?
    .trim_start_matches('[')
    .trim_end_matches(']');
  let port = parsed.port();
  Ok(match port {
    Some(port) if !is_default_port(parsed.scheme(), port) => format!("{}://{host}:{port}", parsed.scheme()),
    _ => format!("{}://{host}", parsed.scheme()),
  })
}

fn is_default_port(scheme: &str, port: u16) -> bool {
  matches!((scheme.to_ascii_lowercase().as_str(), port), ("http", 80) | ("https", 443))
}

/// Validate one host entry with the same grammar as `allow`.
fn validate_hosts(hosts: &[String], source: &Path, kind: &str, name: &str) -> Result<(), Error> {
  for host in hosts {
    let scope: EndpointScope = host.parse().map_err(|err| Error::BadHost {
      file: source.to_path_buf(),
      kind: kind.to_string(),
      name: name.to_string(),
      host: host.clone(),
      detail: err,
    })?;
    if matches!(scope.host, HostPat::Any) {
      let what = format!("{kind} `{name}`");
      tracing::warn!(file = %source.display(), entry = %host, what, "grant matches any host; secret is exfil-risky");
    }
  }
  Ok(())
}

/// Validate one decoy template when present.
fn validate_optional_pattern(pattern: Option<&str>, source: &Path, kind: &str, name: &str) -> Result<(), Error> {
  if let Some(pattern) = pattern {
    validate_pattern(pattern).map_err(|err| Error::BadRegistryPattern {
      file: source.to_path_buf(),
      kind: kind.to_string(),
      name: name.to_string(),
      pattern: pattern.to_string(),
      detail: err,
    })?;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;
  use tempfile::tempdir;

  use pretty_assertions::assert_eq;

  use crate::config::DEFAULT_PATTERN;

  fn write_rules(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    path
  }

  #[test]
  fn bundled_table_loads_and_covers_github() {
    let registry = Registry::load(None).unwrap();
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the bundled registry");
    assert_eq!(
      known.hosts,
      vec!["https://api.github.com", "https://github.com", "https://uploads.github.com"]
    );
    assert_eq!(known.pattern.as_deref(), Some("ghp_{hex:40}"));
  }

  #[test]
  fn bundled_table_covers_the_first_tranche() {
    let registry = Registry::load(None).unwrap();
    // Names follow the platforms' docs: Atlas documents `MONGODB_ATLAS_PRIVATE_API_KEY`
    // and Shopify's Admin API examples use `SHOP_TOKEN`.
    for env in [
      "GITHUB_TOKEN",
      "GITLAB_TOKEN",
      "ANTHROPIC_API_KEY",
      "OPENAI_API_KEY",
      "GEMINI_API_KEY",
      "AWS_ACCESS_KEY_ID",
      "AZURE_CLIENT_SECRET",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "CLOUDFLARE_API_TOKEN",
      "DIGITALOCEAN_TOKEN",
      "HCLOUD_TOKEN",
      "FLY_API_TOKEN",
      "VERCEL_TOKEN",
      "NETLIFY_AUTH_TOKEN",
      "HEROKU_API_KEY",
      "STRIPE_SECRET_KEY",
      "SLACK_BOT_TOKEN",
      "TWILIO_AUTH_TOKEN",
      "SENDGRID_API_KEY",
      "POSTMARK_SERVER_TOKEN",
      "RESEND_API_KEY",
      "NPM_TOKEN",
      "PYPI_TOKEN",
      "HF_TOKEN",
      "DD_API_KEY",
      "SENTRY_AUTH_TOKEN",
      "GRAFANA_API_KEY",
      "MONGODB_ATLAS_PRIVATE_API_KEY",
      "SUPABASE_SERVICE_ROLE_KEY",
      "SHOP_TOKEN",
      "DEEPSEEK_API_KEY",
      "OPENROUTER_API_KEY",
      "TURSO_PLATFORM_TOKEN",
      "GITEA_TOKEN",
    ] {
      let known = registry
        .lookup(env)
        .unwrap_or_else(|| panic!("{env} missing from the bundled registry"));
      assert!(!known.hosts.is_empty(), "{env} has no hosts");
      assert!(known.pattern.is_some(), "{env} has no pattern");
    }
  }

  #[test]
  fn bundled_table_patterns_and_hosts_are_valid() {
    // `load` validates every entry, so a bad pattern or host fails here.
    let registry = Registry::load(None).unwrap();
    assert!(!registry.names.is_empty());
  }

  #[test]
  fn lookup_is_case_insensitive() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.lookup("github_token"), registry.lookup("GITHUB_TOKEN"));
  }

  #[test]
  fn envs_for_host_names_every_env_covering_an_endpoint() {
    let registry = Registry::load(None).unwrap();
    let covered = registry.envs_for_host(Scheme::Https, "github.com", 443);
    for expected in ["GH_TOKEN", "GITHUB_API_TOKEN", "GITHUB_PAT", "GITHUB_TOKEN"] {
      assert!(covered.contains(&expected.to_string()), "{expected} missing from {covered:?}");
    }
    assert!(covered.is_sorted(), "names come sorted for a deterministic pick: {covered:?}");
    assert_eq!(
      registry.envs_for_host(Scheme::Http, "github.com", 80),
      [] as [std::string::String; 0]
    );
    assert_eq!(
      registry.envs_for_host(Scheme::Https, "unknown.example", 443),
      [] as [std::string::String; 0]
    );
  }

  #[test]
  fn rules_d_unions_hosts_and_overrides_the_pattern() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-ghe.toml",
      r#"
[providers.github-ghe]
env = ["GITHUB_TOKEN"]
hosts = ["https://ghe.corp.example"]
pattern = "ghp_ghe_{hex:32}"
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the loaded registry");
    assert_eq!(
      known.hosts,
      vec![
        "https://api.github.com",
        "https://github.com",
        "https://uploads.github.com",
        "https://ghe.corp.example"
      ]
    );
    assert_eq!(known.pattern.as_deref(), Some("ghp_ghe_{hex:32}"));
  }

  #[test]
  fn replace_discards_the_bundled_entry() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-narrow.toml",
      r#"
[providers.github]
env = ["GITHUB_TOKEN"]
hosts = ["https://ghe.corp.example"]
replace = true
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the bundled registry");
    assert_eq!(known.hosts, vec!["https://ghe.corp.example"]);
    assert_eq!(known.pattern, None);
  }

  #[test]
  fn names_entry_overrides_a_provider_claim() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-name.toml",
      r#"
[names.GITHUB_TOKEN]
hosts = ["https://ghe.corp.example"]
pattern = "ghp_named_{hex:32}"
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the loaded registry");
    assert!(known.hosts.contains(&"https://api.github.com".to_string()));
    assert!(known.hosts.contains(&"https://ghe.corp.example".to_string()));
    assert_eq!(known.pattern.as_deref(), Some("ghp_named_{hex:32}"));
  }

  #[test]
  fn contains_tier_matches_a_substring_without_granting_hosts() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.template("ACME_ANTHROPIC_KEY", None), "sk-ant-api03-{base62:64}");
    assert!(
      registry.lookup("ACME_ANTHROPIC_KEY").is_none(),
      "contains tier must not grant hosts"
    );
  }

  #[test]
  fn explicit_pattern_beats_the_registry() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.template("GITHUB_TOKEN", Some("ghp_custom_{hex:8}")), "ghp_custom_{hex:8}");
  }

  #[test]
  fn unknown_env_name_falls_back_to_the_default_pattern() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.template("SOME_RANDOM_THING", None), DEFAULT_PATTERN);
  }

  #[test]
  fn duplicate_claim_in_one_file_is_rejected() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-dup.toml",
      r#"
[providers.first]
env = ["SHARED_TOKEN"]
hosts = ["https://a.example"]

[providers.second]
env = ["SHARED_TOKEN"]
hosts = ["https://b.example"]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("both claim"), "{err:?}");
  }

  #[test]
  fn contains_without_a_pattern_is_rejected() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
[providers.bad]
contains = ["bad"]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("needs a `pattern`"), "{err:?}");
  }

  #[test]
  fn empty_contains_needle_is_rejected() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
[providers.bad]
pattern = "bad_{hex:8}"
contains = [""]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("must not be empty"), "{err:?}");
  }

  #[test]
  fn empty_registry_pattern_is_treated_as_absent() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-blank.toml",
      r#"
[providers.blank]
env = ["BLANK_TOKEN"]
hosts = ["https://blank.example"]
pattern = ""
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    assert_eq!(
      registry.lookup("BLANK_TOKEN").expect("BLANK_TOKEN in the loaded registry").pattern,
      None
    );
    assert_eq!(registry.template("BLANK_TOKEN", None), DEFAULT_PATTERN);
  }

  #[test]
  fn any_host_entry_warns_but_loads() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-any.toml",
      r#"
[names.ANY_TOKEN]
hosts = ["https://*"]
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    assert_eq!(
      registry.lookup("ANY_TOKEN").expect("ANY_TOKEN in the loaded registry").hosts,
      vec!["https://*"]
    );
  }

  #[test]
  fn bad_host_is_rejected() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
[providers.bad]
env = ["BAD_TOKEN"]
hosts = ["https://api.example/path"]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("bad host"), "{err:?}");
  }

  #[test]
  fn decoy_is_deterministic_and_registry_shaped() {
    let registry = Registry::load(None).unwrap();
    let decoy = registry.decoy("GITHUB_TOKEN", None);
    assert_eq!(decoy, registry.decoy("GITHUB_TOKEN", None));
    assert!(decoy.starts_with("ghp_"), "{decoy}");
    assert_eq!(decoy.len(), 44);
  }

  #[test]
  fn rules_d_files_load_in_filename_order() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-first.toml",
      "[names.ORDERED_TOKEN]\nhosts = [\"https://first.example\"]\n",
    );
    write_rules(dir.path(), "20-second.toml", "[names.ORDERED_TOKEN]\npattern = \"late_{hex:8}\"\n");
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("ORDERED_TOKEN").expect("ORDERED_TOKEN in the loaded registry");
    assert_eq!(known.hosts, vec!["https://first.example"]);
    assert_eq!(known.pattern.as_deref(), Some("late_{hex:8}"));
  }

  #[test]
  fn missing_rules_dir_is_not_an_error() {
    let dir = tempdir().unwrap();
    let registry = Registry::load(Some(&dir.path().join("absent"))).unwrap();
    assert_ne!(
      registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the bundled registry").hosts,
      [] as [String; 0]
    );
  }
  #[test]
  fn oauth2_flow_block_parses_and_defaults_fields() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-flow.toml",
      r#"
  [providers.issuer]
  env = ["ISSUER_TOKEN"]
  hosts = ["https://api.example.com"]

  [providers.issuer.oauth2]
  flow = "client_credentials"
  token_url = "https://auth.example.com/oauth/token"
  "#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("ISSUER_TOKEN").expect("ISSUER_TOKEN in the loaded registry");
    let flow = known.oauth2.as_ref().expect("flow present");
    assert_eq!(flow.flow, FlowKind::ClientCredentials);
    assert_eq!(flow.token_url, "https://auth.example.com/oauth/token");
    assert_eq!(flow.fields(), vec!["access_token"]);
  }

  #[test]
  fn oauth2_fields_follow_flow_shape_and_rotation() {
    let mut flow = OAuthFlow {
      flow: FlowKind::AuthorizationCode,
      token_url: "https://auth.example.com/oauth/token".into(),
      authorize_url: Some("https://auth.example.com/authorize".into()),
      refresh_url: None,
      rotates_refresh: false,
      token_fields: Vec::new(),
    };
    assert_eq!(flow.fields(), vec!["access_token", "refresh_token"]);
    flow.flow = FlowKind::ClientCredentials;
    flow.rotates_refresh = true;
    assert_eq!(flow.fields(), vec!["access_token", "refresh_token"]);
    flow.rotates_refresh = false;
    assert_eq!(flow.fields(), vec!["access_token"]);
  }

  #[test]
  fn token_fields_override_the_defaults() {
    let flow = OAuthFlow {
      flow: FlowKind::Refresh,
      token_url: "https://auth.example.com/oauth/token".into(),
      authorize_url: None,
      refresh_url: None,
      rotates_refresh: false,
      token_fields: vec!["wrapped_token".into()],
    };
    assert_eq!(flow.fields(), vec!["access_token"]);
    assert_eq!(flow.token_fields, vec!["wrapped_token"]);
  }

  #[test]
  fn rules_d_unions_the_oauth2_flow() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-flow.toml",
      r#"
  [providers.issuer]
  env = ["ISSUER_TOKEN"]
  hosts = ["https://api.example.com"]

  [providers.issuer.oauth2]
  flow = "authorization_code"
  token_url = "https://auth.example.com/oauth/token"
  authorize_url = "https://auth.example.com/authorize"
  "#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("ISSUER_TOKEN").expect("ISSUER_TOKEN in the loaded registry");
    let flow = known.oauth2.as_ref().expect("flow present");
    assert_eq!(flow.flow, FlowKind::AuthorizationCode);
    assert_eq!(flow.authorize_url.as_deref(), Some("https://auth.example.com/authorize"));
  }

  #[test]
  fn replace_discards_the_oauth2_flow() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-flow.toml",
      r#"
  [providers.issuer]
  env = ["ISSUER_TOKEN"]
  hosts = ["https://api.example.com"]

  [providers.issuer.oauth2]
  flow = "client_credentials"
  token_url = "https://auth.example.com/oauth/token"
  "#,
    );
    write_rules(
      dir.path(),
      "20-narrow.toml",
      r#"
  [providers.issuer]
  env = ["ISSUER_TOKEN"]
  hosts = ["https://api.example.com"]
  replace = true
  "#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("ISSUER_TOKEN").expect("ISSUER_TOKEN in the loaded registry");
    assert!(known.oauth2.is_none(), "replace must discard the flow");
  }

  #[test]
  fn authorization_code_without_authorize_url_is_rejected() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
  [providers.bad]
  env = ["BAD_TOKEN"]
  hosts = ["https://api.example.com"]

  [providers.bad.oauth2]
  flow = "authorization_code"
  token_url = "https://auth.example.com/oauth/token"
  "#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("needs an `authorize_url`"), "{err:?}");
  }

  #[test]
  fn bad_flow_token_url_is_rejected() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
  [providers.bad]
  env = ["BAD_TOKEN"]
  hosts = ["https://api.example.com"]

  [providers.bad.oauth2]
  flow = "client_credentials"
  token_url = "not a url"
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("bad oauth2 url"), "{err:?}");
  }

  #[test]
  fn duplicate_and_empty_token_fields_are_rejected() {
    let dir = tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
  [providers.bad]
  env = ["BAD_TOKEN"]
  hosts = ["https://api.example.com"]

  [providers.bad.oauth2]
  flow = "client_credentials"
  token_url = "https://auth.example.com/oauth/token"
  token_fields = ["access_token", "access_token"]
  "#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("duplicate `token_fields` entry"), "{err:?}");
  }

  const SIGNING_SECRETS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "EXOSCALE_SECRET_KEY",
    "EXOSCALE_SECRET",
    "POLYMARKET_SECRET",
    "POLYMARKET_SECRET_KEY",
    "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
    "ALICLOUD_ACCESS_KEY_SECRET",
    "ALICLOUD_SECRET_KEY",
    "OVH_APPLICATION_SECRET",
    "OVH_APP_SECRET",
    "BINANCE_API_SECRET",
    "BINANCE_PRIVATE_KEY",
    "BINANCE_SECRET",
    "BINANCE_SECRET_KEY",
    "BINANCECOINM_API_SECRET",
    "BINANCECOINM_PRIVATE_KEY",
    "BINANCECOINM_SECRET",
    "BINANCECOINM_SECRET_KEY",
    "BINANCEUS_API_SECRET",
    "BINANCEUS_PRIVATE_KEY",
    "BINANCEUS_SECRET",
    "BINANCEUS_SECRET_KEY",
    "BINANCEUSDM_API_SECRET",
    "BINANCEUSDM_PRIVATE_KEY",
    "BINANCEUSDM_SECRET",
    "BINANCEUSDM_SECRET_KEY",
    "OKX_API_SECRET",
    "OKX_PRIVATE_KEY",
    "OKX_SECRET",
    "OKX_SECRET_KEY",
    "OKXUS_API_SECRET",
    "OKXUS_PRIVATE_KEY",
    "OKXUS_SECRET",
    "OKXUS_SECRET_KEY",
    "MYOKX_API_SECRET",
    "MYOKX_PRIVATE_KEY",
    "MYOKX_SECRET",
    "MYOKX_SECRET_KEY",
    "BYBIT_API_SECRET",
    "BYBIT_PRIVATE_KEY",
    "BYBIT_SECRET",
    "BYBIT_SECRET_KEY",
    "BYBITEU_API_SECRET",
    "BYBITEU_PRIVATE_KEY",
    "BYBITEU_SECRET",
    "BYBITEU_SECRET_KEY",
    "KUCOIN_API_SECRET",
    "KUCOIN_PRIVATE_KEY",
    "KUCOIN_SECRET",
    "KUCOIN_SECRET_KEY",
    "KUCOINFUTURES_API_SECRET",
    "KUCOINFUTURES_PRIVATE_KEY",
    "KUCOINFUTURES_SECRET",
    "KUCOINFUTURES_SECRET_KEY",
    "KRAKEN_API_SECRET",
    "KRAKEN_PRIVATE_KEY",
    "KRAKEN_SECRET",
    "KRAKEN_SECRET_KEY",
    "COINBASE_API_SECRET",
    "COINBASE_PRIVATE_KEY",
    "COINBASE_SECRET",
    "COINBASE_SECRET_KEY",
    "COINBASEEXCHANGE_API_SECRET",
    "COINBASEEXCHANGE_PRIVATE_KEY",
    "COINBASEEXCHANGE_SECRET",
    "COINBASEEXCHANGE_SECRET_KEY",
    "COINBASE_EXCHANGE_API_SECRET",
    "COINBASEINTERNATIONAL_API_SECRET",
    "COINBASEINTERNATIONAL_PRIVATE_KEY",
    "COINBASEINTERNATIONAL_SECRET",
    "COINBASEINTERNATIONAL_SECRET_KEY",
    "BITFINEX_API_SECRET",
    "BITFINEX_PRIVATE_KEY",
    "BITFINEX_SECRET",
    "BITFINEX_SECRET_KEY",
    "BITSTAMP_API_SECRET",
    "BITSTAMP_PRIVATE_KEY",
    "BITSTAMP_SECRET",
    "BITSTAMP_SECRET_KEY",
    "GEMINI_API_SECRET",
    "GEMINI_PRIVATE_KEY",
    "GEMINI_SECRET",
    "GEMINI_SECRET_KEY",
    "GATE_API_SECRET",
    "GATE_PRIVATE_KEY",
    "GATE_SECRET",
    "GATE_SECRET_KEY",
    "GATEEU_API_SECRET",
    "GATEEU_PRIVATE_KEY",
    "GATEEU_SECRET",
    "GATEEU_SECRET_KEY",
    "MEXC_API_SECRET",
    "MEXC_PRIVATE_KEY",
    "MEXC_SECRET",
    "MEXC_SECRET_KEY",
    "BITGET_API_SECRET",
    "BITGET_PRIVATE_KEY",
    "BITGET_SECRET",
    "BITGET_SECRET_KEY",
    "HTX_API_SECRET",
    "HTX_PRIVATE_KEY",
    "HTX_SECRET",
    "HTX_SECRET_KEY",
    "UPBIT_API_SECRET",
    "UPBIT_PRIVATE_KEY",
    "UPBIT_SECRET",
    "UPBIT_SECRET_KEY",
    "BITHUMB_API_SECRET",
    "BITHUMB_PRIVATE_KEY",
    "BITHUMB_SECRET",
    "BITHUMB_SECRET_KEY",
    "DERIBIT_API_SECRET",
    "DERIBIT_PRIVATE_KEY",
    "DERIBIT_SECRET",
    "DERIBIT_SECRET_KEY",
    "BITMEX_API_SECRET",
    "BITMEX_PRIVATE_KEY",
    "BITMEX_SECRET",
    "BITMEX_SECRET_KEY",
    "CRYPTOCOM_API_SECRET",
    "CRYPTOCOM_PRIVATE_KEY",
    "CRYPTOCOM_SECRET",
    "CRYPTOCOM_SECRET_KEY",
  ];

  const SIGNING_VENDOR_KEYS: &[(&[&str], &str)] = &[
    (
      &["ALIBABA_CLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY"],
      "ecs.cn-shanghai.aliyuncs.com",
    ),
    (&["ALIBABA_CLOUD_SECURITY_TOKEN", "ALICLOUD_SECURITY_TOKEN"], "sts.aliyuncs.com"),
    (&["OVH_APPLICATION_KEY", "OVH_APP_KEY", "OVH_CONSUMER_KEY"], "eu.api.ovh.com"),
    (&["GEMINI_API_KEY", "GOOGLE_API_KEY"], "api.gemini.com"),
    (
      &[
        "BITFINEX_API_KEY",
        "BITFINEX_API_TOKEN",
        "BITFINEX_APIKEY",
        "BITFINEX_TOKEN",
        "BITFINEX_ACCESS_TOKEN",
        "BITFINEX_AUTH_TOKEN",
        "BITFINEX_KEY",
      ],
      "api.bitfinex.com",
    ),
    (
      &[
        "KRAKEN_API_KEY",
        "KRAKEN_API_TOKEN",
        "KRAKEN_APIKEY",
        "KRAKEN_TOKEN",
        "KRAKEN_ACCESS_TOKEN",
        "KRAKEN_AUTH_TOKEN",
        "KRAKEN_KEY",
      ],
      "api.kraken.com",
    ),
    (
      &[
        "KUCOIN_API_KEY",
        "KUCOIN_API_TOKEN",
        "KUCOIN_APIKEY",
        "KUCOIN_TOKEN",
        "KUCOIN_ACCESS_TOKEN",
        "KUCOIN_AUTH_TOKEN",
        "KUCOIN_KEY",
        "KUCOIN_PASSPHRASE",
        "KUCOIN_API_PASSPHRASE",
      ],
      "api.kucoin.com",
    ),
    (
      &[
        "BINANCE_ACCESS_KEY",
        "BINANCE_APIKEY",
        "BINANCE_API_KEY",
        "BINANCE_API_TOKEN",
        "BINANCE_KEY",
      ],
      "api.binance.com",
    ),
    (
      &[
        "BINANCECOINM_ACCESS_KEY",
        "BINANCECOINM_APIKEY",
        "BINANCECOINM_API_KEY",
        "BINANCECOINM_API_TOKEN",
        "BINANCECOINM_KEY",
      ],
      "dapi.binance.com",
    ),
    (
      &[
        "BINANCEUS_ACCESS_KEY",
        "BINANCEUS_APIKEY",
        "BINANCEUS_API_KEY",
        "BINANCEUS_API_TOKEN",
        "BINANCEUS_KEY",
      ],
      "api.binance.us",
    ),
    (
      &[
        "BINANCEUSDM_ACCESS_KEY",
        "BINANCEUSDM_APIKEY",
        "BINANCEUSDM_API_KEY",
        "BINANCEUSDM_API_TOKEN",
        "BINANCEUSDM_KEY",
      ],
      "fapi.binance.com",
    ),
    (
      &[
        "BITGET_ACCESS_KEY",
        "BITGET_APIKEY",
        "BITGET_API_KEY",
        "BITGET_API_TOKEN",
        "BITGET_KEY",
        "BITGET_PASSPHRASE",
        "BITGET_API_PASSPHRASE",
      ],
      "api.bitget.com",
    ),
    (
      &[
        "BITHUMB_ACCESS_KEY",
        "BITHUMB_APIKEY",
        "BITHUMB_API_KEY",
        "BITHUMB_API_TOKEN",
        "BITHUMB_KEY",
      ],
      "api.bithumb.com",
    ),
    (
      &[
        "BITMEX_ACCESS_KEY",
        "BITMEX_APIKEY",
        "BITMEX_API_KEY",
        "BITMEX_API_TOKEN",
        "BITMEX_KEY",
      ],
      "www.bitmex.com",
    ),
    (
      &[
        "BITSTAMP_ACCESS_KEY",
        "BITSTAMP_APIKEY",
        "BITSTAMP_API_KEY",
        "BITSTAMP_API_TOKEN",
        "BITSTAMP_KEY",
      ],
      "www.bitstamp.net",
    ),
    (
      &["BYBIT_ACCESS_KEY", "BYBIT_APIKEY", "BYBIT_API_KEY", "BYBIT_API_TOKEN", "BYBIT_KEY"],
      "api.bybit.com",
    ),
    (
      &[
        "BYBITEU_ACCESS_KEY",
        "BYBITEU_APIKEY",
        "BYBITEU_API_KEY",
        "BYBITEU_API_TOKEN",
        "BYBITEU_KEY",
      ],
      "api.bybit.eu",
    ),
    (
      &[
        "COINBASE_ACCESS_KEY",
        "COINBASE_APIKEY",
        "COINBASE_API_KEY",
        "COINBASE_API_TOKEN",
        "COINBASE_KEY",
      ],
      "api.coinbase.com",
    ),
    (
      &[
        "COINBASEEXCHANGE_ACCESS_KEY",
        "COINBASEEXCHANGE_APIKEY",
        "COINBASEEXCHANGE_API_KEY",
        "COINBASEEXCHANGE_API_TOKEN",
        "COINBASEEXCHANGE_KEY",
        "COINBASE_EXCHANGE_API_KEY",
        "COINBASEEXCHANGE_PASSPHRASE",
        "COINBASE_EXCHANGE_PASSPHRASE",
      ],
      "api.exchange.coinbase.com",
    ),
    (
      &[
        "COINBASEINTERNATIONAL_ACCESS_KEY",
        "COINBASEINTERNATIONAL_APIKEY",
        "COINBASEINTERNATIONAL_API_KEY",
        "COINBASEINTERNATIONAL_API_TOKEN",
        "COINBASEINTERNATIONAL_KEY",
        "COINBASEINTERNATIONAL_PASSPHRASE",
      ],
      "api.international.coinbase.com",
    ),
    (
      &[
        "CRYPTOCOM_ACCESS_KEY",
        "CRYPTOCOM_APIKEY",
        "CRYPTOCOM_API_KEY",
        "CRYPTOCOM_API_TOKEN",
        "CRYPTOCOM_KEY",
      ],
      "api.crypto.com",
    ),
    (
      &[
        "DERIBIT_ACCESS_KEY",
        "DERIBIT_APIKEY",
        "DERIBIT_API_KEY",
        "DERIBIT_API_TOKEN",
        "DERIBIT_KEY",
      ],
      "www.deribit.com",
    ),
    (
      &["GATE_ACCESS_KEY", "GATE_APIKEY", "GATE_API_KEY", "GATE_API_TOKEN", "GATE_KEY"],
      "api.gateio.ws",
    ),
    (
      &[
        "GATEEU_ACCESS_KEY",
        "GATEEU_APIKEY",
        "GATEEU_API_KEY",
        "GATEEU_API_TOKEN",
        "GATEEU_KEY",
      ],
      "api.gateeu.com",
    ),
    (
      &["HTX_ACCESS_KEY", "HTX_APIKEY", "HTX_API_KEY", "HTX_API_TOKEN", "HTX_KEY"],
      "api.huobi.pro",
    ),
    (
      &[
        "KUCOINFUTURES_ACCESS_KEY",
        "KUCOINFUTURES_APIKEY",
        "KUCOINFUTURES_API_KEY",
        "KUCOINFUTURES_API_TOKEN",
        "KUCOINFUTURES_KEY",
        "KUCOINFUTURES_PASSPHRASE",
        "KUCOINFUTURES_API_PASSPHRASE",
      ],
      "api-futures.kucoin.com",
    ),
    (
      &["MEXC_ACCESS_KEY", "MEXC_APIKEY", "MEXC_API_KEY", "MEXC_API_TOKEN", "MEXC_KEY"],
      "api.mexc.com",
    ),
    (
      &[
        "MYOKX_ACCESS_KEY",
        "MYOKX_APIKEY",
        "MYOKX_API_KEY",
        "MYOKX_API_TOKEN",
        "MYOKX_KEY",
        "MYOKX_PASSPHRASE",
        "MYOKX_API_PASSPHRASE",
      ],
      "eea.okx.com",
    ),
    (
      &[
        "OKX_ACCESS_KEY",
        "OKX_APIKEY",
        "OKX_API_KEY",
        "OKX_API_TOKEN",
        "OKX_KEY",
        "OKX_PASSPHRASE",
        "OKX_API_PASSPHRASE",
      ],
      "www.okx.com",
    ),
    (
      &[
        "OKXUS_ACCESS_KEY",
        "OKXUS_APIKEY",
        "OKXUS_API_KEY",
        "OKXUS_API_TOKEN",
        "OKXUS_KEY",
        "OKXUS_PASSPHRASE",
        "OKXUS_API_PASSPHRASE",
      ],
      "us.okx.com",
    ),
    (
      &["UPBIT_ACCESS_KEY", "UPBIT_APIKEY", "UPBIT_API_KEY", "UPBIT_API_TOKEN", "UPBIT_KEY"],
      "api.upbit.com",
    ),
  ];

  fn host_grants(known: &KnownHosts, host: &str) -> bool {
    known.hosts.iter().any(|entry| {
      entry
        .parse::<EndpointScope>()
        .is_ok_and(|scope| uri_match(std::slice::from_ref(&scope), Scheme::Https, host, 443))
    })
  }

  /// A concrete hostname the entry must grant: the exact host, or one
  /// subdomain when the entry is a wildcard.
  fn concrete_host(pat: &HostPat) -> String {
    match pat {
      HostPat::Exact(host) => host.clone(),
      HostPat::Wildcard(pattern) => {
        let suffix = pattern.strip_prefix("*.").unwrap_or(pattern);
        format!("a.{suffix}")
      }
      HostPat::Any => "example.com".to_string(),
    }
  }

  #[test]
  fn signing_only_secrets_have_no_hosts() {
    let registry = Registry::load(None).unwrap();
    // Every signing secret from #14 and #19. The value is an HMAC or JWT
    // signing input and never reaches the wire, so the entry is a decoy
    // shape with no hosts and therefore no grant.
    for env in SIGNING_SECRETS {
      let known = registry
        .lookup(env)
        .unwrap_or_else(|| panic!("{env} missing from the bundled registry"));
      assert!(
        known.hosts.is_empty(),
        "{env} is a signing-only secret but has hosts: {:?}",
        known.hosts
      );
      assert_eq!(
        registry.template(env, None).as_ref(),
        DEFAULT_PATTERN,
        "{env} must keep the default decoy shape and no explicit pattern"
      );
    }
  }

  #[test]
  fn signing_vendor_keys_parse_and_match_their_hosts() {
    let registry = Registry::load(None).unwrap();
    for (envs, host) in SIGNING_VENDOR_KEYS {
      for env in *envs {
        let known = registry
          .lookup(env)
          .unwrap_or_else(|| panic!("{env} missing from the bundled registry"));
        assert!(known.pattern.is_some(), "{env} has no decoy shape");
        assert!(!known.hosts.is_empty(), "{env} has no hosts");
        for entry in &known.hosts {
          let scope = entry
            .parse::<EndpointScope>()
            .unwrap_or_else(|err| panic!("{env} host {entry} does not parse: {err}"));
          let concrete = concrete_host(&scope.host);
          assert!(
            uri_match(std::slice::from_ref(&scope), scope.scheme, &concrete, scope.port),
            "{env} host {entry} does not match {concrete}"
          );
        }
        assert!(host_grants(known, host), "{env} hosts {:?} do not grant {host}", known.hosts);
      }
    }
  }
}
