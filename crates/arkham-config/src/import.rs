//! Curation-time import of `OAuth2` flow declarations from discovery and
//! `OpenAPI` documents. Pure mapping: a document string in, a `rules.d` TOML
//! fragment out. Nothing here fetches; the operator hands it a file.
use std::fmt::Write as _;

use serde_json::Value;

use crate::error::Error;
use crate::registry::{FlowKind, OAuthFlow, validate_flow};

/// Map an OIDC discovery document onto one `oauth2` block.
///
/// `grant_types_supported` picks the flow: `client_credentials` maps to
/// [`FlowKind::ClientCredentials`], `authorization_code` to
/// [`FlowKind::AuthorizationCode`]; anything else is an error because
/// arkham only covers flows whose token exchanges run on the wire.
///
/// # Errors
///
/// Returns an error when the document is not valid JSON, when
/// `token_endpoint` is missing, or when no supported grant type is listed.
pub fn flow_from_oidc(doc: &str) -> Result<OAuthFlow, Error> {
  let value: Value = serde_json::from_str(doc).map_err(|source| Error::ParseDiscovery { source })?;
  let obj = value.as_object().ok_or(Error::DiscoveryNotAnObject)?;
  let token_url = obj
    .get("token_endpoint")
    .and_then(Value::as_str)
    .ok_or(Error::DiscoveryMissingTokenEndpoint)?;
  let grants = obj
    .get("grant_types_supported")
    .and_then(Value::as_array)
    .ok_or(Error::DiscoveryMissingGrantTypes)?;
  let flow = if grants.iter().any(|g| g.as_str() == Some("authorization_code")) {
    FlowKind::AuthorizationCode
  } else if grants.iter().any(|g| g.as_str() == Some("client_credentials")) {
    FlowKind::ClientCredentials
  } else {
    return Err(Error::DiscoveryNoSupportedGrantType);
  };
  Ok(OAuthFlow {
    flow,
    token_url: token_url.to_string(),
    authorize_url: obj.get("authorization_endpoint").and_then(Value::as_str).map(str::to_string),
    refresh_url: obj.get("refresh_endpoint").and_then(Value::as_str).map(str::to_string),
    rotates_refresh: false,
    token_fields: Vec::new(),
  })
}

/// One `securitySchemes` entry mapped to its name and flow.
struct SchemeEntry {
  name: String,
  flow: Result<OAuthFlow, String>,
}

/// One curated scheme: its slug and its flow, or why the scheme was skipped.
pub type FlowEntry = (String, Result<OAuthFlow, String>);

/// Map an `OpenAPI` document's `components.securitySchemes` onto `oauth2`
/// blocks, one per `type: oauth2` scheme. `type: openIdConnect` schemes are
/// reported and skipped: that leg is user-login authorization-code, which
/// the operator curates from the issuer's discovery document instead.
///
/// # Errors
///
/// Returns an error when the document is not valid JSON.
pub fn flows_from_openapi(doc: &str) -> Result<Vec<FlowEntry>, Error> {
  let value: Value = serde_json::from_str(doc).map_err(|source| Error::ParseOpenapi { source })?;
  let schemes = value
    .pointer("/components/securitySchemes")
    .and_then(Value::as_object)
    .ok_or(Error::OpenapiNoSchemes)?;
  let mut out = Vec::new();
  for (name, scheme) in schemes {
    let entry = match scheme.get("type").and_then(Value::as_str) {
      Some("oauth2") => SchemeEntry {
        name: name.clone(),
        flow: flow_from_openapi_scheme(scheme),
      },
      Some("openIdConnect") => SchemeEntry {
        name: name.clone(),
        flow: Err("openIdConnect scheme: curate from the issuer's discovery document instead".to_string()),
      },
      _ => continue,
    };
    out.push((entry.name, entry.flow));
  }
  Ok(out)
}

/// Map one `type: oauth2` security scheme. Flow keys follow `OpenAPI`:
/// `clientCredentials` → client credentials, `authorizationCode` →
/// authorization code.
fn flow_from_openapi_scheme(scheme: &Value) -> Result<OAuthFlow, String> {
  let flows = scheme
    .get("flows")
    .and_then(Value::as_object)
    .ok_or_else(|| "oauth2 scheme has no `flows`".to_string())?;
  for (key, flow) in flows {
    let (kind, token_url) = match key.as_str() {
      "clientCredentials" => (FlowKind::ClientCredentials, flow.get("tokenUrl").and_then(Value::as_str)),
      "authorizationCode" => (FlowKind::AuthorizationCode, flow.get("tokenUrl").and_then(Value::as_str)),
      _ => continue,
    };
    let Some(token_url) = token_url else {
      return Err(format!("oauth2 flow `{key}` has no `tokenUrl`"));
    };
    return Ok(OAuthFlow {
      flow: kind,
      token_url: token_url.to_string(),
      authorize_url: flow.get("authorizationUrl").and_then(Value::as_str).map(str::to_string),
      refresh_url: flow.get("refreshUrl").and_then(Value::as_str).map(str::to_string),
      rotates_refresh: false,
      token_fields: Vec::new(),
    });
  }
  Err("oauth2 scheme has no supported flow (`clientCredentials` or `authorizationCode`)".to_string())
}

/// Render one flow as a `rules.d` TOML fragment, complete provider entry.
///
/// # Errors
///
/// Returns an error when the flow fails validation.
pub fn to_toml_fragment(slug: &str, env: &str, flow: &OAuthFlow) -> Result<String, Error> {
  validate_flow(flow, "<generated>", slug)?;
  let mut out = String::new();
  let _ = writeln!(out, "[providers.{slug}]");
  let _ = writeln!(out, "env = [\"{env}\"]");
  out.push_str("replace = true\n");
  out.push('\n');
  let _ = writeln!(out, "[providers.{slug}.oauth2]");
  let _ = writeln!(out, "flow = \"{}\"", flow_kind_name(flow.flow));
  let _ = writeln!(out, "token_url = \"{}\"", flow.token_url);
  if let Some(url) = &flow.authorize_url {
    let _ = writeln!(out, "authorize_url = \"{url}\"");
  }
  if let Some(url) = &flow.refresh_url {
    let _ = writeln!(out, "refresh_url = \"{url}\"");
  }
  Ok(out)
}

fn flow_kind_name(kind: FlowKind) -> &'static str {
  match kind {
    FlowKind::ClientCredentials => "client_credentials",
    FlowKind::AuthorizationCode => "authorization_code",
    FlowKind::Refresh => "refresh",
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn oidc_document_maps_to_a_flow() {
    let flow = flow_from_oidc(
      r#"{
        "token_endpoint": "https://auth.example.com/oauth/token",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "grant_types_supported": ["authorization_code", "refresh_token"]
      }"#,
    )
    .unwrap();
    assert_eq!(flow.flow, FlowKind::AuthorizationCode);
    assert_eq!(flow.token_url, "https://auth.example.com/oauth/token");
    assert_eq!(flow.authorize_url.as_deref(), Some("https://auth.example.com/authorize"));
  }

  #[test]
  fn oidc_client_credentials_maps_without_authorize_url() {
    let flow = flow_from_oidc(
      r#"{
        "token_endpoint": "https://auth.example.com/oauth/token",
        "grant_types_supported": ["client_credentials"]
      }"#,
    )
    .unwrap();
    assert_eq!(flow.flow, FlowKind::ClientCredentials);
    assert!(flow.authorize_url.is_none());
    assert_eq!(flow.fields(), vec!["access_token"]);
  }

  #[test]
  fn openapi_oauth2_scheme_maps() {
    let flows = flows_from_openapi(
      r#"{
        "components": {"securitySchemes": {
          "bearer": {"type": "http", "scheme": "bearer"},
          "oauth": {"type": "oauth2", "flows": {
            "clientCredentials": {"tokenUrl": "https://auth.example.com/oauth/token"}
          }}
        }}
      }"#,
    )
    .unwrap();
    assert_eq!(flows.len(), 1, "{flows:?}");
    let (name, flow) = &flows[0];
    assert_eq!(name, "oauth");
    let flow = flow.as_ref().unwrap();
    assert_eq!(flow.flow, FlowKind::ClientCredentials);
    assert_eq!(flow.token_url, "https://auth.example.com/oauth/token");
  }

  #[test]
  fn openapi_openid_connect_is_reported_and_skipped() {
    let flows = flows_from_openapi(
      r#"{
        "components": {"securitySchemes": {
          "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://a.example/.well-known/openid-configuration"}
        }}
      }"#,
    )
    .unwrap();
    assert_eq!(flows.len(), 1);
    let err = flows[0].1.as_ref().unwrap_err();
    assert!(err.contains("discovery document"), "{err}");
  }

  #[test]
  fn openapi_scheme_without_token_url_is_an_error() {
    let flows = flows_from_openapi(
      r#"{
        "components": {"securitySchemes": {
          "bad": {"type": "oauth2", "flows": {"clientCredentials": {}}}
        }}
      }"#,
    )
    .unwrap();
    let err = flows[0].1.as_ref().unwrap_err();
    assert!(err.contains("no `tokenUrl`"), "{err}");
  }

  #[test]
  fn fragment_loads_as_a_rules_d_file() {
    let flow = flow_from_oidc(
      r#"{
        "token_endpoint": "https://auth.example.com/oauth/token",
        "grant_types_supported": ["client_credentials"]
      }"#,
    )
    .unwrap();
    let text = to_toml_fragment("example", "EXAMPLE_TOKEN", &flow).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("10-example.toml"), &text).unwrap();
    let registry = crate::registry::Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("EXAMPLE_TOKEN").expect("EXAMPLE_TOKEN in the loaded registry");
    let flow = known.oauth2.as_ref().expect("flow present");
    assert_eq!(flow.flow, FlowKind::ClientCredentials);
    assert_eq!(flow.token_url, "https://auth.example.com/oauth/token");
  }
}
