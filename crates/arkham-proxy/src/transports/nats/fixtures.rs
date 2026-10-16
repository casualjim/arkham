//! Grant fixtures shared by NATS tests.

use arkham_config::grants::{Credential, Grant, NatsAuth, NatsScope};

/// One NATS grant parsed from a decoy string and a real string.
pub(crate) fn nats_grants(fake: &str, real: &str) -> Vec<Grant> {
  let scope = NatsScope::from_strings(fake, real).expect("nats strings");
  let secret = match &scope.auth {
    NatsAuth::UserPass { pass, .. } => pass,
    NatsAuth::Token(token) => token,
  };
  vec![Grant::Nats {
    credential: Credential {
      label: "nats".into(),
      fake: secret.fake.clone(),
      value: secret.real.clone(),
    },
    scope: Box::new(scope),
  }]
}
