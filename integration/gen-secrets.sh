#!/usr/bin/env bash
# One-shot secret provisioning for the demo: renders the fnox plain-provider
# config the arkham container resolves its rule values from. Values arrive by
# environment at runtime (integration/.env, gitignored) — never from a
# committed rules file.
set -euo pipefail

dir=${1:-/arkham-config}

: "${ARKHAM_REAL:?ARKHAM_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_DB_REAL:?ARKHAM_DB_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${OIDC_CLIENT_SECRET:?OIDC_CLIENT_SECRET not set: copy integration/.env.example to integration/.env and export it}"

mkdir -p "$dir"

# The global config layer arkham derives its config-dir from; the demo's real
# config arrives via --config, so this one only anchors the directory.
printf '[proxy]\nlisten = "127.0.0.1:8080"\n' >"$dir/config.toml"

# Arkham's fnox level: with ARKHAM_CONFIG=$dir/config.toml, the config dir is
# $dir and the level file sits directly in it.
cat >"$dir/fnox.toml" <<EOF
[providers.plain]
type = "plain"

[secrets.GH_TOKEN]
provider = "plain"
value = "$ARKHAM_REAL"

[secrets.OIDC_CLIENT_SECRET]
provider = "plain"
value = "$OIDC_CLIENT_SECRET"

[secrets.DATABASE_URL]
provider = "plain"
value = "$ARKHAM_DB_REAL"
EOF
chmod -R a+rX "$dir"
echo "fnox config ready in $dir"
