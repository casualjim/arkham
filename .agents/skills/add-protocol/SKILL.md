---
name: add-protocol
description: >
  Checklist for adding a credential-rewriting protocol to arkham. Use when
  adding a wire protocol, a connection-string grant, RESP or pgwire-style
  substitution, capture for a new port, or an integration end-to-end scenario.
---

# Add a credential-rewriting protocol

Worked example: Redis RESP, merged in PR #44 as squash `11ce4a877f7ce9ac010bf2599b9cc0b1bb8055da` (`11ce4a8`). Cite these files. Copy this shape for the next protocol.

Grant matching stays in `arkham-config`. Substitution stays in `arkham-proxy`. Capture backends hand the stream to `serve_transparent_stream` and do not reimplement either.

Each step ends with a command. Run it from the repo root. A non-zero exit means the step is not done. `PROTO` is the transport directory name. The blocks set `PROTO=redis` because Redis is the worked example; point it at the protocol you are adding before you run them.

## 1. Transport module

Add `crates/arkham-proxy/src/transports/<protocol>/` and `pub(crate) mod <protocol>` in `crates/arkham-proxy/src/transports/mod.rs`. `engine` is the shared substitution engine, not a protocol.

The vertical parses the protocol and finds the credential bytes the swap reframes. Redis does that in `crates/arkham-proxy/src/transports/redis/machine.rs` (`AUTH` and `HELLO`, including a password of a different length). `RedisTransport` in `transports/redis/mod.rs` implements `Transport::serve`.

Register the strategy on `ProxyState` (`crates/arkham-proxy/src/lib.rs`, field `redis`, constructed in `ProxyState::new`). Route it from `Expect` in `crates/arkham-proxy/src/identity.rs`: `expect` calls `Grant::redis`, and `Expect::serve` is the only `match` on the picked protocol (`Expect::Redis` → `state.redis.serve`).

```bash
export PROTO=redis
test -d "crates/arkham-proxy/src/transports/$PROTO" \
  && rg -n "mod $PROTO;" crates/arkham-proxy/src/transports/mod.rs \
  && rg -n "fn serve" "crates/arkham-proxy/src/transports/$PROTO/mod.rs" \
  && rg -n -i "Expect::${PROTO}" crates/arkham-proxy/src/identity.rs \
  && rg -n "${PROTO}: Arc<" crates/arkham-proxy/src/lib.rs
```

## 2. Config, validation, and the demo rule

`Scheme` in `crates/arkham-config/src/grants/mod.rs` is the list of protocols. Redis added `Redis` and `Rediss`. `Scheme::as_str` is an exhaustive match, and `Scheme::all` is `strum::EnumIter` (`arkham schemes` prints that iterator). A variant missing from either fails the build. `RuleCfg::value_scheme` in `crates/arkham-config/src/config.rs` recognizes `redis://` and `rediss://`. `GrantCollector::connection_string` dispatches `Scheme::Redis | Scheme::Rediss` to `grants/redis.rs` (`redis::grant`). A connection-string rule has no `allow` entries (`Error::ConnectionStringAllow`); the fake string's port is the match. `Grant::redis` takes `host: Option<&str>` because transparent capture knows the port before it knows a name.

`IfMissing` defaults to `Error` (`#[default]` on `IfMissing::Error` in `config.rs`). A rule whose secret does not resolve fails startup.

Document the fields in `docs/user/reference/configuration.md` (the Redis rules section: scheme, port, `sslrootcert`, `sslcert`/`sslkey`, `guest_tls_mode`). Put a fake URL in `integration/arkham.toml`. Redis uses `[rules.redis_plain]` (`REDIS_URL`, `redis://…@redis:6379/0`) and `[rules.redis_tls]` (`REDIS_TLS_URL`, `rediss://…@redis:6380/0`).

```bash
export PROTO=redis
variant="$(printf '%s' "$PROTO" | python3 -c 'import sys; p=sys.stdin.read().strip(); print(p[:1].upper()+p[1:])')"
rg -n "EnumIter" crates/arkham-config/src/grants/mod.rs \
  && rg -n "${variant}," crates/arkham-config/src/grants/mod.rs \
  && rg -n "Self::${variant} => \"${PROTO}\"" crates/arkham-config/src/grants/mod.rs \
  && rg -n "${PROTO}://" crates/arkham-config/src/config.rs \
  && rg -n "fn ${PROTO}\\(" crates/arkham-config/src/grants/mod.rs \
  && rg -n "Scheme::${variant}" crates/arkham-config/src/grants/mod.rs \
  && rg -n "### ${variant} rules" docs/user/reference/configuration.md \
  && python3 - <<'PY'
import os, pathlib, re, sys
proto = os.environ["PROTO"]
text = pathlib.Path("integration/arkham.toml").read_text()
scheme = re.compile(re.escape(proto) + r"s?://")
bad = []
saw = False
for block in text.split("\n["):
    if not scheme.search(block):
        continue
    # allow-list rules name the scheme inside `allow`. A connection-string
    # rule puts it in `value` and has no allow entries.
    if not re.search(r'^value\s*=', block, re.M):
        continue
    saw = True
    if re.search(r'^allow\s*=', block, re.M):
        bad.append(block.split("]", 1)[0])
if not saw:
    print(f"no connection-string rule contains {proto}://")
    sys.exit(1)
if bad:
    print("connection-string rules must not set allow:", bad)
    sys.exit(1)
print(f"{proto} connection-string rules set no allow")
PY
```

## 3. Registry

A connection-string protocol does not get a `[providers.*]` host list. The string is the grant. `[providers.redis-cloud]` in `rules/registry.toml` is the Redis Cloud HTTPS REST API (`https://api.redislabs.com`), not RESP. Leave it alone.

Add a registry provider only when the protocol is an HTTP API with allow-list hosts. That edit is `rules/registry.toml` plus `docs/user/how-to/extend-the-registry.md`. Wire-protocol work does not need it.

`[providers.redis-cloud]` is the one exception already in the tree: the Redis Cloud HTTPS API, and only when `PROTO=redis`. Any other `[providers.<protocol>]` or `[providers.<protocol>-*]` name is a wire-host provider this step rejects.

```bash
export PROTO=redis
python3 - <<'PY'
import os, pathlib, sys
proto = os.environ["PROTO"]
# redis-cloud is the HTTPS REST API, not RESP. No other protocol has that exception.
allowed = {"redis": ["redis-cloud"]}
names = []
for line in pathlib.Path("rules/registry.toml").read_text().splitlines():
    if not line.startswith("[providers."):
        continue
    name = line.split("]", 1)[0].removeprefix("[providers.")
    if name == proto or name.startswith(proto + "-"):
        names.append(name)
extra = [name for name in names if name not in allowed.get(proto, [])]
if extra:
    print(f"{proto} added a wire-host provider:", extra)
    sys.exit(1)
print(f"{proto} wire-host providers:", ", ".join(names) or "(none)")
PY
```

## 4. Capture

Capture is all outbound TCP. nft (`crates/arkham-tproxy/src/nft.rs`), tun (`crates/arkham-tun/src/tun.rs`), and eBPF (`crates/arkham-ebpf`, `crates/arkham-ebpf-programs`) do not special-case a protocol port. The destination address is the identity; `expect` selects the scope by port.

The only port special case is UDP/443 (QUIC), which these backends do not terminate: nft drops `udp dport 443`, tun returns on `dst.port() == 443`, and `crates/arkham-ebpf/src/udp.rs` relays UDP with no substitution. Redis 6379 and 6380 needed no capture change.

eBPF cannot pin a compose service cgroup. `ARKHAM_BACKEND=ebpf mise run demo:bwrap` covers https and tcp with curl and a raw TCP client (`integration/bwrap/run.sh`). It does not run `integration/client/run.ts`. That script skips a scenario whose env var is unset.

```bash
export PROTO=redis
rg -n "udp dport 443" crates/arkham-tproxy/src/nft.rs \
  && rg -n 'dst\.port\(\) == 443' crates/arkham-tun/src/tun.rs \
  && rg -n "no substitution" crates/arkham-ebpf/src/udp.rs \
  && python3 - <<'PY'
import os, pathlib, sys
proto = os.environ["PROTO"].lower()
roots = ["crates/arkham-tproxy", "crates/arkham-tun", "crates/arkham-ebpf", "crates/arkham-ebpf-programs"]
hits = []
for root in roots:
    for path in pathlib.Path(root).rglob("*.rs"):
        if proto in path.read_text(errors="replace").lower():
            hits.append(str(path))
if hits:
    print("capture names the protocol:\n" + "\n".join(hits))
    sys.exit(1)
print("capture backends do not name the protocol")
PY
```

## 5. Secrets

Missing secrets fail closed at boot. `IfMissing::Error` is the default. That is what broke the first Redis CI run: Redis became healthy, then the arkham container exited because `REDIS_URL` / `REDIS_TLS_URL` were not declared, and the client could not join its netns. Both the x86 and ARM jobs failed this way.

The committed `integration/fnox.toml` is not what the container loads. The `certs` service runs `integration/gen-secrets.sh`, which rewrites the runtime fnox config from the environment (`ARKHAM_CONFIG=/arkham-config/config.toml` in `integration/compose.yaml`).

For each rule `env` name:

- `integration/gen-secrets.sh` requires the real value (`: "${ARKHAM_REDIS_REAL:?...}"`) and writes `[secrets.REDIS_URL]` / `[secrets.REDIS_TLS_URL]`.
- `integration/.env.example` defines `ARKHAM_REDIS_REAL` and `ARKHAM_REDIS_TLS_REAL`.
- `integration/compose.yaml` passes those variables into the service that runs `gen-secrets.sh` (`${ARKHAM_REDIS_REAL:?...}`).

Redis demo URLs (fake and real passwords are the same length):

- fake `redis://arkham_user:arkham_fake_redis_pass@redis:6379/0`
- real `redis://arkham_user:arkham_real_redis_pass@redis:6379/0`
- real TLS `rediss://arkham_user:arkham_real_redis_pass@redis:6380/0?sslrootcert=/certs/ca.crt`

`sslrootcert` stays on the real `rediss://` string so arkham trusts the demo CA. It is parsed off and not sent to Redis.

`RULE_ENVS` is the rule `env` names. `REAL_ENVS` is what `gen-secrets.sh` requires. Redis uses `REDIS_URL REDIS_TLS_URL` and `ARKHAM_REDIS_REAL ARKHAM_REDIS_TLS_REAL`. A real value's scheme is `PROTO://` or `PROTOs://` (`rediss://` for `PROTO=redis`).

```bash
export PROTO=redis
export RULE_ENVS="REDIS_URL REDIS_TLS_URL"
export REAL_ENVS="ARKHAM_REDIS_REAL ARKHAM_REDIS_TLS_REAL"
rg -n "gen-secrets.sh" integration/compose.yaml \
  && python3 - <<'PY'
import os, pathlib, sys
proto = os.environ["PROTO"]
rules = os.environ["RULE_ENVS"].split()
reals = os.environ["REAL_ENVS"].split()
script = pathlib.Path("integration/gen-secrets.sh").read_text()
example = pathlib.Path("integration/.env.example").read_text().splitlines()
compose = pathlib.Path("integration/compose.yaml").read_text()
missing = []
for key in rules:
    if f"[secrets.{key}]" not in script:
        missing.append(f"[secrets.{key}]")
for key in reals:
    if key not in script:
        missing.append(key)
    line = next((item for item in example if item.startswith(key + "=")), "")
    if not line:
        missing.append(f"{key} in .env.example")
    elif f"{proto}://" not in line and f"{proto}s://" not in line:
        missing.append(f"{key} scheme is not {proto}://")
    if "${" + key + ":?" not in compose:
        missing.append(f"{key} required by compose")
if missing:
    print("secrets wiring missing:", missing)
    sys.exit(1)
print("rule secrets are required at render time")
PY
```

## 6. No hostname on the transparent path

Transparent capture has a destination address and a port, not a URL host. Some clients send no SNI. Bun's `RedisClient` sends none. The value swap and the TLS leaf mint must use the host on the scope that `expect` already selected by port.

`RedisTransport::serve` does both:

- Guest TLS: `host.or(Some(scope.downstream.host.as_str()))` is the authority passed to `guest_tls_opening` (`crates/arkham-proxy/src/connection.rs`). Without a name, that function logs `guest TLS with no name to mint for` and closes.
- Swap: `matched_name.unwrap_or(scope.downstream.host.as_str())` is `PairCtx.host`. Keying the machine on the captured address misses `Grant::redis` and forwards the fake password. That was the second Redis CI failure, after boot succeeded.

Follow `RedisTransport::serve`. `PostgresTransport::serve` still passes the raw host into `guest_tls_opening`; a client that omits SNI needs the Redis fallback.

```bash
export PROTO=redis
rg -n "scope\.downstream\.host" "crates/arkham-proxy/src/transports/$PROTO" \
  && rg -n "${PROTO}_tls_without_sni" crates/arkham-proxy/src/e2e.rs
```

## 7. Upstream client certificates

Decide whether servers for this protocol can require a client certificate. Support it, or document why the demo turns it off.

Redis supports it. `RedisScope::client_cert` and `client_key` come from `sslcert` and `sslkey` on the real `rediss://` string (`crates/arkham-config/src/grants/redis.rs`). `connect_server` presents that pair (`with_client_auth_cert`). With neither set, it uses `with_no_client_auth`.

The demo sets `tls-ca-cert-file` and `tls-auth-clients no` in `integration/compose.yaml`. A CA file makes Redis require a client certificate. The proxy had none, so Redis closed with `peer did not return a certificate`. The demo authenticates with `AUTH` passwords, so client auth is off. The `sslcert`/`sslkey` path stays for a deployment that does present a certificate.

Guest mTLS is separate: `[rules.<label>.tls."<env>"].guest_tls_mode` (`tls` or `mtls`) on the scope's `guest_tls` field.

`integration/gen-certs.sh` mints the Redis leaf with `DNS:redis` and the demo IP so the upstream handshake can verify the name.

```bash
export PROTO=redis
rg -n "client_cert|sslcert" "crates/arkham-config/src/grants/${PROTO}.rs" \
  && rg -n "with_client_auth_cert|with_no_client_auth" "crates/arkham-proxy/src/transports/$PROTO"
```

## 8. Tests

Unit tests live next to the machine and the grant parser. Redis covers reframing and redaction in `transports/redis/machine.rs` (`auth_password_reframes_to_any_length`, `hello_auth_reframes_around_setname`, `inline_auth_reframes`, `upstream_redacts_real_password`) and grant parsing in `crates/arkham-config/src/grants/mod.rs` (`redis_rules_state_no_allow_entries`, `redis_grant_answers_for_redis_schemes`). In-process proxy tests in `crates/arkham-proxy/src/e2e.rs`: `redis_auth_swaps_over_cleartext`, `redis_auth_swaps_over_tls_both_legs`, `redis_tls_without_sni_mints_for_the_grant_host`.

The compose end-to-end test uses the official server image and a maintained client. Redis is `image: redis:7-alpine` in `integration/compose.yaml` and Bun's `RedisClient` (`import { RedisClient } from "bun"` in `integration/client/run.ts`). The proxy is the only code we wrote on that path.

`run.ts` scenario 6 builds pgwire frames in process (`pgStartup`, `pgFrame`). A new protocol's scenario uses the official client the way scenarios 9 and 10 use `RedisClient`.

Gate the scenario on the compose env, with an `else` that skips when the variable is unset (bwrap):

```ts
const REDIS_URL = process.env.REDIS_URL ?? "";
if (REDIS_URL) {
  await redisScenarios("plaintext", REDIS_URL);
} else {
  stage("redis plaintext scenarios skipped: no REDIS_URL");
}
```

`retry`'s first argument is the scheme that scenario covers (`"redis"`, `"rediss"`). `redisScenarios` picks it from `kind`. A scenario that covers no scheme passes `""` and is not recorded.

```bash
export PROTO=redis
rg -n "$PROTO" "crates/arkham-proxy/src/transports/$PROTO" crates/arkham-proxy/src/e2e.rs \
  && rg -n "\"${PROTO}\"" integration/client/run.ts \
  && rg -n -i "image: ${PROTO}:" integration/compose.yaml
```

## 9. CI and the README

`.github/workflows/ci.yml` job `rust` runs on `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm`. Both run `mise build`, which depends on `mise run test`. That runs `test:rust` and then `test:ssh` (`.mise/tasks/test/ssh`).

`test:ssh` loops `ARKHAM_TEST_BACKENDS` (default `tproxy tun`) and runs `integration/compose.yaml`. On a non-zero client exit it appends compose logs to `/tmp/arkham-integration-compose.log`. The workflow step `Dump integration compose logs` (`if: failure()`) prints that file and `docker compose logs`. A new scenario rides this path once `run.ts` calls it and the client env is set. Do not add a workflow job per protocol.

Add a row to the protocol table in `README.md`. Redis is the RESP row. `integration/README.md` lists scenarios 9 and 10, the official image, Bun's client, `tls-auth-clients no`, and the bwrap skip.

```bash
export PROTO=redis
rg -n "ubuntu-24.04-arm" .github/workflows/ci.yml \
  && rg -n "Dump integration compose logs|arkham-integration-compose.log" .github/workflows/ci.yml .mise/tasks/test/ssh \
  && rg -n -i "^\\| ${PROTO} \\|" README.md \
  && rg -n -i "$PROTO" integration/README.md
```

## 10. Pull request

`Closes #N` when the PR fully finishes issue N. `Refs #N` when N is an umbrella or epic. A title that starts with `Tracking:` is one of those: PR #44's body is `Refs #23` because #23 is `Tracking: Redis RESP credential rewriting`. The squash commit message does not carry that line; read the PR body.

The command needs `gh` signed in (`gh auth status`). If it is not, open the PR on the forge and look for the same line in the body.

```bash
export ISSUE=23 PR=44
gh auth status \
  && python3 - <<'PY'
import json, os, subprocess, sys
issue = os.environ["ISSUE"]
pr = os.environ["PR"]
title = json.loads(subprocess.check_output(["gh", "issue", "view", issue, "--json", "title"], text=True))["title"]
body = json.loads(subprocess.check_output(["gh", "pr", "view", pr, "--json", "body"], text=True))["body"]
tracking = title.startswith("Tracking:")
needle = f"Refs #{issue}" if tracking else f"Closes #{issue}"
if needle not in body:
    print(f"PR body must contain {needle!r} (issue title: {title})")
    sys.exit(1)
print(needle, "present")
PY
```

Set `ISSUE` and `PR` to the issue this change finishes and the pull request that carries it. The command requires `Closes #N` when the issue title does not start with `Tracking:`, and `Refs #N` when it does.

## 11. Scheme coverage

A passing `retry(scheme, label, fn)` records `scheme`. When `ARKHAM_COVERED` is set, the client writes that set to the path. Compose sets it to `/out/covered.json` and bind-mounts `integration/out` on `/out`. Unset, the write is skipped, so a run of the script without that mount still finishes. Compose also passes `HOST_UID` and drops to that user after `apt-get`, so the file is not owned by root.

`.mise/tasks/test/ssh` deletes `integration/out/covered.json` before each backend (`tproxy`, then `tun`). A leftover from the previous backend cannot satisfy the next one. After a client exits 0 it runs `integration/docker/arkham schemes` and fails, naming each scheme missing from the file. `arkham schemes` prints `Scheme::all()`, which is every `EnumIter` variant. CI runs this on both `rust` matrix legs (`mise build` → `test` → `test:ssh`). Do not add a parser or a second list.

A new variant needs an `as_str` arm (the match is exhaustive) and a passing `retry` whose scheme is that name, against the official server image. `EnumIter` puts the variant in `arkham schemes` on its own. Until the scenario passes, `test:ssh` fails.

```bash
export PROTO=redis
rg -n "ARKHAM_COVERED" integration/client/run.ts integration/compose.yaml \
  && rg -n "rm -f integration/out/covered.json" .mise/tasks/test/ssh \
  && rg -n "EnumIter" crates/arkham-config/src/grants/mod.rs \
  && rg -n "fn all" crates/arkham-config/src/grants/mod.rs \
  && rg -n "\"${PROTO}\"" integration/client/run.ts
```
