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

Each step ends with a command. Run it from the repo root. A non-zero exit means the step is not done. The Redis names below are the example; substitute the protocol you are adding.

## 1. Transport module

Add `crates/arkham-proxy/src/transports/<protocol>/` and `pub(crate) mod <protocol>` in `crates/arkham-proxy/src/transports/mod.rs`. `engine` is the shared substitution engine, not a protocol.

The vertical parses the protocol and finds the credential bytes the swap reframes. Redis does that in `crates/arkham-proxy/src/transports/redis/machine.rs` (`AUTH` and `HELLO`, including a password of a different length). `RedisTransport` in `transports/redis/mod.rs` implements `Transport::serve`.

Register the strategy on `ProxyState` (`crates/arkham-proxy/src/lib.rs`, field `redis`, constructed in `ProxyState::new`). Route it from `Expect` in `crates/arkham-proxy/src/identity.rs`: `expect` calls `Grant::redis`, and `Expect::serve` is the only `match` on the picked protocol (`Expect::Redis` → `state.redis.serve`).

```bash
test -d crates/arkham-proxy/src/transports/redis \
  && rg -n "mod redis" crates/arkham-proxy/src/transports/mod.rs \
  && rg -n "fn serve" crates/arkham-proxy/src/transports/redis/mod.rs \
  && rg -n "AUTH|HELLO" crates/arkham-proxy/src/transports/redis/machine.rs \
  && rg -n "Expect::Redis" crates/arkham-proxy/src/identity.rs \
  && rg -n "redis: Arc<RedisTransport>" crates/arkham-proxy/src/lib.rs
```

## 2. Config, validation, and the demo rule

`Scheme` in `crates/arkham-config/src/grants/mod.rs` is the list of protocols. Redis added `Redis` and `Rediss`. `RuleCfg::value_scheme` in `crates/arkham-config/src/config.rs` recognizes `redis://` and `rediss://`. `GrantCollector::connection_string` dispatches `Scheme::Redis | Scheme::Rediss` to `grants/redis.rs` (`redis::grant`). A connection-string rule has no `allow` entries (`Error::ConnectionStringAllow`); the fake string's port is the match. `Grant::redis` takes `host: Option<&str>` because transparent capture knows the port before it knows a name.

`IfMissing` defaults to `Error` (`#[default]` on `IfMissing::Error` in `config.rs`). A rule whose secret does not resolve fails startup.

Document the fields in `docs/user/reference/configuration.md` (the Redis rules section: scheme, port, `sslrootcert`, `sslcert`/`sslkey`, `guest_tls_mode`). Put a fake URL in `integration/arkham.toml`. Redis uses `[rules.redis_plain]` (`REDIS_URL`, `redis://…@redis:6379/0`) and `[rules.redis_tls]` (`REDIS_TLS_URL`, `rediss://…@redis:6380/0`).

```bash
rg -n "Redis,|Rediss," crates/arkham-config/src/grants/mod.rs \
  && rg -n 'redis://|rediss://' crates/arkham-config/src/config.rs \
  && rg -n "fn redis\(" crates/arkham-config/src/grants/mod.rs \
  && rg -n "Scheme::Redis \| Scheme::Rediss" crates/arkham-config/src/grants/mod.rs \
  && rg -n "redis_plain|redis_tls" integration/arkham.toml \
  && rg -n "### Redis rules" docs/user/reference/configuration.md \
  && python3 - <<'PY'
import pathlib, sys
text = pathlib.Path("integration/arkham.toml").read_text()
blocks = text.split("\n[")
bad = []
for block in blocks:
    if block.startswith("rules.redis_plain]") or block.startswith("rules.redis_tls]"):
        if "\nallow" in "\n" + block.split("\n[", 1)[0]:
            bad.append(block.split("]", 1)[0])
if bad:
    print("connection-string rules must not set allow:", bad)
    sys.exit(1)
PY
```

## 3. Registry

A connection-string protocol does not get a `[providers.*]` host list. The string is the grant. `[providers.redis-cloud]` in `rules/registry.toml` is the Redis Cloud HTTPS REST API (`https://api.redislabs.com`), not RESP. Leave it alone.

Add a registry provider only when the protocol is an HTTP API with allow-list hosts. That edit is `rules/registry.toml` plus `docs/user/how-to/extend-the-registry.md`. Wire-protocol work does not need it.

```bash
rg -n '^\[providers\.redis' rules/registry.toml \
  && python3 - <<'PY'
import pathlib, sys
names = [
    line.split("]", 1)[0].removeprefix("[providers.")
    for line in pathlib.Path("rules/registry.toml").read_text().splitlines()
    if line.startswith("[providers.redis")
]
if names != ["redis-cloud"]:
    print("RESP must not grow a wire-host provider; found", names)
    sys.exit(1)
print("registry redis providers:", ", ".join(names), "(HTTPS API only)")
PY
```

## 4. Capture

Capture is all outbound TCP. nft (`crates/arkham-tproxy/src/nft.rs`), tun (`crates/arkham-tun/src/tun.rs`), and eBPF (`crates/arkham-ebpf`, `crates/arkham-ebpf-programs`) do not special-case a protocol port. The destination address is the identity; `expect` selects the scope by port.

The only port special case is UDP/443 (QUIC), which these backends do not terminate: nft drops `udp dport 443`, tun returns on `dst.port() == 443`, and `crates/arkham-ebpf/src/udp.rs` relays UDP with no substitution. Redis 6379 and 6380 needed no capture change.

eBPF cannot pin a compose service cgroup. `ARKHAM_BACKEND=ebpf mise run demo:bwrap` runs the same client script. Scenarios whose env is unset are skipped (bwrap sets no `REDIS_URL`).

```bash
rg -n "udp dport 443" crates/arkham-tproxy/src/nft.rs \
  && rg -n 'dst\.port\(\) == 443' crates/arkham-tun/src/tun.rs \
  && rg -n "no substitution" crates/arkham-ebpf/src/udp.rs \
  && python3 - <<'PY'
import pathlib, sys
roots = ["crates/arkham-tproxy", "crates/arkham-tun", "crates/arkham-ebpf", "crates/arkham-ebpf-programs"]
needles = ("6379", "6380")
hits = []
for root in roots:
    for path in pathlib.Path(root).rglob("*"):
        if path.suffix not in {".rs"}:
            continue
        text = path.read_text(errors="replace")
        for needle in needles:
            if needle in text:
                hits.append(f"{path}: {needle}")
if hits:
    print("capture special-cases a protocol port:\n" + "\n".join(hits))
    sys.exit(1)
print("capture backends do not special-case Redis ports")
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

```bash
rg -n "ARKHAM_REDIS_REAL|ARKHAM_REDIS_TLS_REAL" integration/gen-secrets.sh integration/.env.example integration/compose.yaml \
  && rg -n '\[secrets\.REDIS_URL\]|\[secrets\.REDIS_TLS_URL\]' integration/gen-secrets.sh \
  && rg -n "gen-secrets.sh" integration/compose.yaml \
  && python3 - <<'PY'
import pathlib, sys
script = pathlib.Path("integration/gen-secrets.sh").read_text()
example = pathlib.Path("integration/.env.example").read_text()
compose = pathlib.Path("integration/compose.yaml").read_text()
required = ["ARKHAM_REDIS_REAL", "ARKHAM_REDIS_TLS_REAL", "[secrets.REDIS_URL]", "[secrets.REDIS_TLS_URL]"]
missing = [item for item in required if item not in script]
if missing:
    print("gen-secrets.sh missing", missing)
    sys.exit(1)
for key in ("ARKHAM_REDIS_REAL", "ARKHAM_REDIS_TLS_REAL"):
    if f"{key}=" not in example:
        print(key, "missing from .env.example")
        sys.exit(1)
    if "${" + key + ":?" not in compose:
        print(key, "is not required by compose")
        sys.exit(1)
print("redis secrets are required at render time")
PY
```

## 6. No hostname on the transparent path

Transparent capture has a destination address and a port, not a URL host. Some clients send no SNI. Bun's `RedisClient` sends none. The value swap and the TLS leaf mint must use the host on the scope that `expect` already selected by port.

`RedisTransport::serve` does both:

- Guest TLS: `host.or(Some(scope.downstream.host.as_str()))` is the authority passed to `guest_tls_opening` (`crates/arkham-proxy/src/connection.rs`). Without a name, that function logs `guest TLS with no name to mint for` and closes.
- Swap: `matched_name.unwrap_or(scope.downstream.host.as_str())` is `PairCtx.host`. Keying the machine on the captured address misses `Grant::redis` and forwards the fake password. That was the second Redis CI failure, after boot succeeded.

Follow `RedisTransport::serve`. `PostgresTransport::serve` still passes the raw host into `guest_tls_opening`; a client that omits SNI needs the Redis fallback.

```bash
rg -n "scope\.downstream\.host" crates/arkham-proxy/src/transports/redis/mod.rs \
  && rg -n "guest TLS with no name to mint for" crates/arkham-proxy/src/connection.rs \
  && rg -n "fn redis_tls_without_sni_mints_for_the_grant_host" crates/arkham-proxy/src/e2e.rs
```

## 7. Upstream client certificates

Decide whether servers for this protocol can require a client certificate. Support it, or document why the demo turns it off.

Redis supports it. `RedisScope::client_cert` and `client_key` come from `sslcert` and `sslkey` on the real `rediss://` string (`crates/arkham-config/src/grants/redis.rs`). `connect_server` presents that pair (`with_client_auth_cert`). With neither set, it uses `with_no_client_auth`.

The demo sets `tls-ca-cert-file` and `tls-auth-clients no` in `integration/compose.yaml`. A CA file makes Redis require a client certificate. The proxy had none, so Redis closed with `peer did not return a certificate`. The demo authenticates with `AUTH` passwords, so client auth is off. The `sslcert`/`sslkey` path stays for a deployment that does present a certificate.

Guest mTLS is separate: `[rules.<label>.tls."<env>"].guest_tls_mode` (`tls` or `mtls`) on the scope's `guest_tls` field.

`integration/gen-certs.sh` mints the Redis leaf with `DNS:redis` and the demo IP so the upstream handshake can verify the name.

```bash
rg -n "sslcert|client_cert" crates/arkham-config/src/grants/redis.rs \
  && rg -n "with_client_auth_cert|with_no_client_auth" crates/arkham-proxy/src/transports/redis/mod.rs \
  && rg -n "tls-auth-clients no" integration/compose.yaml \
  && rg -n "DNS:redis" integration/gen-certs.sh \
  && rg -n "sslcert|guest_tls_mode" docs/user/reference/configuration.md
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

A shared function that serves two schemes takes a word argument the label also contains (`"plaintext"` or `"tls"`), matching `redisScenarios` in `run.ts`.

```bash
rg -n "fn auth_password_reframes_to_any_length|fn upstream_redacts_real_password" crates/arkham-proxy/src/transports/redis/machine.rs \
  && rg -n "fn redis_auth_swaps_over_cleartext|fn redis_tls_without_sni_mints_for_the_grant_host" crates/arkham-proxy/src/e2e.rs \
  && rg -n "image: redis:7-alpine" integration/compose.yaml \
  && rg -n 'RedisClient' integration/client/run.ts \
  && rg -n 'redis plaintext requirepass auth swaps password|redis tls requirepass auth over arkham MITM' integration/client/run.ts integration/README.md
```

## 9. CI and the README

`.github/workflows/ci.yml` job `rust` runs on `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm`. Both run `mise build`, which depends on `mise run test`. That runs `test:rust` and then `test:ssh` (`.mise/tasks/test/ssh`).

`test:ssh` loops `ARKHAM_TEST_BACKENDS` (default `tproxy tun`) and runs `integration/compose.yaml`. On a non-zero client exit it appends compose logs to `/tmp/arkham-integration-compose.log`. The workflow step `Dump integration compose logs` (`if: failure()`) prints that file and `docker compose logs`. A new scenario rides this path once `run.ts` calls it and the client env is set. Do not add a workflow job per protocol.

Add a row to the protocol table in `README.md`. Redis is the RESP row. `integration/README.md` lists scenarios 9 and 10, the official image, Bun's client, `tls-auth-clients no`, and the bwrap skip.

```bash
rg -n "ubuntu-24.04-arm" .github/workflows/ci.yml \
  && rg -n "Dump integration compose logs|arkham-integration-compose.log" .github/workflows/ci.yml .mise/tasks/test/ssh \
  && rg -n "^\| Redis \|" README.md \
  && rg -n "redis:7-alpine|tls-auth-clients no" integration/README.md
```

## 10. Pull request

`Closes #N` when the PR fully finishes issue N. `Refs #N` when N is an umbrella or epic. A title that starts with `Tracking:` is one of those: PR #44's body is `Refs #23` because #23 is `Tracking: Redis RESP credential rewriting`. The squash commit message does not carry that line; read the PR body.

```bash
gh issue view 23 --json title --jq .title \
  && gh pr view 44 --json body --jq .body | rg "Refs #23"
```

For the issue this PR finishes, replace `23` and `44`. Require `Closes #N` when the issue title does not start with `Tracking:`. Require `Refs #N` when it does.

## 11. End-to-end coverage gate

`supported_and_configured_protocols_have_live_e2e_scenarios` in `crates/arkham-proxy/src/protocol_coverage.rs` fails the build when a protocol is supported or configured and has no live compose scenario. It is a `#[cfg(test)]` module included from `crates/arkham-proxy/src/lib.rs`. There is no hand-maintained manifest.

Supported protocols are the `Scheme` variants in `crates/arkham-config/src/grants/mod.rs` plus directories under `crates/arkham-proxy/src/transports/` except `engine`. The directory name is the protocol id. A scheme maps to the directory of the same name, or to the longest directory name that is a prefix (`https` → `http`, `rediss` → `redis`). A variant with no directory, or a directory with no variant, is a gap.

Configured protocols are quoted `scheme://` URLs in `integration/arkham.toml`. An unknown scheme (`mysql://` while `Scheme` has no `Mysql`) is a gap.

A live scenario is a `retry()` label in `integration/client/run.ts`:

- The label contains the scheme as an alphanumeric-bounded token, so `https` does not cover `http`.
- `rediss` has no token in the Redis labels. A label that contains both `redis` and `tls` covers it.
- The label sits on a path the compose client runs. `const NAME = process.env.KEY` plus `if (NAME) { ... } else { ... }` counts only when `KEY` is in the `client` service `environment` of `integration/compose.yaml`. The `else` arm does not count.
- A shared function called as `fn("tls")` and `fn("plaintext")` attributes a label to the call whose first word the label contains. A template that does not contain that word runs for every call.
- `if (!X || Y)` is not an env gate. Use `if (NAME)`.

The test also asserts the parser still sees `Http`, `Https`, `Tcp`, `Postgres`, `Redis`, `Rediss`, and `Ssh`. A new `Scheme` variant is picked up without editing the test.

The test runs inside `mise run test` (`test:rust` → `cargo nextest`, workspace, `--exclude arkham-ebpf-programs`). CI runs that via `mise build` on both matrix legs. Do not run `cargo test` or a nextest filter.

```bash
rg -n "mod protocol_coverage" crates/arkham-proxy/src/lib.rs \
  && rg -n "fn supported_and_configured_protocols_have_live_e2e_scenarios" crates/arkham-proxy/src/protocol_coverage.rs \
  && mise run --force test
```
