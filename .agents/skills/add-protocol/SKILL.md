---
name: add-protocol
description: >
  Checklist for adding a credential-rewriting protocol to arkham. Use when
  adding a wire protocol or connection-string grant (Redis, Postgres, MySQL,
  MQTT, AMQP, and the like), capture for a new port, or an integration
  end-to-end scenario.
---

# Add a credential-rewriting protocol

Grant matching stays in `arkham-config`. Substitution stays in `arkham-proxy` (`transports/`). Capture backends hand the stream to `serve_transparent_stream`.

`PROTO` is the transport directory (`redis`). `VARIANT` is the `Scheme` variant you write out (`Redis`, `Rediss`); do not derive it by capitalizing `PROTO`. Redis, as one finished protocol, is [reference/redis.md](reference/redis.md).

## Checklist

1. **Transport.** Add `crates/arkham-proxy/src/transports/$PROTO/` and `pub(crate) mod` it. `engine` is the shared substitution machine, not a protocol. Register the strategy on `ProxyState` and route it from `Expect`.

2. **Scheme.** Add `VARIANT`. `Scheme::as_str` is an exhaustive match. `Scheme::all` is `strum::EnumIter`, so `arkham schemes` lists the variant without a second array. When a URL omits a port, add an arm in `EndpointScope`'s port match (`crates/arkham-config/src/grants/mod.rs`). `tcp` stays explicit.

3. **Grant.** Parse the rule once in `arkham-config` and dispatch it from `GrantCollector::connection_string`. A connection-string rule has no `allow` entries; the string is the grant. A missing secret fails startup (`IfMissing::Error`): an undeclared secret makes arkham exit at boot. Require the real value in `integration/gen-secrets.sh`, `integration/.env.example`, and a `${VAR:?}` in `integration/compose.yaml`.

4. **Decoy.** The decoy is format-valid. A raw TCP swap is equal-length only, so a `tcp://` grant whose shaped decoy has a different length uses the length-matched render from `decoy_for_rule`. A protocol that reframes may change length.

5. **`expect`.** Add the grant lookup in `expect` (`crates/arkham-proxy/src/identity.rs`). That order is the tie-break: one port matching more than one family is ambiguous until bytes arrive, the first arm wins, and an arm whose framing does not arrive closes instead of trying another. Protocols that cannot share a port use different ports. Add the `Expect` `PartialEq` arm in the same file. `Expect::serve` is not the only match. A scope arm compares by pointer; a unit arm compares by kind.

6. **Transparent host.** Capture has a destination address and a port, not a URL host, and some clients send no SNI. Mint the leaf and key the swap on the host of the scope `expect` already selected, not on the captured address.

7. **Client certificates.** Support an upstream client certificate, or say why this demo turns it off. A CA file on the server can make it demand one.

8. **Registry.** A connection-string protocol does not get a `[providers.*]` host list. Add a provider only for an HTTP API with allow-list hosts.

9. **Capture.** nft, tun, and eBPF do not special-case a protocol port. The only special case is UDP/443 (QUIC). Leave this protocol's port out of those crates.

10. **Tests.** Unit tests sit next to the machine and the grant parser. Property tests follow `crates/arkham-proxy/src/transports/engine/fuzz_props.rs`: invariants on valid framing, and no panic on arbitrary bytes. The compose scenario uses the official server image and a maintained client. `retry`'s first argument is the scheme; a scenario that covers none passes `""` and is not recorded. Gate the scenario on its env var so `integration/client/run.ts` still runs when that service is absent. `integration/bwrap/run.sh` does not run `run.ts`.

11. **Docs.** Add a row to the protocol table in `README.md` and the scenario list in `integration/README.md`. The existing `rust` jobs already run `mise run test:ssh` on x86_64 and ARM. Do not add a job per protocol.

12. **Pull request.** The PR body says `Closes #N`, or `Refs #N` when the issue title starts with `Tracking:`.

## Done

From the repo root. Pass every new scheme (`redis`, and `rediss` when that variant exists).

```bash
mise run test:rust
set -o pipefail
mise run test:ssh | tee /tmp/arkham-test-ssh.log
.agents/skills/add-protocol/scripts/covered.sh /tmp/arkham-test-ssh.log "$SCHEME"
```

`mise run test:rust` runs the unit and property tests. `covered.sh` fails when `test:ssh` skipped (no docker daemon still exits 0), when no backend printed `passed`, or when `integration/out/covered.json` lacks a scheme.
