# Local confinement without containers: full plan

Scope captured here: a local execution backend for `arkham agent` that confines the agent on the host with OS primitives instead of a container. Transparent traffic capture is the mechanism on all three OSes. Nothing about networking is imposed on the sandbox: no `HTTP_PROXY` or `HTTPS_PROXY` variables, no proxy flags, no cooperation from agent tooling. Those variables belong to the tools now, and the space only gets more crowded. The platform routes traffic into arkham whether the sandbox knows or not. Explicit proxy remains as a fallback and debug path only. This plan covers Linux, macOS, and Windows end to end. No track is parked.

## Constraints

1. The sandbox carries decoys only, delivered as env values. Env stays the secret-input channel. It must never carry network behavior.
2. Real secrets live in arkham processes. The sandbox never sees them.
3. One portable policy (write profiles), one renderer per OS for filesystem confinement, one capture design per OS.
4. Capture failure must not leak secrets. Agents hold decoys, so direct egress on capture failure sends decoys upstream and upstream rejects them. Breakage, not leakage. Substitution paths keep their fail-closed latches regardless.
5. Per-workspace secret sets must never union. Decoys are deterministic per env name (`fake_for` hashes the seed alone), so two workspaces sharing `GITHUB_TOKEN` mint the same fake for different reals. Selection of the secret set happens per connection before pairs are built. Unknown source splices with no swap.

## Current state, from source

- Confinement today is the compose stack. `generate_stack` (`crates/arkham-compose/src/stack.rs:461`) resolves `WorkspaceInputs`, selects decoys, writes rewrites, derives ambient sources, writes grants state, resolves profile mounts, and renders a `Stack`. The agent service holds decoys only. Arkham holds real secrets. `AgentArgs::run` (`crates/arkham-compose/src/confine.rs:842`) runs generate, start, then enter.
- The proxy is single tenant. `ProxyState` holds one `Arc<ResolvedConfig>` and one plugin registry, write once, no reload (`crates/arkham-proxy/src/lib.rs:63`). Routing is destination only via `grant.matches(scheme, host, port)`. The peer address is read for a debug log and never selects rules (`lib.rs:245`). No `Proxy-Authorization` handling exists anywhere in `arkham-proxy`.
- Linux capture exists. `arkham-tproxy` installs nftables rules plus policy routes over netlink (`crates/arkham-tproxy/src/nft.rs`, `route.rs`) and refuses unscoped host-namespace installs without an explicit flag (`error.rs:91`). `arkham-ebpf` attributes by cgroup membership plus PID check, with byte-explicit map structs. The Linux decision is eBPF: each sandbox lands in its own cgroup, capture attaches per cgroup, attribution is structural.
- Rama abstracts per-OS capture. Linux has `ip_transparent` socket options plus a tproxy connector layer (`rama-net/src/socket/opts.rs`, `socket/linux/tproxy.rs`). Windows has a WFP redirect-context reader (`socket/windows/tproxy.rs`): the redirect record is queried with `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`, our code provides the `WfpContextDecoder`, and an absent record (`WSAEINVAL`) means the socket was not redirected. macOS has the `rama-net-apple-networkextension` crate plus a full transparent-proxy example (`ffi/apple/examples/transparent_proxy`) with container app, system extension, signing scripts, and install flow.
- Public precedent for one policy with per-OS backends is Chromium: Linux combines namespaces with seccomp-bpf, macOS uses Seatbelt profiles (`sandbox/mac/seatbelt.cc`), and Windows combines a restricted token with a job object, a separate desktop, and integrity levels (`docs/design/sandbox.md`).

## Write profiles

A profile names readable paths and writable paths for one workspace execution. Modes are `read-only` (deny writes, keep the `/dev/null` sink shells require) and `workspace-write` (writable workspace root plus a backend-defined temp area). A third spelling, `danger-full-access`, bypasses confinement and never reaches a backend. Network and process visibility stay outside this vocabulary: the network is governed by capture, not by policy flags. One shared helper derives the writable set, and every renderer plus every test reads that helper. No renderer invents its own roots.

Renderers are per OS, selected by platform first and functional probe second. Linux tries bwrap, then the Landlock launcher. macOS uses Seatbelt. Windows uses the restricted-token runner. Each candidate probes once with the real profile (`true` under it, exit 0 wins) and the verdict caches for the process lifetime. A platform with no usable runner errors instead of running bare. An operator `runnerCommand` override may assert its own enforcement and skip probes.

Enforcement is a reported fact. Backends return `full` or `partial`. Older Landlock ABIs report partial. Windows reports partial for hard-link aliasing and unconfined reads. Callers that need an absolute boundary reject partial. Nothing claims full without a passing probe.

## Linux: eBPF capture with cgroup attribution

Each sandbox runs in its own cgroup. The eBPF programs (`arkham-ebpf-programs`: `connect4`, `recvmsg4`, `capture_egress`, `CONFIG` / `ORIG_DST` / `FLOW` maps) attach per cgroup, so flows arrive already attributed to a workspace. The userspace half hands accepted streams to `serve_transparent_stream`. No env vars, no proxy flags, no cooperation from the agent. Tools inside may set `HTTP_PROXY` to anything: the TCP connection itself is captured either way.

The bwrap invocation keeps the filesystem shape from the compose inputs (workspace root and `include` entries with their ro flags, `file_mounts` and guest mounts read only, `tool_mounts` with their flags, fnox binds and grants mounts never entering) plus `--unshare-pid --unshare-uts --unshare-ipc --die-with-parent --new-session`, the CA as a read-only bind with trust env pointers, and decoy env values. `--unshare-net` stays off: the sandbox shares the host stack and eBPF sees its flows through cgroup membership.

## macOS: NetworkExtension dispatcher plus sidecars

The provider attributes and dispatches. It never substitutes. Each intercepted TCP flow is handed to the workspace sidecar that owns the originating process, and the sidecar performs MITM plus substitution. Secrets stay out of the system extension, and `arkham-proxy` is reused with one addition: parsing a PROXY header on the loopback handoff.

Three components, following the rama example layout. A host controller app installs and manages the proxy profile through `NETransparentProxyManager` with `start`, `stop`, and `status`. A system extension implements `NETransparentProxyProvider` and links a Rust dispatcher as a static library through the rama C ABI bridge. One arkham sidecar process per workspace accepts dispatched flows on its claimed loopback port. macOS owns the extension lifecycle: it starts, stops, and restarts the extension as needed, so the dispatcher restarts cleanly from externally persisted configuration, and the controller re-pushes the workspace table on every start and every change.

Per-flow data path, grounded in the bridge surface (`ffi/apple/RamaAppleNetworkExtension`). `handleNewFlow` snapshots `NEFlowMetaData` at the adapter boundary: source app bundle identifier, audit token bytes, PID when set, remote hostname, protocol, and both endpoints. The snapshot crosses FFI as a plain struct (`rama_apple_ne_ffi.h`: endpoint metadata plus `source_app_bundle_identifier`, `source_app_audit_token_bytes`, `source_app_pid` with its `is_set` flag). The Rust engine returns one verdict per flow: dispatch to a workspace, bypass, or block. TCP and UDP flows share the core logic through the `TcpFlowLike` and `UdpFlowLike` protocols, with the modern macOS 15 UDP callback plus the legacy fallback. Interception rules stay TCP only: UDP is excluded, which keeps QUIC and DNS on the system path by construction.

Attribution resolves in order. The source PID when set, or the audit token through `rama_apple_audit_token_to_pid`, indexes the supervisor process table: agent PIDs with start times, pushed over XPC on spawn and exit, where start times defeat PID reuse. The bundle identifier covers agents running as distinct signed helpers. Anything unattributed bypasses: connectivity fails open while secrets stay safe, because bypassed flows carry decoys. `NENetworkRule` objects select remote networks and TCP while excluding loopback, private ranges, and DNS.

Dispatch is a loopback handoff. The provider opens an `NWConnection` to `127.0.0.1:<workspace-port>`, writes a PROXY v1 header carrying the original destination, then relays bytes both ways. The sidecar parses the header and continues down the existing transparent-stream path. Egress keeps the bridge default of stamping the original flow metadata (`preserve_original_meta_data`), so upstream connections present the true source identity.

Secrets never cross Apple-logged paths. The opaque config payload appears in system diagnostics with no suppression, so it carries timeouts and exclusions only. The CA follows the example: the sysext generates the MITM root CA into `/Library/Keychains/System.keychain` with boring TLS on first start and reuses it; the controller rotates it live over XPC and clears it on request. The container app never creates or reads CA material.

Packaging is an app bundle with the embedded extension, copied to `/Applications` and registered. It surfaces under Filters and Proxies, needs one user approval, and persists across reboots. Two signing tracks share one extension implementation with the entitlement payload switched per track: Apple Development with automatic signing for local work, Developer ID with notarize plus staple for distribution, distinct bundle IDs per track, both extension IDs uninstalled when switching. Logging goes through unified logging with the bridge privacy split: endpoints and attribution are private metadata, never public text. Debug persistence stays development only.

Verification: install developer signed, start, prove an unattributed `curl` bypasses, prove an attributed agent flow substitutes with zero proxy env set, kill a sidecar and prove its flows bypass, rotate the CA live over XPC.

## Windows: WFP callout driver plus Rama

Two parts with a hard responsibility split. A kernel callout driver decides what happens to traffic. Rama in userspace decides how redirected traffic is handled. The driver holds no proxy logic and no secrets.

Filters select TCP v4 and v6 while excluding loopback, private ranges, DNS, and UDP 443 (QUIC drops to force fallback, parity with the nft rules). The redirect callout sits at `ALE_CONNECT_REDIRECT`, where the destination can still change. Its classify function reads the originating process ID, looks it up in the driver-side process table arkham pushes (agent PID subtrees tagged per workspace), rewrites the destination to `127.0.0.1:<workspace-port>`, attaches the redirect handle, and writes the context blob carrying the original destination plus the workspace tag. An `ALE_AUTH_CONNECT` callout owns allow-or-block decisions: QUIC drops, pinned-app bypasses, system-service exclusions. Unknown processes get no tag and their flows are permitted direct.

Each workspace sidecar accepts on its claimed port, queries `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` on the socket, and decodes the record with arkham `WfpContextDecoder`: original destination out, workspace tag cross-checked against the port. The flow then continues down the existing transparent-stream path. An absent record (`WSAEINVAL`) means the socket was not redirected, and the flow splices. No PROXY header is needed here: the context already carries the original destination.

Driver and proxy talk through a device object with IOCTLs. Arkham pushes proxy endpoints, sidecar ports, and process-table deltas on agent spawn and exit, and pulls counters for verification. All runtime state lives in driver memory only, is set at proxy startup, and clears automatically when arkham exits, tracked through kernel process notifications. Proxy updates need no reboot: start the new instance, let it register, confirm substitution, stop the old one, where the tracked PID keeps the old instance from clearing the new config. Driver updates need a reboot. Verification reads driver load state, the service entry, registered filters and callouts, and the Base Filtering Engine status. Debug tooling is DebugView for kernel output, WinDbg in a VM for deep work, Process Explorer and WinObj for inspection.

The installer needs admin rights: service registration with a BFE dependency, a private sublayer with a documented weight for coexistence with VPNs and other WFP products, persistent filter install, and clean removal undoing all of it. Development uses test signing. The production signing path is an open question below.

Failure strategy is fail open for connectivity: no proxy configured, local or private destination, uninterceptive protocol, or redirect failure all permit direct. Secret safety is unaffected per the constraints, since direct flows carry decoys.

## Proxy shape

One arkham process per workspace. Each sidecar holds exactly one `ResolvedConfig`, which makes cross-workspace leakage structurally impossible and needs zero proxy code changes: `serve` already takes one snapshot. The recorded alternative is a multi-listener single process (local port or source key selects the snapshot, per-workspace plugin registries and mint stores). Unknown source splices with no swap in every shape.

Port allocation: the fixed `127.0.0.1:8099` works in compose because each stack owns its netns. Host sidecars share loopback, so each workspace claims its own port. Keep a claim record under the workspace state dir (`<state-dir>/arkham/ws/<slug>/proxy.port`) holding port plus owner PID. On start, reuse a live claim, reap a dead one after a bind probe, else claim the next free port from the configured range. `ARKHAM_LISTEN` keeps overriding everything, so operators and tests pin ports directly. A slug-hash default without claims is rejected: collisions fail at bind time with a confusing error instead of self-healing. Down teardown (`rm`) drops the claim.

## Filesystem backends

Linux argv shape for `workspace-write`, before the `--` separator and the agent command:

```sh
bwrap \
  --ro-bind / / \
  --dev /dev --proc /proc \
  --unshare-pid --unshare-uts --unshare-ipc \
  --tmpfs /tmp \
  --bind <workspace-root> <workspace-root> \
  --ro-bind <rewritten-file> <dest> ... \
  --ro-bind <tool-dir> <config-dir> ... \
  --ro-bind <ca.pem> /arkham/ca.pem \
  --die-with-parent --new-session --clearenv \
  --setenv SSL_CERT_FILE /arkham/ca.pem \
  --setenv NODE_EXTRA_CA_CERTS /arkham/ca.pem \
  --setenv REQUESTS_CA_BUNDLE /arkham/ca.pem \
  --setenv <DECOY> <fake> ... \
  -- <shell-or-command>
```

No `HTTP_PROXY` variables appear. Landlock is the chain fallback with `--ro / --rw <roots>` grants from the same profile. `read-only` mode drops the workspace bind and the tmpfs.

macOS emits SBPL from the shared writable roots:

```
(version 1) (allow default) (deny file-write*)
(allow file-write* (literal "/dev/null"))
(allow file-write* (subpath "<root>") (subpath "<tmp>"))
```

Every root is canonicalized first: Seatbelt matches resolved paths, so `/tmp` renders as `/private/tmp` and symlinked ancestors resolve. Launch is `sandbox-exec -p <profile> -- <command>`. A missing `sandbox-exec` fails the probe and the backend reports unavailable. The App Sandbox entitlement path is rejected because it needs a signed bundle and Xcode packaging for a CLI tool.

Windows uses raw restricted tokens, not AppContainer. The child token derives from `CreateRestrictedToken` with `WRITE_RESTRICTED`, `DISABLE_MAX_PRIVILEGE`, and `LUA_TOKEN`, with distinct workspace and private-temp capability SIDs. The token intersects writes only, so reads keep ambient access. AppContainer is rejected because its token carries no ambient reads: every readable path would need pre-granting, which means wholesale host DACL mutation for an agent that reads toolchains across the disk. One standing workspace ACE per workspace plus a random private temp directory with a revocable ACE per live session pair keeps sessions from inheriting each other temp authority. The Low integrity layer applies, and ambient deletes are denied through the parent `FILE_DELETE_CHILD` right. Partial is always reported: hard-link aliasing, unconfined reads, and trees ACLed by other tools.

## Security analysis

Threat model: the agent is untrusted code holding decoys only. Real secrets live in arkham processes. Host data outside the profile stays unreadable where the backend allows (bwrap hides, Seatbelt and Windows deny) and unwritable everywhere. Workspaces cannot reach each other secrets or writable roots.

Per-backend gaps: bwrap leaves kernel exploits and abstract-socket or D-Bus peers outside the mount view, covered by the denylist (`--unshare-ipc`, minimal env, no host socket binds). Landlock leaves older ABIs partial. Seatbelt leaves reads visible, depends on deprecated `sandbox-exec`, and overbroad network denies break unix-socket IPC. Windows tokens leave reads unconfined with hard-link aliasing, partial by construction. Capture leaves pinned or embedded-trust flows bypassed, which carries decoys only.

## Work areas

Policy and scaffold: policy types plus the shared writable-roots helper in `arkham-config`, one `Error` variant for unavailable confinement, the probe harness running `true` under a `read-only` profile, port claim records, and the `--isolate bwrap|compose` switch with compose default.

Linux: bwrap argv renderer from stack inputs, Landlock chain with partial reporting, eBPF per-workspace cgroup capture, sidecar lifecycle in `AgentArgs`.

macOS: Seatbelt renderer with canonicalization, host controller plus sysext packaging from the rama example layout, both signing tracks, CA lifecycle, `NENetworkRule` selection, attribution mapping, unified logging.

Windows: restricted-token renderer with ACE lifecycle, callout driver (minimal, redirect plus tagging), filter set, installer with service and BFE wiring, redirect-context decoder, verification and debug docs.

Proxy: per-workspace sidecars with claim records. Multi-listener single process is the recorded alternative.

Verification throughout: e2e per backend proving outside-root writes fail in the backend denial dialect, reads fail where the backend governs them, decoys substitute through transparent capture with no proxy env set on the agent, host `/tmp` stays untouched under bwrap, and unknown-source flows splice. Run `mise run format` and `mise run --force test` for Rust changes.

## Open questions

- macOS identity for supervisor-spawned CLI agents: the bridge delivers bundle identifier, audit token, and PID when set, but which of those a `sandbox-exec` child actually presents is unverified. Spike against the rama example: spawn a CLI child, read its flow metadata, confirm one stable key. Fallbacks if none is stable: distinct signed helper executables per workspace, or UID-keyed correlation.
- Windows driver signing path for production (attestation versus EV) and the installer shape. Test signing covers development.
- Windows redirect-context schema and its versioning between driver and arkham releases. The driver writes it, arkham decodes it, so both sides stay in this repo.
- Port range defaults and claim file format. Proposed `18080-19999` and TOML.
- Proxy-only fallback on systems with no usable runner: refuse by default, allow behind an explicit flag. Flag spelling undecided.
- PROXY header version on the macOS loopback handoff. Proposed v1 text format for TCP v4 and v6; v2 only if a TLV need appears.
- Whether `danger-full-access` needs an approval record beyond the existing escalation vocabulary. Proposed shape resolves it per call without calling the backend.

## References

- Current stack: `crates/arkham-compose/src/stack.rs` (`generate_stack:461`, `Stack:1347`, `EXPLICIT_LISTEN:266`), `crates/arkham-compose/src/confine.rs` (`AgentArgs:785`).
- Proxy: `crates/arkham-proxy/src/lib.rs` (`ProxyState:63`, `ExplicitService:239`), `crates/arkham-config/src/grants.rs` (`ResolvedConfig:652`), `crates/arkham-config/src/config.rs` (`fake_for:832`, `ProxyCfg.listen:278`).
- Linux capture: `crates/arkham-tproxy/src` (`nft.rs`, `route.rs`, `tproxy.rs`, `error.rs`), `crates/arkham-ebpf` plus `crates/arkham-ebpf-programs`.
- Rama: `rama-net/src/socket/opts.rs` (`ip_transparent`), `rama-net/src/socket/linux/tproxy.rs`, `rama-net/src/socket/windows/tproxy.rs`, `rama-net-apple-networkextension` plus `ffi/apple/examples/transparent_proxy`, `docs/book/src/proxies/operate/transparent/windows.md`, `docs/book/src/proxies/operate/transparent/macos.md`.
- Chromium: `sandbox/mac/seatbelt.cc`, `docs/design/sandbox.md` (Windows token plus job plus desktop plus integrity).
