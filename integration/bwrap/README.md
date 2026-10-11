# bwrap demo (transparent capture without docker)

Same proof as the [docker demo](../README.md), minus the docker daemon: a
network namespace with a veth up to the host, `arkham serve --proxy-backend tproxy`
capturing inside it, and the client sandboxed by [bubblewrap] while
sharing the netns — proxy-unaware, fake-token-holding, captured on the way
out. Set `ARKHAM_BACKEND=ebpf` to run the same scenarios over the eBPF
backend instead.

[bubblewrap]: https://github.com/containers/bubblewrap

| # | Client (under bwrap) | Grant | Passes when |
|---|----------------------|-------|-------------|
| 1 | HTTPS GET `api:8443` with the fake bearer | `https://api:8443` | response body is `token:<fake>`; api log saw the real bearer only |
| 2 | Cleartext line protocol to `10.99.0.20:9000` | `tcp://10.99.0.20:9000` | `AUTH <fake>` became `AUTH real` upstream, reply is `OK <fake>` |

The api server is the docker demo's `integration/api/server.ts`; the CA and
api leaf come from `integration/gen-certs.sh`; the fake is the deterministic
`arkham fake GH_TOKEN`. arkham installs its own nft TPROXY rules and policy
routes inside the namespace over netlink — the host only carries a small
masquerade table for the veth, removed on exit.

## Run

```sh
mise run demo:bwrap
```

The task builds the release binary as you and escalates only the demo
script (netns, veth, host NAT) via sudo, with a confirmation prompt;
`--use-sudo` skips the prompt.

To assert the same scenarios over the eBPF backend:

```sh
ARKHAM_BACKEND=ebpf mise run demo:bwrap
```

That needs a cgroup v2 hierarchy. The
script creates `/sys/fs/cgroup/arkham-bwrap`, starts arkham outside it, and
migrates the client into it before the client runs — no nft rules are
installed for the capture, only the veth masquerade table.

Requirements: sudo (for the netns, veth, and host NAT), `iproute2`, `nft`, `openssl`, `bun`, `curl`, `bwrap`.
Everything (netns, veth, host NAT table, temp certs, the eBPF cgroup) is cleaned up on exit.
