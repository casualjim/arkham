# How to capture traffic transparently

This guide shows you how to make arkham capture a workload's connections without the workload knowing anything about a proxy. You need arkham on Linux, root, and a workload whose network namespace arkham shares or controls.

Explicit-proxy mode (point `HTTPS_PROXY` at arkham) needs none of this. Reach for transparent capture when you cannot or will not configure the client, or when the client must not be able to bypass the proxy.

Transparent capture comes in three backends, chosen with `--proxy-backend`. `tproxy` is the kernel path: nftables rules and policy routes hand TCP to an `IP_TRANSPARENT` listener, and UDP passes through untouched except for the QUIC drop. `tun` is the userspace path: arkham opens a TUN device and runs its own TCP/IP stack, so it relays UDP itself (DNS to the system resolver, QUIC dropped), and it needs root. `ebpf` is the netfilter-free kernel path: cgroup socket hooks rewrite destinations to arkham's loopback listeners, needing a cgroup for the workload. They are peers, not a migration path — pick by mechanism, not by age.

## 1. Start arkham with a capture backend

```sh
sudo arkham serve --proxy-backend tproxy --config arkham.toml
```

Or, over the userspace stack:

```sh
sudo arkham serve --proxy-backend tun --config arkham.toml
```

Or, naming the cgroup the workload will be placed in:

```sh
sudo mkdir -p /sys/fs/cgroup/arkham
sudo arkham serve --proxy-backend ebpf --ebpf-cgroup /sys/fs/cgroup/arkham --config arkham.toml
```

`tproxy` and `tun` install what they need themselves, over netlink: `tproxy` an `IP_TRANSPARENT` listener plus nftables rules and policy routes, `tun` the device plus policy routes. No `nft` or `ip` binary is required. Either captures every outbound TCP connection in the network namespace, LAN destinations included.

`ebpf` is different in two ways that matter operationally. It touches no netfilter and no routing table: the programs are attached to a cgroup, and arkham loads them itself. And it captures by *cgroup membership*, not by namespace, so the workload has to be moved into `--ebpf-cgroup` — and arkham must stay outside it, or its own upstream dials would be redirected back into it. `--ebpf-cgroup enclosing` is the exception: it attaches to the cgroup arkham's own cgroup lives under, for a runtime that places both arkham and its workload in one parent cgroup (a compose stack, say, where the parent's filesystem path depends on where the daemon sits). arkham is a member of the attached cgroup then, and the proxy PID recorded in the programs is what keeps its own sockets out.

```sh
echo $$ | sudo tee /sys/fs/cgroup/arkham/cgroup.procs
```

`ARKHAM_PROXY_BACKEND`, plus `ARKHAM_EBPF_CGROUP` for the cgroup path, are the environment equivalents.

Destinations the loader's netns cannot reach must not be captured: `connect4` would fake a handshake and then hang until the dial budget runs out. The loader always bypasses its own non-loopback addresses, and `--ebpf-bypass` (`ARKHAM_EBPF_BYPASS`, repeat or comma-separate) bypasses more. Bypassed dials fail or succeed on their own routing instead of transiting the proxy.

Podman networks need a runtime channel: they are created inside the agent long after arkham starts, so no startup flag can name them. The generated stack mounts a shared bypass file into both services (`ARKHAM_EBPF_BYPASS_FILE`, or `--ebpf-bypass-file` by hand): the agent entrypoint rewrites it from `podman network inspect`, and arkham reloads it live within seconds, no restart. One CIDR per line, `#` comments allowed.

## 2. Understand the safety guard

With `--proxy-backend tproxy`, arkham refuses unscoped capture rules when it runs in the host network namespace itself. The rules reroute every outbound TCP packet, and an unclean exit would leave the machine without TCP egress until the rules are cleaned up by hand.

Two accepted shapes:

- Run arkham in its own network namespace (a container with `cap_add: NET_ADMIN`), and share that namespace with the workload. This is what a secured workspace (`arkham init` then `arkham up`) and the integration demo do.
- Acknowledge the risk on a disposable machine with `--tproxy-allow-root-netns` or `ARKHAM_TPROXY_ALLOW_ROOT_NETNS=1`.

`tun` has no such guard: the policy routes it installs name the TUN device, and the teardown guard removes them on exit.

## 3. Grant raw TCP by destination address

A captured TLS connection is identified by SNI, so HTTPS grants work as usual:

```toml
allow = ["https://api.anthropic.com"]
```

A raw TCP connection has no SNI. The destination address is the only identity, so a `tcp://` grant must name the literal address the workload dials:

```toml
allow = ["tcp://10.202.0.20:9000"]
```

A `tcp://` entry requires an explicit port. Plain HTTP capture identifies the connection by its `Host` header, so `http://api.internal:8000` grants cleartext HTTP with no address guessing.

## 4. Know what passes through

With `--proxy-backend tproxy`:

- DNS and other UDP pass through unintercepted.
- QUIC on port 443 is dropped by nft rule, so HTTP/3 clients fall back to TCP and get captured. QUIC to other ports passes through.

With `--proxy-backend tun`, the UDP path runs inside arkham instead: DNS is relayed to the system resolver, QUIC on port 443 is dropped, and any other UDP flow is relayed to its original destination.

With `--proxy-backend ebpf`, only *connected* UDP is captured — a socket that called `connect()`, which is what every HTTP/3 stack does. Those datagrams are relayed unchanged, with no substitution, so a captured QUIC flow reaches the real server with its decoy intact and an authenticated request over it will fail. Unconnected `sendto` traffic, typical DNS included, is never captured and passes through untouched.

Either way, connections with no matching grant are spliced byte for byte. The client sees the real upstream certificate and the decoy travels untouched, so nothing on your network breaks.

## 5. Tear down

Ctrl-C is the normal stop; arkham handles SIGINT at process level, drops the capture task, and the teardown guard removes the nft rules and policy routes. If the process was killed outright before it could clean up, the policy rules remain — under `tproxy` that means no TCP egress until they are removed by hand (the failure mode the root-netns guard exists to prevent), and under `tun` a stale capture-table default route blackholes egress. Reboot or remove them.

`ebpf` has no such residue. The programs and their maps belong to the loading process, so exit detaches them: nothing is written to netfilter, to a routing table, or under `/sys/fs/bpf`. Verify both directions with `bpftool prog list`: the three `arkham-ebpf-programs` entries are attached while arkham runs and gone once it exits.

## Check it works

The runnable proof is the integration demo in the repository:

```sh
git clone https://github.com/casualjim/arkham
cd arkham
mise run demo
```

It runs the container image, a client sharing arkham's netns, and an upstream on an RFC1918 subnet, and it asserts four substitution scenarios and one splice scenario. See [integration/README.md](../../../integration/README.md) for the scenario table.

The same scenarios run without docker over the eBPF backend:

```sh
ARKHAM_BACKEND=ebpf mise run demo:bwrap
```
