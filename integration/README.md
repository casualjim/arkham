# Integration demo (transparent capture)

Runs the real container image (runtime-only `Dockerfile`, prebuilt
binary) in the deployment shape arkham exists for: the
client container shares arkham's network namespace and knows nothing about
any proxy. arkham runs `serve --proxy-backend tproxy` and installs its nft rules and
policy routing inside the shared netns, so every client connection is
captured on the way out.

This demo pins `tproxy` because the eBPF backend captures by cgroup
membership, and a compose service's cgroup path is not something the demo
can fix. For the same scenarios over eBPF, run the docker-free
[bwrap demo](bwrap/README.md) with `ARKHAM_BACKEND=ebpf`.

Topology:

- `client` — `network_mode: service:arkham`; talks to `api` by plain
  hostname:port. Holds only the deterministic fake (`arkham fake GH_TOKEN`).
- `arkham` — legs on the default bridge and the `server` network;
  `cap_add: NET_ADMIN` for the TPROXY listener, nft rules, and policy
  routes (all self-installed over netlink — the runtime image ships no
  `nft`/`ip`). Marked upstream dials bypass capture (fwmark rule).
- `api` — bun server on `server` only, static IP `10.202.0.20`,
  validates only the real token.
- `db` — real PostgreSQL 17 (Alpine) on `server` only, static IP
  `10.202.0.30`, TLS with a demo-CA leaf, validates only the real password.
- `server` subnet is RFC1918 on purpose: arkham captures LAN traffic too
  (the capture routes are default-route-only), and this demo proves it.

| # | Client does | Grant | Passes when |
| --- | ------------- | ------- | ------------- |
| 1 | HTTPS GET `api:8443` with the fake bearer | `https://api:8443` | server saw the real bearer, response body redacted back to the fake |
| 2 | Cleartext HTTP GET `api:8000` with the fake bearer | `http://api:8000` | same as 1 through transparent plain-HTTP capture (Host header identity) |
| 3 | Cleartext line protocol to `api:9000` | `tcp://10.202.0.20:9000` | `AUTH fake` became `AUTH real`, `OK real` came back as `OK fake` |
| 4 | TLS line protocol to `api:9443` | `https://api:9443` | same as 3 through terminated TLS legs |
| 5 | TLS line protocol to `api:9444` | none | tunnel splices untouched: fake arrives as-is, server rejects |
| 6 | Postgres wire protocol driven by the client's own `DATABASE_URL` (the rule's stated fake string): SSLRequest, TLS, cleartext password auth, `SELECT` | `[rules.db]`: `env = "DATABASE_URL"`, `value` the fake URL; the real URL in fnox | the fake password authenticates against real PostgreSQL — arkham swapped the real one in from the secret source — and the query row comes back |
| 7 | OAuth2 `client_credentials` POST `api:8000/token` with the fake client secret, then GET with the minted token | `[rules.oidc]` + `oauth2` block | issuer saw the real client secret, the client received a minted decoy access token (never the real one), and the decoy swapped back to the real access token on the API call |
| 8 | OpenSSH client with the decoy identity to `10.202.0.40` | `[rules.ssh]` `ssh://10.202.0.40:22` | `echo ssh-ok`, and `known_hosts` records arkham's host key |
| 9 | Redis RESP via Bun's `RedisClient` to `redis:6379`: requirepass, ACL user, `HELLO 3 AUTH`, a pipeline, and `WRONGPASS` | `[rules.redis_plain]`: fake `redis://` URL; real URL rendered into fnox by `gen-secrets.sh` | official Redis accepts the swapped password; the real password is absent from the client error |
| 10 | Same client to `redis:6380` over TLS. Bun sends no SNI | `[rules.redis_tls]`: fake `rediss://` URL; real URL carries `sslrootcert` | same swap. The guest leaf is minted for the scope host. Redis is started with `tls-auth-clients no` |

Scenario 3's grant host is the literal destination IP because raw TCP
capture has no SNI — the destination address is the identity
(`crates/arkham-tproxy/src/tproxy.rs` `tproxy_conn_task`). Scenario 5 is the fail-closed control: without a grant
arkham splices TLS byte-identical, so no secret can leak and the server
refuses the fake.
Scenario 6's entry is a real
libpq URL naming the host (`db`); a transparently captured connection
carries no hostname arkham can key on (libpq sent no SNI before PostgreSQL
17), so the transparent path shortlists by port alone — any captured
connection to :5432 resolves to the entry, whatever address DNS resolved.
Both connection strings name the host the way real deployments do —
the `db` hostname, never an IP. The client keeps full TLS hostname
verification on: it dials by that name, and arkham mints the guest leaf
for it. The bwrap demo has
no postgres and no `DATABASE_URL`, so scenario 6 is skipped there.
Scenario 7 exercises runtime token minting
(`crates/arkham-proxy/src/mint.rs`): the client secret is a static
substitution (`arkham fake OIDC_CLIENT_SECRET`, pinned in
`compose.yaml`), and the access token is minted per issue, so no real
access token ever reaches the client container.
Scenarios 9 and 10 are the official `redis:7-alpine` image and Bun's
`RedisClient`. The proxy is the only code we wrote on that path. A
`tls-ca-cert-file` makes Redis require a client certificate; this demo
authenticates with passwords and the upstream client has no certificate,
so the server is started with `tls-auth-clients no`. The bwrap demo has
no Redis and no `REDIS_URL`, so those scenarios are skipped there.

## Run

```sh
mise run demo
```

First run only: the demo's real values resolve from fnox at serve time, so
no committed rule file carries a `value`. `gen-secrets.sh` renders the
arkham container's fnox config from the environment:

```sh
cp integration/.env.example integration/.env   # gitignored; adjust freely
```



The task builds the release binary, packs it into
the runtime image via the repo `Dockerfile`, and runs
`docker compose up --abort-on-container-exit --exit-code-from client`.
Client exit code 0 means every scenario passed.

Recomputing the fake after changing `env` in `arkham.toml`:

```sh
mise run build -- --release
target/release/arkham fake GH_TOKEN
```

Update the value in `compose.yaml` (`client.environment.ARKHAM_FAKE`) to match.
