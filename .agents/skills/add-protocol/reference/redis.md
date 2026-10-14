# Redis

Worked example of a connection-string protocol. `PROTO` is `redis`. The variants are `Redis` and `Rediss`.

## Where it lives

- Transport: `crates/arkham-proxy/src/transports/redis/` (`RedisTransport::serve`, `machine.rs` for `AUTH` and `HELLO`).
- Registered on `ProxyState` as `redis: Arc<RedisTransport>` and routed by `Expect::Redis` in `crates/arkham-proxy/src/identity.rs`.
- `Scheme::Redis` / `Scheme::Rediss`, `as_str` arms `"redis"` / `"rediss"`, and `Scheme::all` via `EnumIter`. A URL with no port uses 6379 for both.
- `GrantCollector::connection_string` dispatches both schemes to `grants/redis.rs`. `[rules.redis_plain]` and `[rules.redis_tls]` in `integration/arkham.toml` set `value` and no `allow`.
- `expect` tries Postgres, then Redis, then SSH. `PartialEq` for `Expect::Redis` compares the scope by pointer.
- `[providers.redis-cloud]` is the Redis Cloud HTTPS API, not RESP. RESP did not add a wire-host provider.
- Capture crates do not mention 6379 or 6380. UDP/443 stays the QUIC exception.
- Compose runs `image: redis:7-alpine`. The client is Bun's `RedisClient`. `retry` records `"redis"` or `"rediss"` from the scenario kind.

## Rules this protocol ran into

An undeclared secret makes arkham exit at boot. `integration/gen-secrets.sh` requires `ARKHAM_REDIS_REAL` and `ARKHAM_REDIS_TLS_REAL`, `integration/.env.example` defines them, and `integration/compose.yaml` passes them with `${VAR:?}`.

Key the swap and the TLS leaf on the scope host, not the captured address. Transparent capture knows a destination and a port. Bun's client sends no SNI. `RedisTransport::serve` uses `scope.downstream.host` for both the mint and `PairCtx.host`.

A CA file on the server can make it demand a client certificate. `sslcert` and `sslkey` on the real `rediss://` string fill `RedisScope::client_cert`, and `connect_server` presents that pair. This demo authenticates with passwords, so the server is started with `tls-auth-clients no`.
