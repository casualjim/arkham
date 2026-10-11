// Demo client. Shares arkham's network namespace; arkham's transparent capture
// takes every connection. The client knows nothing about the proxy:
// it just talks to api by hostname. It holds ONLY the fake token; every
// passing scenario proves arkham swapped it for the real one (and redacted
// replies). Hard bounds everywhere: 5s per network await, 20s per scenario,
// 90s for the whole run — the demo never sits silent.
import { connect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { readFile } from "node:fs/promises";

const FAKE = process.env.ARKHAM_FAKE ?? "";
const OIDC_FAKE_SECRET = process.env.OIDC_FAKE_SECRET ?? "";
const CERT_DIR = process.env.CERT_DIR ?? "/certs";
const PG_URL = process.env.DATABASE_URL ?? ""; // the fake connection string
const ATTEMPT_TIMEOUT_MS = 5000;
const SCENARIO_BUDGET_MS = 20000;
const TOTAL_BUDGET_MS = 90000;
const DEADLINE = Date.now() + TOTAL_BUDGET_MS;

if (!FAKE || !OIDC_FAKE_SECRET) {
  console.error("ARKHAM_FAKE or OIDC_FAKE_SECRET not set");
  process.exit(1);
}

function outOfTime() {
  return Date.now() > DEADLINE;
}

function race<T>(what: string, p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`${what}: timed out after ${ATTEMPT_TIMEOUT_MS}ms`)), ATTEMPT_TIMEOUT_MS).unref?.();
    }),
  ]);
}

function stage(what: string) {
  process.stderr.write(`[${new Date().toISOString().slice(17, 23)}] ${what}\n`);
}

async function tlsTo(host: string, port: number, ca: Buffer): Promise<TLSSocket> {
  stage(`tls ${host}:${port} connecting`);
  const tls = tlsConnect({ host, port, servername: host, ca, rejectUnauthorized: true });
  await race(`tls ${host}:${port} handshake`, new Promise<void>((resolve, reject) => {
    tls.once("secureConnect", () => resolve());
    tls.once("error", reject);
  }));
  stage(`tls ${host}:${port} handshake ok`);
  return tls;
}

function exchange(sock: Socket | TLSSocket, payload: string): Promise<string> {
  return race("line reply", new Promise<string>((resolve, reject) => {
    let buf = "";
    const onData = (c: Buffer) => {
      buf += c.toString();
      if (buf.includes("\n")) {
        sock.off("data", onData);
        sock.destroy();
        resolve(buf);
      }
    };
    sock.once("error", reject);
    sock.on("data", onData);
    sock.write(payload);
  }));
}

async function readAll(sock: Socket | TLSSocket): Promise<string> {
  return race("http reply", new Promise<string>((resolve, reject) => {
    let buf = "";
    sock.on("data", (c: Buffer) => {
      buf += c.toString();
    });
    sock.once("end", () => resolve(buf));
    sock.once("error", reject);
  }));
}

async function retry(what: string, fn: () => Promise<boolean>) {
  const deadline = Date.now() + SCENARIO_BUDGET_MS;
  let last = "no attempt completed";
  for (let attempt = 1; attempt <= 100; attempt++) {
    if (Date.now() > deadline || outOfTime()) {
      console.error(`FAIL ${what}: ${last}`);
      process.exit(1);
    }
    try {
      stage(`${what} attempt ${attempt}`);
      if (await fn()) {
        console.log(`PASS ${what}`);
        return;
      }
      last = "assertion false";
    } catch (err) {
      last = String(err);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  console.error(`FAIL ${what}: ${last}`);
  process.exit(1);
}

const ca = await readFile(`${CERT_DIR}/ca.crt`);

// 1. https:// grant, HTTP over MITM TLS: server must see the real bearer;
//    the redacted body comes back carrying the fake.
await retry("https mitm substitutes request and redacts response", async () => {
  const tls = await tlsTo("api", 8443, ca);
  stage("http request sent");
  tls.write(`GET /echo HTTP/1.1\r\nHost: api\r\nAuthorization: Bearer ${FAKE}\r\nConnection: close\r\n\r\n`);
  const resp = await readAll(tls);
  tls.destroy();
  const status = resp.split("\r\n", 1)[0];
  const body = resp.split("\r\n\r\n", 2)[1] ?? "";
  stage(`http reply: ${JSON.stringify({ status, body })}`);
  return status === "HTTP/1.1 200 OK" && body === `token:${FAKE}\n`;
});

// 2. http:// grant, cleartext HTTP through transparent capture: server must
//    see the real bearer; the redacted body comes back carrying the fake.
await retry("http mitm substitutes request and redacts response", async () => {
  stage("http api:8000 connecting");
  const sock = await race("http api:8000 connect", new Promise<Socket>((resolve, reject) => {
    const s = connect(8000, "api");
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  }));
  sock.write(`GET /echo HTTP/1.1\r\nHost: api\r\nAuthorization: Bearer ${FAKE}\r\nConnection: close\r\n\r\n`);
  const resp = await readAll(sock);
  sock.destroy();
  const status = resp.split("\r\n", 1)[0];
  const body = resp.split("\r\n\r\n", 2)[1] ?? "";
  stage(`http reply: ${JSON.stringify({ status, body })}`);
  return status === "HTTP/1.1 200 OK" && body === `token:${FAKE}\n`;
});

// 3. tcp:// grant, cleartext raw stream: opaque substitution both ways.
await retry("tcp raw substitutes both directions", async () => {
  stage("tcp api:9000 connecting");
  const sock = await race("tcp api:9000 connect", new Promise<Socket>((resolve, reject) => {
    const s = connect(9000, "api");
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  }));
  stage("tcp api:9000 connected");
  return (await exchange(sock, `AUTH ${FAKE}\n`)) === `OK ${FAKE}\n`;
});

// 4. https:// grant, non-HTTP payload inside MITM TLS: raw machines on the
//    terminated legs.
await retry("tcp over tls mitm substitutes both directions", async () => {
  const tls = await tlsTo("api", 9443, ca);
  return (await exchange(tls, `AUTH ${FAKE}\n`)) === `OK ${FAKE}\n`;
});

// 5. No grant: arkham never terminates the TLS, the handshake passes through
//    to the api server (its own CA-signed leaf verifies), and the fake
//    arrives untouched, so the server rejects it.
await retry("grantless tls splices untouched", async () => {
  const tls = await tlsTo("api", 9444, ca);
  return (await exchange(tls, `AUTH ${FAKE}\n`)) === `ERR ${FAKE}\n`;
});

// 6. Database rule against real PostgreSQL (the compose demo only — bwrap
//    has no postgres, so no DATABASE_URL means the scenario is skipped).
//    The client consumes exactly what the guest holds: its DATABASE_URL,
//    the rule's stated FAKE connection string. Arkham captures the dial,
//    matches the rule on the fake string's port, and swaps the fake
//    password for the real one from the secret source. PostgreSQL rejects
//    the fake password, so an opened session proves the swap. The guest
//    dials by the URL's hostname, and arkham mints the leaf for that name,
//    so full hostname verification stays on — no IPs anywhere.
if (PG_URL) {

  function pgFrame(type: number, body: Buffer): Buffer {
    const len = Buffer.alloc(4);
    len.writeInt32BE(body.length + 4);
    return Buffer.concat([Buffer.from([type]), len, body]);
  }
  function pgStartup(params: Record<string, string>): Buffer {
    const body = Buffer.concat([
      Buffer.from([0, 3, 0, 0]),
      ...Object.entries(params).map(([key, value]) => Buffer.from(`${key}\0${value}\0`, "utf8")),
      Buffer.from([0]),
    ]);
    const len = Buffer.alloc(4);
    len.writeInt32BE(body.length + 4);
    return Buffer.concat([len, body]);
  }
  function pgRead(sock: Socket | TLSSocket, n: number): Promise<Buffer> {
    return race("pg read", new Promise<Buffer>((resolve, reject) => {
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length >= n) {
          sock.off("data", onData);
          resolve(buf.subarray(0, n));
        }
      };
      sock.on("data", onData);
      sock.once("error", reject);
    }));
  }
  await retry("postgres mitm swaps the password for a real server", async () => {
    const db = new URL(PG_URL);
    stage(`pg ${db.hostname}:${db.port || 5432} connecting`);
    const sock = await race("pg connect", new Promise<Socket>((resolve, reject) => {
      const s = connect(Number(db.port || 5432), db.hostname);
      s.once("connect", () => resolve(s));
      s.once("error", reject);
    }));
    stage("pg sslRequest");
    sock.write(Buffer.from([0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f]));
    const answer = (await pgRead(sock, 1)).toString("latin1");
    if (answer !== "S") throw new Error(`server refused TLS: ${answer}`);
    const tls = tlsConnect({ socket: sock, servername: db.hostname, ca, rejectUnauthorized: true });
    await race("pg tls handshake", new Promise<void>((resolve, reject) => {
      tls.once("secureConnect", () => resolve());
      tls.once("error", reject);
    }));
    stage("pg tls ok (arkham's minted leaf)");
    tls.write(pgStartup({ user: db.username, database: db.pathname.slice(1) }));
    const auth = await pgRead(tls, 9);
    if (auth[0] !== 0x52 || auth.readUInt32BE(5) !== 3) throw new Error(`expected cleartext password auth, got ${auth.toString("latin1")}`);
    stage("pg cleartext auth requested");
    tls.write(pgFrame(0x70, Buffer.from(`${db.password}\0`, "utf8")));
    const ok = await pgRead(tls, 9);
    if (ok[0] !== 0x52 || ok.readUInt32BE(5) !== 0) throw new Error(`auth rejected: ${ok.toString("latin1")}`);
    stage("pg authenticated - the fake was swapped for the real");
    tls.write(pgFrame(0x51, Buffer.from("SELECT 'ok'\0", "utf8")));
    const result = await race("pg query reply", new Promise<Buffer>((resolve, reject) => {
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.includes(0x5a)) {
          tls.off("data", onData);
          resolve(buf);
        }
      };
      tls.on("data", onData);
      tls.once("error", reject);
    }));
    tls.destroy();
    sock.destroy();
    stage("pg query ok");
    return result.includes(Buffer.from("ok"));
  });
} else {
  stage("pg scenario skipped: no DATABASE_URL (bwrap)");
}

// 7. OAuth2 client_credentials through the token issuer: the fake client
//    secret is swapped to the real one at /token, the returned access token
//    is minted as a decoy (never the real value), and that decoy swaps back
//    to the real access token on the API call. Garbage tokens stay
//    unauthorized.
await retry("oauth2 token endpoint mints and the minted decoy substitutes", async () => {
  const basic = Buffer.from(`demo-client:${OIDC_FAKE_SECRET}`).toString("base64");
  const tokenResp = await fetch("http://api:8000/token", {
    method: "POST",
    headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  if (tokenResp.status !== 200) {
    stage(`token endpoint status ${tokenResp.status}`);
    return false;
  }
  const { access_token: minted, token_type: tokenType } = (await tokenResp.json()) as { access_token: string; token_type: string };
  stage(`minted token head: ${minted.slice(0, 8)}…`);
  // The minted decoy renders the default {hex:32} pattern; the real access
  // token does not. A regex shape check proves minting fired without the
  // client ever learning the real value.
  if (!/^[0-9a-f]{32}$/.test(minted) || tokenType !== "Bearer" || minted === OIDC_FAKE_SECRET) {
    return false;
  }
  const apiResp = await fetch("http://api:8000/api", { headers: { authorization: `Bearer ${minted}` } });
  if (apiResp.status !== 200 || (await apiResp.text()) !== "ok\n") {
    return false;
  }
  const badResp = await fetch("http://api:8000/api", { headers: { authorization: "Bearer not-a-token" } });
  return badResp.status === 401;
});

// 8. SSH: a plain openssh binary, the decoy identity, and nothing else.
// Options inline (no config file): strict checking with accept-new and a
// writable known_hosts of its own, so the first connection records arkham's
// host key — ssh's mechanism is the allowlist, arkham adds no pins.
const SSH_DST = process.env.SSH_DST ?? "";
const SSH_KNOWN_HOSTS = "/tmp/known_hosts";
const sshCommand = [
  "ssh",
  "-i",
  "/certs/ssh/decoy",
  "-o",
  "IdentitiesOnly=yes",
  "-o",
  "StrictHostKeyChecking=accept-new",
  "-o",
  `UserKnownHostsFile=${SSH_KNOWN_HOSTS}`,
  "-o",
  "GlobalKnownHostsFile=/dev/null",
  "-o",
  "BatchMode=yes",
  "-o",
  "ConnectTimeout=5",
  `agent@${SSH_DST}`,
  "echo",
  "ssh-ok",
];
if (SSH_DST) {
  await retry("ssh decoy in, real key out", async () => {
    const proc = Bun.spawn(sshCommand, { stdout: "pipe", stderr: "pipe" });
    const out = await new Response(proc.stdout).text();
    const err = await new Response(proc.stderr).text();
    const code = await proc.exited;
    stage(`ssh reply: ${JSON.stringify({ code, out, err })}`);
    if (code !== 0 || out.trim() !== "ssh-ok") {
      return false;
    }
    // Debian hashes known_hosts entries, so assert on the recorded key
    // blob: it must be arkham's host key, proving the client verified and
    // stored it via its own accept-new — never a pre-mounted pin.
    const [known, arkhamHost] = await Promise.all([
      readFile(SSH_KNOWN_HOSTS, "utf8"),
      readFile("/certs/ssh/arkham_host.pub", "utf8"),
    ]);
    return known.includes(arkhamHost.trim().split(" ")[1] ?? "");
  });
} else {
  stage("ssh scenario skipped: no SSH_DST (bwrap)");
}

console.log("all scenarios passed");
process.exit(0);
