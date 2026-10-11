# How to extend the known-host registry

This guide shows you how to teach arkham about a private API endpoint, a self-hosted control plane, or a token shape it does not know. You need the env var name, the host that may receive the real value, and roughly what the token looks like.

arkham ships a bundled table mapping known services to their env names, API hosts, and token shapes, so most rules need nothing beyond `env`. When a name is not in the table, or the table is wrong for your deployment, override it with a `rules.d` file rather than repeating `allow` in every rule.

## 1. Pick the file location

Two override directories, both loaded in filename order:

- Global: `<config-dir>/arkham/rules.d/*.toml`, beside the global config file. Applies to every workspace.
- Project: `<workspace-root>/.config/arkham/rules.d/*.toml`. Applies to one workspace.

Project entries override global ones, which override the bundled table.

## 2. Add a provider entry

```toml
# <config-dir>/arkham/rules.d/acme.toml
[providers.acme]
env = ["ACME_API_KEY"]
hosts = ["https://api.acme.example.com"]
pattern = "acme_{hex:32}"
```

| Field | Meaning |
| --- | --- |
| `env` | Env var names this provider owns. |
| `hosts` | `scheme://host[:port]` allow entries granted to every listed name. A per-tenant endpoint uses a `*.`-suffix host family. |
| `pattern` | Decoy shape for these names. |
| `contains` | Substrings matched against lowercased env names to select a decoy shape only, never hosts. |
| `replace` | `true` discards what earlier layers declared for these names, then applies this entry's fields. |

A rule referencing the name now inherits the hosts and the shape:

```toml
[rules.acme]
env = "ACME_API_KEY"
```

## 3. Or add a name-only entry

When only the hosts need overriding, a names entry is the smaller change:

```toml
[names.GH_ENTERPRISE_TOKEN]
hosts = ["https://ghe.corp.example"]
```

## 4. Declare an OAuth2 token issuer

When the service issues its own tokens (an OAuth2 token endpoint instead of one static key), declare the flow so freshly issued tokens never reach the agent as real values.

The two curation commands turn a vendor's own documents into the entry:

```sh
# OIDC discovery: fetch and save the document, then map it
arkham registry from-oidc issuer.json example EXAMPLE_TOKEN

# OpenAPI: map every `type: oauth2` security scheme
arkham registry from-openapi openapi.json example EXAMPLE_TOKEN
```

Both print a `rules.d` TOML fragment to stdout. Review it, then drop it into `rules.d`. They never fetch at runtime and never touch the bundled table.

For hand-written entries, the block is:

```toml
[providers.acme]
env = ["ACME_TOKEN"]
hosts = ["https://api.acme.example.com"]

[providers.acme.oauth2]
flow = "client_credentials"
token_url = "https://auth.acme.example.com/oauth/token"
```

With the flow declared, the proxy terminates TLS on the token endpoint and rewrites the response body: every `access_token` the issuer returns is replaced with a freshly minted decoy matching the rule's pattern. The agent holds the decoy; the proxy swaps it back on every later request. `expires_in` is logged at mint time; values are never logged.

## 5. Preview the decoy

`arkham fake` uses the same table, so the override is visible without running a proxy:

```sh
arkham fake ACME_API_KEY
# acme_1f4a9c...  (matches the pattern above)
```

## How conflicts resolve

Within one registry file, the pattern lookup order is an explicit `pattern` in the rule, then `[names.<ENV>]`, then a `[providers.*]` entry claiming the env name, then `contains`, then the default `{hex:32}`.

Across files, a later load's pattern overrides an earlier one regardless of tier, because the bundled table loads first and `rules.d` files load in filename order. The one exception is `contains`: matches are tried in load order, so the earliest-loaded file wins, and within one file the first provider name in sort order wins. A `contains` needle from a bundled provider therefore beats a `rules.d` needle under a different provider name. Set `replace = true` on your provider entry to discard its earlier `contains` needles first.

See [the registry reference](../reference/registry.md) for the full format.
