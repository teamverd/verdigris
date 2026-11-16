# Middleware

Per-route, in order: `path deny → ip acl → CORS preflight → auth →
rate limit → cache → handler → security/cors/ratelimit headers →
compression`.

## Site defaults

Every middleware block also exists at site level and is inherited by
all of the site's routes — including the implicit `site.root` /
`site.proxy` catch-alls:

```toml
[[site]]
hosts = ["app.example.com"]
auth = { bearer = { tokens = ["${API_TOKEN}"] } }   # every route below
rate_limit = { rate = "100/s", key = "ip" }     # one shared bucket
ip_deny = ["203.0.113.0/24"]

[[site.route]]
prefix = "/public"
respond = { status = 200, body = "open" }
auth = { enabled = false }        # opt out of the site default

[[site.route]]
prefix = "/api"
proxy = "http://127.0.0.1:9000"
rate_limit = { rate = "10/s", key = "route" }   # replaces, doesn't merge
```

- A route block **replaces** the site block wholesale — except
  `response_headers` (`set`/`add` union, route keys win; `remove`
  concatenates) and `security`, which merge field-wise.
- `enabled = false` opts a route out of an inherited block; the bare
  spelling says the same thing for every middleware block —
  `auth = false`, `cors = false`, `rate_limit = false`, `cache = false`,
  `compress = false`, `response_headers = false`, `security = false`,
  `path_deny = false`.
- A site-level `rate_limit` builds **one shared limiter** across all
  routes that inherit it — `key = "ip"` limits each client site-wide.
- IP ACLs **tighten only**: denies union, and a request must pass both
  non-empty allow lists — a route can't widen a site ACL.
- `timeouts`, `limits`, and `security` also layer global → site →
  route.

## IP ACLs

```toml
[[site.route]]
prefix = "/internal"
ip_allow = ["10.0.0.0/8", "192.168.0.0/16"]
ip_deny = ["10.0.0.9/32"]
```

Client IP honours `X-Forwarded-For` only from `trusted_proxies`. A
site's `trusted_proxies` **replaces** the global
`server.trusted_proxies` list — set the full CIDR set on the site, not
just the additions.

## Path denylist

`path_deny` rejects requests whose normalized path matches a denylist —
from a list file (`file`), inline entries (`paths`), or both. At site
level it covers every route, including the `root`/`proxy`/`respond`/
`redirect` catch-alls:

```toml
[[site]]
hosts = ["a.example", "b.example"]
path_deny = { file = "bad-requests.txt" }   # or: path_deny = "bad-requests.txt"

[[site.route]]
prefix = "/public"
respond = "open"
path_deny = false                           # opt out of the site list
```

List-file format: one path per line, `#` comments and blank lines
skipped, and a leading `path ` per line is tolerated so Caddy-exported
lists (`path /.env`, `path /admin*`) work verbatim. A trailing `*`
makes an entry a literal prefix — `/admin*` denies `/admin`, `/admin/x`,
`/administrator`; every other entry is an exact match. Entries are
normalized like request paths — percent-decoding, dot-segments,
duplicate slashes — so `/%2e%2e/x`, `%2F`, and `//` spellings hit the
same entry.

- `status` is the denial response (default `403`; `404` for stealth)
  and must be an error status.
- `close = true` drops the connection without responding (Caddy
  `abort` parity): on HTTP/1 the socket closes mid-request, on HTTP/2
  the whole connection is torn down — the client never sees an HTTP
  status. The denial still lands in the access log and metrics as
  `444`; `status` is ignored. To close *every* request on a route
  regardless of path, use the `close = true` handler instead.
- Runs **first** in the middleware order — before IP ACLs, auth, rate
  limiting, cache, and the handler.
- A route's own `path_deny` **replaces** the site list (like
  `rate_limit`); `path_deny = false` opts out entirely.
- `file` is relative to the config file that names it and joins the
  `--watch` set — editing the list triggers a reload. `verd config`
  shows the file reference, not the expanded entries.

## Response headers

`response_headers` (and `proxy.request_headers` upstream-bound) apply
in a fixed order — **remove → set → add** — so a same-named
`remove`+`set` means "clear the incoming value, write ours".

## Authentication

```toml
auth = { basic = { realm = "ops",
                   users = { ned = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$3nGf8u5Z2p2mJx0yq9Rk3g" } }}
# or: auth = { bearer = { tokens = ["${API_TOKEN}"] } }
# or the token shorthand: auth = { bearer = "${API_TOKEN}" }
# or: auth = { api_key = { location = "header", name = "x-api-key", keys = ["${KEY1}"] } }
```

Basic-auth passwords must be argon2id or bcrypt hashes (plaintext is
rejected at validation). `basic = "users.htpasswd"` is shorthand for
`{ htpasswd = "users.htpasswd" }` — a bcrypt `$2y$` file instead of
inline users. The authenticated identity rides request extensions into
handlers, the access log, and rate-limit keys.

## CORS

```toml
cors = { origins = ["https://app.example.com", "*.staging.example.com"],
         methods = ["GET","POST"], headers = ["content-type"],
         credentials = true, max_age = "1h" }
```

Preflights short-circuit before auth; actual responses get ACAO/ACAC and
a `Vary: Origin`.

## Rate limiting

```toml
rate_limit = { rate = "10/s", burst = 20, key = "identity" }
# or: rate_limit = { rate = "600/m", burst = 20, key = "header:x-api-key" }
```

Token bucket per key (`ip`, `identity`, or `header:<name>`), with
`dry_run` (log-but-allow), `exempt` CIDRs, and `RateLimit-*` headers.
Idle buckets are swept automatically.

## Compression

```toml
compress = { types = ["text/*", "application/json"], min_bytes = "1KiB",
             algorithms = ["br", "zstd", "gzip"], level = 5 }
# or just: compress = true
# or pick algorithms: compress = "br" / compress = ["br", "zstd"]
```

Streams br/zstd/gzip by `Accept-Encoding` q-values; skips small bodies,
precompressed content, ranges, HEAD, no-transform responses, and upgrades.
