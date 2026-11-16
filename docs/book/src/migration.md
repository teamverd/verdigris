# Migrating from nginx / Caddy

| nginx | verd.toml |
| --- | --- |
| `server { listen 443 ssl; }` | `server.listen = [{ addr = "0.0.0.0:443", tls = true }]` |
| `server_name example.com` | `hosts = ["example.com"]` on `[[site]]` |
| `location / { root … }` | `[[site.route]] prefix="/" static={root="…"}` |
| `location ~ …` | `regex = "…"` on the route |
| `try_files …` | `static.try_files` (paths serve from `root` — no prefix rebase) |
| `client_max_body_size` | `limits.body_bytes` (route or global `[limits]`) |
| `gzip on` | `compress = true` |
| `proxy_pass http://app` | `proxy = "http://app"` or `{ upstream = "app" }` |
| `proxy_set_header X-…` | `proxy.request_headers = { set = { … } }` |
| `upstream { least_conn; }` | `[upstream.app] lb="least_conn"` |
| `limit_req_zone` | `route.rate_limit` |
| `auth_basic` | `route.auth = { basic = { users = { name = "hash" } } }` |
| `include sites-enabled` | `include = ["conf.d"]` (merges every `*.toml`) |
| `add_header X-…` | `route.response_headers = { set = { … } }` |
| `access_log /var/log/x` | `log.access = "/var/log/x"` |
| `return 301 https://…` | `route.redirect = "https://…"` (whole site: `site.redirect`) |
| `return 404` | `respond = 404` |
| `error_page 404 /nf.html` | `static.error_pages = { 404 = "nf.html", "5xx" = "oops.html" }` |
| `ssl_certificate(…)` | `site.tls = { cert="…", key="…" }` |

| Caddy | verd.toml |
| --- | --- |
| `example.com { file_server }` | `hosts=["example.com"] tls="auto"` + static route |
| `reverse_proxy app:9000` | `proxy = "http://app:9000"` |
| automatic HTTPS | `tls = "auto"` + `[acme]` account block |
| `basic_auth` | `route.auth = { basic = { users = { name="hash" } } }` |
| `file_server browse` | `static = { root = "…", listing = true }` |
| `encode zstd gzip` | `compress = true` |
| `respond 404` | `respond = 404` |
| `abort` | `close = true` on the route — connection drops, no response |
| `redir https://apex{uri}` | `site.redirect = "https://apex{path}{query}"` |
| `@blocked { path … }` + `abort @blocked` | `path_deny` on `[[site]]` — see below |

Caddy's shared bad-requests denylist — `(badreq) { @blocked { path … }
abort @blocked }` or `@blocked { import ./bad-requests.txt }` — maps to a
site-level `path_deny` naming the same file:

```toml
[[site]]
hosts = ["example.com"]
path_deny = { file = "bad-requests.txt", close = true }   # Caddy `abort` parity; or status = 404 for stealth
```

The file works verbatim: one path per line, `#` comments, `path`-line
prefixes tolerated, `*` suffix = prefix. `abort` maps to
`close = true` — the connection drops with no response (logged as
`444`); without it the denial answers with a configured `status`.
Unlike an `import`ed snippet the list applies to *every* route of the
site automatically — no matcher block to wire into each site. See
[Path denylist](middleware.md#path-denylist).

Wildcard hosts (`*.example.com`), regex routes, per-site trusted proxies,
and multi-site host routing match nginx semantics — the config reference
covers each knob.
