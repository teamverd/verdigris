# HTTP/3 (QUIC)

verd can serve HTTP/3 over QUIC on TLS listeners and proxy to `h3://`
upstreams. It is **off by default** — enabling it binds a UDP socket
alongside the existing TCP listener; nothing about the TCP path
changes.

## Enabling

Globally, for every TLS listener:

```toml
[server]
http3 = true
```

Or per listener entry (the per-entry value wins):

```toml
[server]
listen = [
  { addr = "0.0.0.0:443", tls = true, http3 = true },
  { addr = "0.0.0.0:8443", tls = true },                 # inherits global (default off)
]
```

`http3 = true` on a non-TLS listener is a config error — QUIC always
carries TLS 1.3.

## Alt-Svc

When a listener serves both TCP TLS and QUIC, TCP responses advertise
`Alt-Svc: h3=":port"` so capable clients can migrate. No Alt-Svc is
emitted on the QUIC side itself.

## Upstreams

```toml
[upstream.up]
servers = ["h3://backend.internal:443"]

[upstream.up.tls]
verify = true        # same verify/ca/sni block as https://
```

All requests to an `h3://` member share one QUIC connection; streams
multiplex like an h2 upstream. Health checks, passive failure tracking,
retry semantics, and `host_header` behave the same as TCP upstreams.

## WebSockets over HTTP/3

HTTP/3 has no `Upgrade` header — WebSockets ride **RFC 9220 extended
CONNECT** instead, and verd bridges between the two wire forms:

- an **h3 client** can reach a classic `Upgrade` upstream (`http://`,
  `https://`), or an `h3://` upstream directly;
- a **classic WebSocket client** can reach an `h3://` upstream —
  verd synthesizes the 101/`Sec-WebSocket-Accept` the client expects
  (h2 upstreams get RFC 8441 extended CONNECT).

Tunnels get the same accounting as TCP ones: byte counters, idle
deadline from the route's `timeouts.send`, connection-slot accounting,
and the process-wide graceful-shutdown drain.

## Operational notes

- **UDP ports**: QUIC is UDP — open/forward UDP on the listener port
  (containers need a separate `/udp` publish, see
  [Docker & deployment](./docker.md)).
- **CPU**: QUIC moves TCP's kernel work into userspace (packet parsing,
  per-packet AEAD, ACKs, stream reassembly) — expect more CPU per byte
  than the TLS/TCP path in exchange for a 1-RTT handshake and no
  head-of-line blocking under loss.
- 0-RTT is not offered (replay risk); `acme-tls/1` stays TCP-only by
  design.
