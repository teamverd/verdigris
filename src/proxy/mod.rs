//! Reverse proxy handler: pick a healthy member, rewrite the request,
//! forward it over a pooled connection, and stream the response back.
//! Includes the retry loop, protocol-upgrade tunnelling and the
//! [`Clusters`] registry shared by all proxy routes.

pub mod cluster;
/// Header-policy helpers — crate-internal, exposed for fuzz targets.
pub mod headers;
pub mod lb;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderValue, StatusCode};
use http_body::{Body, Frame};
use pin_project_lite::pin_project;
use tokio_util::sync::CancellationToken;

use crate::body::{self, BoxBody};
use crate::config::model as cfg;
use crate::errors::BoxError;
use crate::handler::RequestCtx;
use crate::middleware;
use crate::observe::UpstreamUsed;
use crate::proxy::cluster::{
    Checkout, Cluster, Member, RetryGuard, Return, UpError, track_inflight,
};

/// Registry of clusters built for a config generation: named `[upstream.*]`
/// blocks plus anonymous clusters synthesized for inline `proxy = [...]`
/// lists and `site.proxy` shorthands.
pub struct Clusters {
    by_name: HashMap<String, Arc<Cluster>>,
}

impl Clusters {
    /// Build all named clusters in the config.
    pub fn build(cfg: &cfg::Config) -> Result<Self, String> {
        let mut by_name = HashMap::new();
        for (name, up) in &cfg.upstream {
            let cluster = Cluster::build(name, up)?;
            by_name.insert(name.clone(), Arc::new(cluster));
        }
        Ok(Self { by_name })
    }

    /// Resolve a route's upstream reference to a cluster, building an
    /// anonymous cluster (`@key`) for inline URL lists on first use.
    pub fn resolve(&mut self, r: &cfg::UpstreamRef, key: &str) -> Result<Arc<Cluster>, String> {
        match r {
            cfg::UpstreamRef::Name(n) => self.by_name.get(n).cloned().ok_or_else(|| {
                format!(
                    "unknown upstream {n:?} — define it as `[upstream.{n}]` or list server URLs inline"
                )
            }),
            cfg::UpstreamRef::Urls(urls) => match self.by_name.entry(format!("@{key}")) {
                Entry::Occupied(e) => Ok(e.get().clone()),
                Entry::Vacant(e) => {
                    let c = cfg::UpstreamConfig {
                        servers: urls.iter().cloned().map(Into::into).collect(),
                        ..Default::default()
                    };
                    Ok(e.insert(Arc::new(Cluster::build(key, &c)?)).clone())
                }
            },
        }
    }

    /// All clusters (for the admin `/upstreams` view).
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Cluster>> {
        self.by_name.values()
    }

    /// Spawn active health probes for every cluster. Tasks also exit when
    /// their cluster is dropped (they hold `Weak` refs).
    pub fn spawn_background(&self, shutdown: CancellationToken) {
        for c in self.by_name.values() {
            c.spawn_probes(shutdown.clone());
        }
    }
}

/// Live upgraded tunnels. They are spawned detached from any listener's
/// `JoinSet` — a tunnel outlives both its HTTP connection and the config
/// generation that created it — so they are tracked process-wide for the
/// graceful drain at shutdown.
static TUNNELS: std::sync::LazyLock<tokio_util::task::TaskTracker> =
    std::sync::LazyLock::new(tokio_util::task::TaskTracker::new);
/// Cancel signal to all live tunnels when the drain deadline is exceeded.
static TUNNEL_STOP: std::sync::LazyLock<tokio_util::sync::CancellationToken> =
    std::sync::LazyLock::new(tokio_util::sync::CancellationToken::new);

/// Close the tracker to new tunnels and wait for live ones to end
/// (called during graceful drain, within the drain deadline).
pub(crate) async fn drain_tunnels() {
    TUNNELS.close();
    TUNNELS.wait().await;
}

/// Abort every live tunnel (drain deadline exceeded).
pub(crate) fn abort_tunnels() {
    TUNNEL_STOP.cancel();
}

/// A compiled proxy handler.
pub struct Proxy {
    cluster: Arc<Cluster>,
    rewrite: Option<CompiledRewrite>,
    headers: Option<middleware::HeaderOps>,
    retries: cfg::RetryPolicy,
    host_header: cfg::HostHeader,
}

struct CompiledRewrite {
    strip: Option<String>,
    replace: Option<(String, String)>,
    regex: Option<(regex::Regex, String)>,
}

impl Proxy {
    /// Build from config.
    pub fn build(
        p: &cfg::ProxyHandler,
        clusters: &mut Clusters,
        key: &str,
    ) -> Result<Self, String> {
        let cluster = clusters.resolve(&p.upstream, key)?;
        let rewrite = p
            .rewrite
            .as_ref()
            .map(|r| {
                let regex = r
                    .regex
                    .as_ref()
                    .map(|rr| {
                        regex::Regex::new(&rr.pattern)
                            .map(|re| (re, rr.replace.clone()))
                            .map_err(|e| format!("invalid rewrite regex {:?}: {e}", rr.pattern))
                    })
                    .transpose()?;
                Ok::<CompiledRewrite, String>(CompiledRewrite {
                    strip: r.strip_prefix.clone(),
                    replace: r.replace_prefix.as_ref().map(|pp| {
                        let (f, t) = pp.pair();
                        (f.to_string(), t.to_string())
                    }),
                    regex,
                })
            })
            .transpose()?;
        let headers = p
            .request_headers
            .as_ref()
            .filter(|h| h.enabled)
            .map(middleware::HeaderOps::build)
            .transpose()?;
        Ok(Self {
            cluster,
            rewrite,
            headers,
            retries: p.retries.clone(),
            host_header: p.host_header.clone(),
        })
    }

    /// Apply the configured rewrites to the normalized path.
    fn rewrite_path(&self, path: &str) -> String {
        let Some(r) = &self.rewrite else {
            return path.to_string();
        };
        let mut p = path.to_string();
        if let Some(prefix) = &r.strip
            && let Some(rest) = p.strip_prefix(prefix.as_str())
        {
            p = rest.to_string();
        }
        if let Some((from, to)) = &r.replace
            && let Some(rest) = p.strip_prefix(from.as_str())
        {
            p = format!("{to}{rest}");
        }
        if let Some((re, replace)) = &r.regex {
            p = re.replace(&p, replace.as_str()).into_owned();
        }
        if p.is_empty() {
            p.push('/');
        }
        if !p.starts_with('/') {
            p = format!("/{p}");
        }
        p
    }

    /// The `no healthy upstream` response for this cluster.
    fn unavailable(
        &self,
        parts: &http::request::Parts,
        ctx: &RequestCtx,
    ) -> http::Response<BoxBody> {
        let status = StatusCode::from_u16(self.cluster.unavailable.status)
            .unwrap_or(StatusCode::BAD_GATEWAY);
        let body = match &self.cluster.unavailable.body {
            Some(tpl) => crate::handler::substitute_parts(
                tpl,
                &ctx.path,
                &parts.uri,
                &parts.method,
                parts
                    .extensions
                    .get::<crate::observe::RequestId>()
                    .map(|r| r.as_str()),
                ctx,
            ),
            None => "no healthy upstream".to_string(),
        };
        // 1xx/204/304 forbid a response body — emit none rather than
        // produce invalid framing.
        let forbidden = body::response_body_forbidden(&http::Method::GET, status);
        let mut resp = http::Response::new(if forbidden {
            body::empty()
        } else {
            body::full(format!("{body}\n"))
        });
        *resp.status_mut() = status;
        if !forbidden {
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
        resp
    }

    /// Forward one request upstream and produce the downstream response.
    pub async fn handle(
        &self,
        req: http::Request<BoxBody>,
        ctx: &RequestCtx,
    ) -> http::Response<BoxBody> {
        let cluster = self.cluster.clone();
        let mut req = req;
        // HTTP/3 requests can never take the classic upgrade path:
        // `hyper::upgrade::on` yields a TCP IO, and WebSocket over h3 is
        // RFC 9220 extended CONNECT — a different mechanism.
        let upgrade_intent =
            headers::wants_upgrade(req.headers()) && req.version() != http::Version::HTTP_3;
        // RFC 9220: an h3 request with CONNECT + `:protocol` is an
        // extended-CONNECT tunnel request (WebSocket, WebTransport…)
        let ext_connect = req.method() == http::Method::CONNECT
            && req.extensions().get::<h3::ext::Protocol>().is_some();
        let tunnel_intent = upgrade_intent || ext_connect;
        // a tunnel will own the socket after this — permanently disarm
        // the connection's between-requests read deadline for it
        let deadline_off = tunnel_intent
            .then(|| {
                req.extensions()
                    .get::<crate::server::timeout::DeadlineOff>()
                    .map(|d| d.0.clone())
            })
            .flatten();
        // a tunnel owns a socket after the response — keep the
        // connection's admission slot (cloned share, not a new slot)
        // counted for the tunnel's lifetime
        let conn_slot = tunnel_intent
            .then(|| req.extensions().get::<crate::server::ConnGuard>().cloned())
            .flatten();
        // route send deadline → tunnel inactivity bound (the upstream
        // half of a tunnel has no TimeoutIo around it)
        let send_deadline = tunnel_intent
            .then(|| {
                req.extensions()
                    .get::<crate::server::timeout::SendDeadline>()
                    .copied()
            })
            .flatten()
            .map(|s| s.0)
            .unwrap_or_default();
        let mut client_upgrade = if upgrade_intent {
            Some(hyper::upgrade::on(&mut req))
        } else {
            None
        };
        // the upgrade token / :protocol value for tunnel bootstraps —
        // captured before `into_parts` moves the extensions
        let tunnel_proto: Option<String> = if ext_connect {
            req.extensions()
                .get::<h3::ext::Protocol>()
                .map(|p| p.as_str().to_string())
        } else if upgrade_intent {
            req.headers()
                .get(http::header::UPGRADE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        } else {
            None
        };
        let idem = lb::idempotent(req.method()) && !tunnel_intent;
        let replayable = req.body().is_end_stream();
        let (mut parts, body) = req.into_parts();

        // precompute pieces shared by every attempt
        let orig_headers = parts.headers.clone();
        let orig_host = headers::original_host(&parts);
        let query = parts
            .uri
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        // With no rewrite configured, forward the original request-target
        // verbatim: `ctx.path` is percent-DECODED for routing, so
        // re-encoding it irreversibly merges encoded segments into real
        // slashes (GitLab-style `group%2Fproject` breaks upstream).
        // Rewrites operate on the decoded path by design — re-encode then.
        let path = match &self.rewrite {
            None => parts.uri.path().to_string(),
            Some(_) => headers::encode_path(&self.rewrite_path(&ctx.path)),
        };
        let target = http::Uri::from_maybe_shared(format!("{path}{query}"));
        let Ok(target) = target else {
            return crate::server::service::error_response(
                StatusCode::BAD_GATEWAY,
                "could not build upstream request URI",
            );
        };

        // stable mutations done once, before the attempt loop
        headers::strip_hop_by_hop(&mut parts.headers, upgrade_intent);
        headers::set_forwarded(
            &mut parts.headers,
            ctx.peer_ip,
            ctx.peer_trusted,
            ctx.client_ip,
            ctx.scheme,
            &orig_host,
        );

        let mut tried: Vec<usize> = Vec::new();
        let mut retries_used = 0u8;
        let mut first_body = Some(body);
        // held while a retry attempt is outstanding; freed when the loop
        // exits so the cluster budget reflects retries actually in flight
        let mut _budget_slot = None;
        loop {
            let Some(member) = lb::pick(&cluster, ctx.client_ip, &tried) else {
                return self.unavailable(&parts, ctx);
            };
            tried.push(member.id);
            cluster
                .requests
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let inflight = track_inflight(&member);

            let attempt_start = std::time::Instant::now();
            let member_addr = member.url.authority();
            let checkout = match member.checkout(&cluster).await {
                Ok(c) => c,
                Err(e) => {
                    member.report_failure(cluster.health.passive.as_ref());
                    member.meters.attempt(false);
                    member.meters.set_healthy(member.healthy());
                    match self.retry_slot(idem, replayable, retries_used) {
                        Some(g) => {
                            _budget_slot = Some(g);
                            retries_used += 1;
                            continue;
                        }
                        None => return Self::error_for(&e),
                    }
                }
            };
            // multiplexed conns (h2, h3) share rules: absolute-form URI,
            // te: trailers passthrough, per-stream version
            let multiplexed = matches!(checkout, Checkout::H2 { .. } | Checkout::H3 { .. });
            let h3 = matches!(checkout, Checkout::H3 { .. });

            // Tunnel path — engaged when either side can't take the
            // classic `Upgrade` wire form:
            //   ext_connect              → h3 downstream, any upstream
            //   upgrade_intent + h2/h3   → classic downstream, but
            //     `connection: upgrade` is not a legal h2/h3 field —
            //     those need RFC 8441/9220 extended CONNECT instead.
            // classic→h1 upgrades stay on the `hyper::upgrade` path.
            if ext_connect || (upgrade_intent && multiplexed) {
                let Some(proto) = tunnel_proto.as_deref() else {
                    return Self::error_for(&UpError::Send(
                        "upgrade request without a protocol token".into(),
                    ));
                };
                let res = self
                    .tunnel_attempt(TunnelAttempt {
                        checkout,
                        parts: &parts,
                        headers_ops: &self.headers,
                        orig_host: &orig_host,
                        target: &target,
                        member: member.clone(),
                        cluster: cluster.clone(),
                        member_addr,
                        proto,
                        ext_connect,
                        first_body: first_body.take(),
                        client_upgrade: client_upgrade.take(),
                        conn_slot: conn_slot.clone(),
                        deadline_off: deadline_off.clone(),
                        send_deadline,
                        inflight,
                    })
                    .await;
                match res {
                    Ok(resp) => {
                        member.report_success();
                        member.meters.attempt(true);
                        member.meters.set_healthy(true);
                        return resp;
                    }
                    Err(e) => {
                        member.report_failure(cluster.health.passive.as_ref());
                        member.meters.attempt(false);
                        member.meters.set_healthy(member.healthy());
                        match self.retry_slot(idem, replayable, retries_used) {
                            Some(g) if matches!(e, UpError::Connect | UpError::ConnectTimeout) => {
                                _budget_slot = Some(g);
                                retries_used += 1;
                                continue;
                            }
                            _ => return Self::error_for(&e),
                        }
                    }
                }
            }

            // per-attempt header copy: host, te-trailers, user ops differ
            // per member/connection kind
            let mut headers = parts.headers.clone();
            headers::preserve_te_trailers(&mut headers, &orig_headers, multiplexed);
            // exactly one outbound Host: the upstream authority for
            // host_header = "upstream", else the client Host we routed on.
            // `insert`
            // collapses duplicate client Host headers (we routed on the
            // first; the upstream must see that same value, not both),
            // and it synthesizes Host for h2-inbound requests (whose
            // authority lives in :authority) heading to h1 upstreams.
            let host_out = match &self.host_header {
                cfg::HostHeader::Upstream => member.url.authority(),
                cfg::HostHeader::Original => orig_host.clone(),
                cfg::HostHeader::Custom(v) | cfg::HostHeader::Verbatim(v) => v.clone(),
            };
            if let Ok(v) = HeaderValue::from_str(&host_out) {
                headers.insert(HOST, v);
            }
            if let Some(ops) = &self.headers {
                ops.apply(&mut headers);
            }
            let out_body = first_body.take().unwrap_or_else(body::empty);
            let mut out_req = http::Request::new(out_body);
            *out_req.method_mut() = parts.method.clone();
            // multiplexed conns require :authority → absolute-form URI
            // built from the (possibly rewritten) Host header; h1 gets
            // origin-form.
            if multiplexed {
                let authority = headers
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                    .unwrap_or_else(|| member.url.authority());
                let scheme = if member.url.tls { "https" } else { "http" };
                if let Ok(u) = http::Uri::from_maybe_shared(format!(
                    "{scheme}://{authority}{}",
                    target.path_and_query().map(|p| p.as_str()).unwrap_or("/")
                )) {
                    *out_req.uri_mut() = u;
                } else {
                    *out_req.uri_mut() = target.clone();
                }
            } else {
                *out_req.uri_mut() = target.clone();
            }
            *out_req.version_mut() = if h3 {
                http::Version::HTTP_3
            } else if multiplexed {
                http::Version::HTTP_2
            } else {
                http::Version::HTTP_11
            };
            *out_req.headers_mut() = headers;

            let send = checkout.send(out_req);
            let res = match tokio::time::timeout(cluster.limits.response_header, send).await {
                Ok(Ok((resp, ret))) => (resp, ret),
                Ok(Err(e)) => {
                    member.report_failure(cluster.health.passive.as_ref());
                    member.meters.attempt(false);
                    member.meters.set_healthy(member.healthy());
                    match self.retry_slot(idem, replayable, retries_used) {
                        // Connect* = the request may never have reached
                        // the upstream — the only safe kind to retry
                        Some(g) if matches!(e, UpError::Connect | UpError::ConnectTimeout) => {
                            _budget_slot = Some(g);
                            retries_used += 1;
                            continue;
                        }
                        _ => return Self::error_for(&e),
                    }
                }
                Err(_) => {
                    member.report_failure(cluster.health.passive.as_ref());
                    member.meters.attempt(false);
                    member.meters.set_healthy(member.healthy());
                    match self.retry_slot(idem, replayable, retries_used) {
                        Some(g) => {
                            _budget_slot = Some(g);
                            retries_used += 1;
                            continue;
                        }
                        None => return Self::error_for(&UpError::HeaderTimeout),
                    }
                }
            };
            let (mut resp, ret) = res;
            member.report_success();
            member.meters.attempt(true);
            member.meters.set_healthy(true);
            cluster
                .meters
                .duration(attempt_start.elapsed().as_secs_f64());

            // upgrade tunnelling: the 101 response and both raw sockets are
            // spliced; the tunnel task ends when either side closes.
            if upgrade_intent
                && resp.status() == StatusCode::SWITCHING_PROTOCOLS
                && let Some(client_up) = client_upgrade.take()
            {
                let upstream_up = hyper::upgrade::on(&mut resp);
                if let Some(off) = &deadline_off {
                    off.off.store(true, std::sync::atomic::Ordering::Relaxed);
                    off.wake_reader();
                }
                let stop = TUNNEL_STOP.clone();
                TUNNELS.spawn(async move {
                    // conn slot held until the tunnel closes
                    let _conn_slot = conn_slot;
                    crate::observe::metrics::tunnel_open();
                    let counts = (
                        Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    );
                    tokio::select! {
                        _ = stop.cancelled() => {}
                        _ = tunnel(client_up, upstream_up, counts.clone()) => {}
                        _ = tunnel_idle(counts.clone(), send_deadline) => {}
                    }
                    crate::observe::metrics::tunnel_close(
                        counts.0.load(std::sync::atomic::Ordering::Relaxed),
                        counts.1.load(std::sync::atomic::Ordering::Relaxed),
                    );
                });
            }
            let is_101 = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
            headers::strip_hop_by_hop(resp.headers_mut(), is_101);

            let (rparts, rbody) = resp.into_parts();
            let body = UpstreamBody {
                inner: rbody,
                member,
                ret: Some(ret),
                _inflight: inflight,
            };
            let mut out = http::Response::from_parts(rparts, body::boxed(body));
            out.extensions_mut().insert(UpstreamUsed(member_addr));
            return out;
        }
    }

    /// Take a retry-budget slot if this request is allowed another attempt:
    /// idempotent, with a replayable (already-drained/empty) body, under the
    /// per-request and cluster-wide limits.
    fn retry_slot(&self, idem: bool, replayable: bool, used: u8) -> Option<RetryGuard> {
        if !idem || !replayable || used >= self.retries.max_per_request {
            return None;
        }
        lb::take_retry(&self.cluster, self.retries.budget_fraction)
    }

    /// Map an upstream error to a downstream response.
    fn error_for(e: &UpError) -> http::Response<BoxBody> {
        let (status, msg) = match e {
            UpError::ConnectTimeout | UpError::HeaderTimeout => {
                (StatusCode::GATEWAY_TIMEOUT, "upstream timed out")
            }
            UpError::Busy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream connection limit reached",
            ),
            _ => (StatusCode::BAD_GATEWAY, "upstream request failed"),
        };
        crate::server::service::error_response(status, msg)
    }

    /// One tunnel request against a checked-out member: build the
    /// protocol-correct bootstrap (classic `Upgrade` for h1, RFC 8441
    /// extended CONNECT for h2, RFC 9220 for h3), send it, and on
    /// acceptance splice the client side to the upstream end under the
    /// process-wide tunnel tracker. Returns the downstream response —
    /// `200`/`101` on success (the tunnel itself is already spawned),
    /// or the upstream's decline forwarded like any other reply.
    async fn tunnel_attempt(
        &self,
        a: TunnelAttempt<'_>,
    ) -> Result<http::Response<BoxBody>, UpError> {
        // per-attempt header copy with the same Host/ops policy as the
        // normal path — then the protocol-specific bootstrap fields
        let mut headers = a.parts.headers.clone();
        let host_out = match &self.host_header {
            cfg::HostHeader::Upstream => a.member.url.authority(),
            cfg::HostHeader::Original => a.orig_host.to_string(),
            cfg::HostHeader::Custom(v) | cfg::HostHeader::Verbatim(v) => v.clone(),
        };
        if let Ok(v) = HeaderValue::from_str(&host_out) {
            headers.insert(HOST, v);
        }
        if let Some(ops) = a.headers_ops {
            ops.apply(&mut headers);
        }
        // tunnels carry no entity body — the byte stream rides framing
        headers.remove(http::header::CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);

        let mut out_req = http::Request::new(body::empty());
        match &a.checkout {
            Checkout::H1 { .. } => {
                // classic bootstrap: RFC 9110 Upgrade. `sec-websocket-*`
                // ride through from the client headers; key/version are
                // synthesized when the h3 side legitimately omitted them
                headers.insert(
                    http::header::CONNECTION,
                    HeaderValue::from_static("upgrade"),
                );
                if let Ok(v) = HeaderValue::from_str(a.proto) {
                    headers.insert(http::header::UPGRADE, v);
                }
                headers
                    .entry(SEC_WEBSOCKET_VERSION)
                    .or_insert(HeaderValue::from_static("13"));
                headers.entry(SEC_WEBSOCKET_KEY).or_insert_with(ws_key);
                *out_req.method_mut() = http::Method::GET;
                *out_req.uri_mut() = a.target.clone();
                *out_req.version_mut() = http::Version::HTTP_11;
            }
            Checkout::H2 { .. } => {
                // RFC 8441: CONNECT + `:protocol` via the hyper ext
                *out_req.method_mut() = http::Method::CONNECT;
                out_req
                    .extensions_mut()
                    .insert(hyper::ext::Protocol::from(a.proto));
                *out_req.uri_mut() = absolute_uri(a.target, &headers, &a.member);
                *out_req.version_mut() = http::Version::HTTP_2;
            }
            Checkout::H3 { .. } => {
                // RFC 9220: CONNECT + `:protocol` via the h3 ext —
                // vendored h3 accepts arbitrary registered tokens
                *out_req.method_mut() = http::Method::CONNECT;
                if let Ok(p) = a.proto.parse::<h3::ext::Protocol>() {
                    out_req.extensions_mut().insert(p);
                }
                *out_req.uri_mut() = absolute_uri(a.target, &headers, &a.member);
                *out_req.version_mut() = http::Version::HTTP_3;
            }
        }
        *out_req.headers_mut() = headers;

        let send = a.checkout.upgrade_send(out_req);
        let outcome = match tokio::time::timeout(a.cluster.limits.response_header, send).await {
            Ok(o) => o?,
            Err(_) => return Err(UpError::HeaderTimeout),
        };
        let (up, resp_headers, permit) = match outcome {
            cluster::UpgradeOutcome::Rejected { resp, ret } => {
                // upstream declined — forward its response like any
                // other reply (still wrapped for repool accounting)
                let (rparts, rbody) = resp.into_parts();
                let body = UpstreamBody {
                    inner: rbody,
                    member: a.member,
                    ret: Some(ret),
                    _inflight: a.inflight,
                };
                let mut out = http::Response::from_parts(rparts, body::boxed(body));
                out.extensions_mut().insert(UpstreamUsed(a.member_addr));
                return Ok(out);
            }
            cluster::UpgradeOutcome::Accepted {
                up,
                resp_headers,
                permit,
            } => (up, resp_headers, permit),
        };

        // accepted: build the client end and the downstream response
        let counts = (
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        let (client_end, mut resp) = if a.ext_connect {
            // h3 downstream: head goes out on the claimed stream first
            // (`H3TunnelStart`), then the tunnel gets the send half.
            // The request body IS the client→upstream byte channel.
            let (tx, rx) = tokio::sync::oneshot::channel();
            let end = ClientEnd::H3 {
                send_rx: rx,
                body: a.first_body.unwrap_or_else(body::empty),
            };
            let mut r = http::Response::new(body::empty());
            *r.status_mut() = StatusCode::OK;
            *r.headers_mut() = ws_response_headers(&resp_headers);
            r.extensions_mut()
                .insert(crate::server::quic::H3TunnelStart {
                    tx: Arc::new(std::sync::Mutex::new(Some(tx))),
                });
            (end, r)
        } else {
            // classic downstream: synthesize the 101 the client expects
            // — upstream answered ext-CONNECT (2xx), which never
            // produces a Sec-WebSocket-Accept, so derive it locally
            let Some(client_up) = a.client_upgrade else {
                return Err(UpError::Send(
                    "upgrade intent without an upgradeable request".into(),
                ));
            };
            let end = ClientEnd::Io(client_up);
            let mut r = http::Response::new(body::empty());
            *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            let mut h = http::HeaderMap::new();
            h.insert(
                http::header::CONNECTION,
                HeaderValue::from_static("upgrade"),
            );
            if let Ok(v) = HeaderValue::from_str(a.proto) {
                h.insert(http::header::UPGRADE, v);
            }
            if let Some(key) = a
                .parts
                .headers
                .get(SEC_WEBSOCKET_KEY)
                .and_then(|v| v.to_str().ok())
                && let Ok(v) = HeaderValue::from_str(&ws_accept(key))
            {
                h.insert(SEC_WEBSOCKET_ACCEPT, v);
            }
            for (k, v) in ws_response_headers(&resp_headers) {
                if let Some(k) = k {
                    h.insert(k, v);
                }
            }
            *r.headers_mut() = h;
            (end, r)
        };
        if let Some(off) = a.deadline_off {
            off.off.store(true, std::sync::atomic::Ordering::Relaxed);
            off.wake_reader();
        }
        let stop = TUNNEL_STOP.clone();
        TUNNELS.spawn(async move {
            // conn slot held until the tunnel closes
            let _conn_slot = a.conn_slot;
            let _permit = permit;
            crate::observe::metrics::tunnel_open();
            tokio::select! {
                _ = stop.cancelled() => {}
                _ = tunnel_h3(client_end, up, counts.clone()) => {}
                _ = tunnel_idle(counts.clone(), a.send_deadline) => {}
            }
            crate::observe::metrics::tunnel_close(
                counts.0.load(std::sync::atomic::Ordering::Relaxed),
                counts.1.load(std::sync::atomic::Ordering::Relaxed),
            );
        });
        resp.extensions_mut().insert(UpstreamUsed(a.member_addr));
        Ok(resp)
    }
}

/// Everything one upstream tunnel attempt needs — grouped so the call
/// in the retry loop stays readable.
struct TunnelAttempt<'a> {
    checkout: Checkout,
    parts: &'a http::request::Parts,
    headers_ops: &'a Option<middleware::HeaderOps>,
    orig_host: &'a str,
    target: &'a http::Uri,
    member: Arc<Member>,
    cluster: Arc<Cluster>,
    member_addr: String,
    proto: &'a str,
    /// Downstream is h3 extended-CONNECT (vs classic `Upgrade`).
    ext_connect: bool,
    /// The h3 client's request body — the client→upstream byte channel.
    first_body: Option<BoxBody>,
    /// Classic downstream's `OnUpgrade` — present when `!ext_connect`.
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    conn_slot: Option<crate::server::ConnGuard>,
    deadline_off: Option<crate::server::timeout::DeadlineGate>,
    send_deadline: std::time::Duration,
    inflight: cluster::InflightGuard,
}

pin_project! {
    /// Tunnel-side io wrapper: payload bytes read are added to `count`
    /// (relaxed atomic per read — bulk copies only, not per request).
    struct CountIo<T> {
        #[pin]
        inner: T,
        count: Arc<std::sync::atomic::AtomicU64>,
    }
}

impl<T: tokio::io::AsyncRead> tokio::io::AsyncRead for CountIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        match this.inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                this.count.fetch_add(
                    (buf.filled().len() - before) as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: tokio::io::AsyncWrite> tokio::io::AsyncWrite for CountIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Splice a client upgrade and its upstream counterpart; payload bytes
/// read in each direction accumulate into `counts` (up/down).
async fn tunnel(
    client: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    counts: (
        Arc<std::sync::atomic::AtomicU64>,
        Arc<std::sync::atomic::AtomicU64>,
    ),
) {
    let (c, u) = tokio::join!(client, upstream);
    match (c, u) {
        (Ok(c), Ok(u)) => {
            let mut c = CountIo {
                inner: hyper_util::rt::TokioIo::new(c),
                count: counts.0,
            };
            let mut u = CountIo {
                inner: hyper_util::rt::TokioIo::new(u),
                count: counts.1,
            };
            let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
        }
        (c, u) => {
            if let Err(e) = c {
                tracing::debug!(error = %e, "client upgrade failed");
            }
            if let Err(e) = u {
                tracing::debug!(error = %e, "upstream upgrade failed");
            }
        }
    }
}

// sec-websocket-* — not in the `http` crate's header constants
const SEC_WEBSOCKET_KEY: http::HeaderName = http::HeaderName::from_static("sec-websocket-key");
const SEC_WEBSOCKET_ACCEPT: http::HeaderName =
    http::HeaderName::from_static("sec-websocket-accept");
const SEC_WEBSOCKET_VERSION: http::HeaderName =
    http::HeaderName::from_static("sec-websocket-version");
const SEC_WEBSOCKET_PROTOCOL: http::HeaderName =
    http::HeaderName::from_static("sec-websocket-protocol");
const SEC_WEBSOCKET_EXTENSIONS: http::HeaderName =
    http::HeaderName::from_static("sec-websocket-extensions");

/// A random `Sec-WebSocket-Key` — RFC 6455 wants 16 random bytes,
/// base64. UUID v4 is already on the dependency tree.
fn ws_key() -> HeaderValue {
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
    HeaderValue::from_str(&key).unwrap_or(HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="))
}

/// `Sec-WebSocket-Accept` for a client key — RFC 6455 §4.2.2:
/// `base64(SHA-1(key + GUID))`. Needed when the upstream answered
/// extended-CONNECT (which has no accept field) and the classic
/// client expects one.
fn ws_accept(key: &str) -> String {
    use base64::Engine;
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// The WS handshake fields worth copying from an upstream's upgrade
/// response into the downstream reply (subprotocol/extension picks).
fn ws_response_headers(up: &http::HeaderMap) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for name in [
        SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_EXTENSIONS,
        SEC_WEBSOCKET_VERSION,
    ] {
        if let Some(v) = up.get(&name) {
            out.insert(name, v.clone());
        }
    }
    out
}

/// `https://{authority}{path}` for multiplexed upstreams — same
/// construction the normal send path uses for h2/h3.
fn absolute_uri(target: &http::Uri, headers: &http::HeaderMap, member: &Member) -> http::Uri {
    let authority = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| member.url.authority());
    http::Uri::from_maybe_shared(format!(
        "https://{authority}{}",
        target.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    ))
    .unwrap_or_else(|_| target.clone())
}

/// The client side of a tunnel once the response is on the wire:
/// either a classic `hyper::upgrade` socket, or an h3 downstream where
/// the request body is the upload channel and the claimed send half
/// (delivered after [`crate::server::quic::H3TunnelStart`]) is the
/// download channel.
enum ClientEnd {
    Io(hyper::upgrade::OnUpgrade),
    H3 {
        send_rx: tokio::sync::oneshot::Receiver<
            h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
        >,
        body: BoxBody,
    },
}

/// Byte source for one tunnel direction.
enum TunnelRead {
    /// Raw socket read (classic upgrade socket, either side).
    Io(tokio::io::ReadHalf<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>),
    /// h3 downstream request body: DATA frames → bytes.
    Body(BoxBody),
    /// h3 upstream stream recv half: DATA frames → bytes.
    H3(h3::client::RequestStream<h3_quinn::RecvStream, Bytes>),
}

/// Byte sink for one tunnel direction.
enum TunnelWrite {
    Io(tokio::io::WriteHalf<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>),
    /// h3 stream send half — server (downstream) or client (upstream);
    /// both take `send_data(Bytes)`. Boxed: the h3 halves dwarf the Io
    /// variant.
    H3(Box<H3DataSink>),
}

/// Unify the two `send_data` halves — `h3::server` and `h3::client`
/// request streams are distinct types with the same API.
enum H3DataSink {
    Server(h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>),
    Client(h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>),
}

impl H3DataSink {
    async fn send(&mut self, data: Bytes) -> Result<(), h3::error::StreamError> {
        match self {
            Self::Server(s) => s.send_data(data).await,
            Self::Client(s) => s.send_data(data).await,
        }
    }

    async fn close(&mut self) {
        match self {
            Self::Server(s) => {
                let _ = s.finish().await;
            }
            Self::Client(s) => {
                let _ = s.finish().await;
            }
        }
    }
}

impl TunnelRead {
    /// Next payload chunk; `None` on clean end or error (the other
    /// direction's FIN/error propagates through the stream itself).
    async fn next(&mut self, buf: &mut [u8]) -> Option<Bytes> {
        match self {
            Self::Io(io) => match tokio::io::AsyncReadExt::read(io, buf).await {
                Ok(0) | Err(_) => None,
                Ok(n) => Some(Bytes::copy_from_slice(&buf[..n])),
            },
            Self::Body(b) => match http_body_util::BodyExt::frame(b).await {
                Some(Ok(f)) => f.into_data().ok(),
                // trailers end the body; errors truncate it
                _ => None,
            },
            Self::H3(r) => match r.recv_data().await {
                Ok(Some(mut b)) => {
                    use bytes::Buf;
                    Some(b.copy_to_bytes(b.remaining()))
                }
                _ => None,
            },
        }
    }
}

/// One direction of a tunnel: read → count → write → half-close.
async fn tunnel_pump(
    mut r: TunnelRead,
    mut w: TunnelWrite,
    count: Arc<std::sync::atomic::AtomicU64>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    while let Some(data) = r.next(&mut buf).await {
        count.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let ok = match &mut w {
            TunnelWrite::Io(io) => tokio::io::AsyncWriteExt::write_all(io, &data).await.is_ok(),
            TunnelWrite::H3(s) => s.send(data).await.is_ok(),
        };
        if !ok {
            return;
        }
    }
    match &mut w {
        TunnelWrite::Io(io) => {
            let _ = tokio::io::AsyncWriteExt::shutdown(io).await;
        }
        TunnelWrite::H3(s) => s.close().await,
    }
}

/// Splice a client end to an upstream end once both materialize —
/// `OnUpgrade`s resolve when hyper detaches the io, the h3 downstream
/// send half arrives after `serve_request` writes the response head.
async fn tunnel_h3(
    client: ClientEnd,
    up: cluster::UpEnd,
    counts: (
        Arc<std::sync::atomic::AtomicU64>,
        Arc<std::sync::atomic::AtomicU64>,
    ),
) {
    // resolve the upstream end
    let (up_read, up_write) = match up {
        cluster::UpEnd::Io(on) => match on.await {
            Ok(io) => {
                let (r, w) = tokio::io::split(hyper_util::rt::TokioIo::new(io));
                (TunnelRead::Io(r), TunnelWrite::Io(w))
            }
            Err(e) => {
                tracing::debug!(error = %e, "upstream upgrade failed");
                return;
            }
        },
        cluster::UpEnd::H3(end) => (
            TunnelRead::H3(end.recv),
            TunnelWrite::H3(Box::new(H3DataSink::Client(end.send))),
        ),
    };
    // resolve the client end
    let (cl_read, cl_write) = match client {
        ClientEnd::Io(on) => match on.await {
            Ok(io) => {
                let (r, w) = tokio::io::split(hyper_util::rt::TokioIo::new(io));
                (TunnelRead::Io(r), TunnelWrite::Io(w))
            }
            Err(e) => {
                tracing::debug!(error = %e, "client upgrade failed");
                return;
            }
        },
        ClientEnd::H3 { send_rx, body } => match send_rx.await {
            Ok(send) => (
                TunnelRead::Body(body),
                TunnelWrite::H3(Box::new(H3DataSink::Server(send))),
            ),
            // head write failed or serve_request dropped the stream
            Err(_) => return,
        },
    };
    // c→u reads the client end, writes the upstream end; u→c the
    // reverse. join! waits for both directions like copy_bidirectional.
    let _ = tokio::join!(
        tunnel_pump(cl_read, up_write, counts.0),
        tunnel_pump(up_read, cl_write, counts.1),
    );
}

/// Ends when a tunnel moves no bytes in either direction for `period`
/// (the route's send deadline). An upstream that stops reading — or a
/// tunnel left silent — would otherwise pin both sockets forever.
/// `period == 0` means never fire.
async fn tunnel_idle(
    counts: (
        Arc<std::sync::atomic::AtomicU64>,
        Arc<std::sync::atomic::AtomicU64>,
    ),
    period: std::time::Duration,
) {
    if period.is_zero() {
        std::future::pending::<()>().await;
    }
    let mut last = (
        counts.0.load(std::sync::atomic::Ordering::Relaxed),
        counts.1.load(std::sync::atomic::Ordering::Relaxed),
    );
    loop {
        tokio::time::sleep(period).await;
        let now = (
            counts.0.load(std::sync::atomic::Ordering::Relaxed),
            counts.1.load(std::sync::atomic::Ordering::Relaxed),
        );
        if now == last {
            return;
        }
        last = now;
    }
}

pin_project! {
    /// The upstream response body. When it completes cleanly the underlying
    /// connection is returned to the member's idle pool; when it errors or
    /// is dropped early the connection is closed instead (it may hold an
    /// incomplete response). The inflight counter and connection permit
    /// live exactly as long as this body.
    struct UpstreamBody {
        #[pin]
        inner: BoxBody,
        member: Arc<Member>,
        ret: Option<Return>,
        _inflight: cluster::InflightGuard,
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(None) => {
                if let Some(ret) = this.ret.take() {
                    this.member.repool(ret);
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                // dirty connection — drop it rather than repooling
                this.ret.take();
                Poll::Ready(Some(Err(e)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[tokio::test(start_paused = true)]
    async fn tunnel_idle_ends_quiet_tunnels_not_busy_ones() {
        let counts = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        // quiet tunnel: fired after one idle window
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(90),
            tunnel_idle(counts.clone(), std::time::Duration::from_secs(30)),
        )
        .await;
        assert!(res.is_ok(), "idle tunnel must end after one window");

        // busy tunnel: bytes keep moving, watchdog never fires
        let counts = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let bump = {
            let c = counts.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    c.0.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            tunnel_idle(counts, std::time::Duration::from_secs(30)),
        )
        .await;
        assert!(res.is_err(), "active tunnel must not be killed");
        bump.abort();

        // disabled: pending forever, timeout elapses
        let counts = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            tunnel_idle(counts, std::time::Duration::ZERO),
        )
        .await;
        assert!(res.is_err(), "zero period must never fire");
    }
}

#[cfg(test)]
mod handle_tests {
    use super::*;
    use crate::config::model as cfg;
    use crate::handler::RequestCtx;
    use http::Method;
    use http_body_util::BodyExt;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn ctx(path: &str) -> RequestCtx {
        RequestCtx {
            path: path.into(),
            host: "cli.example".into(),
            client_ip: "10.0.0.1".parse().unwrap(),
            peer_ip: "10.0.0.1".parse().unwrap(),
            peer_trusted: false,
            tls: false,
            scheme: "http",
        }
    }

    fn req(uri: &str) -> http::Request<BoxBody> {
        http::Request::builder()
            .uri(uri)
            .header(http::header::HOST, "cli.example")
            .body(crate::body::empty())
            .unwrap()
    }

    /// h1 upstream that replies `status`/`body` and records the Host it saw.
    async fn fake(status: u16, body: &'static str) -> (SocketAddr, Arc<std::sync::Mutex<String>>) {
        let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        let hosts = Arc::new(std::sync::Mutex::new(String::new()));
        let h = hosts.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = lis.accept().await {
                let h = h.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let mut used = 0;
                    loop {
                        match s.read(&mut buf[used..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => used += n,
                        }
                        if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                            let text = String::from_utf8_lossy(&buf[..used]).to_string();
                            if let Some(line) =
                                text.lines().find(|l| l.to_lowercase().starts_with("host:"))
                            {
                                *h.lock().unwrap() = line[5..].trim().to_string();
                            }
                            let resp = format!(
                                "HTTP/1.1 {status} X\r\ncontent-length: {}\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = s.write_all(resp.as_bytes()).await;
                            used = 0;
                        }
                    }
                });
            }
        });
        (addr, hosts)
    }

    fn base(urls: Vec<String>) -> cfg::ProxyHandler {
        cfg::ProxyHandler {
            upstream: cfg::UpstreamRef::Urls(urls),
            rewrite: None,
            request_headers: None,
            retries: cfg::RetryPolicy::default(),
            host_header: cfg::HostHeader::Upstream,
        }
    }

    fn proxy_for(urls: Vec<String>, f: impl FnOnce(&mut cfg::ProxyHandler)) -> Proxy {
        let mut p = base(urls);
        f(&mut p);
        let empty = cfg::Config::default();
        let mut clusters = Clusters::build(&empty).unwrap();
        Proxy::build(&p, &mut clusters, "r").unwrap()
    }

    #[tokio::test]
    async fn handle_happy_path_and_host_modes() {
        let (addr, hosts) = fake(200, "hi").await;
        // host_header = "upstream" → upstream sees its own authority
        let p = proxy_for(vec![format!("http://{addr}")], |p| {
            p.host_header = cfg::HostHeader::Upstream
        });
        let r = p.handle(req("/x"), &ctx("/x")).await;
        assert_eq!(r.status(), 200);
        r.into_body().collect().await.unwrap();
        assert_eq!(hosts.lock().unwrap().as_str(), addr.to_string());

        // host_header = "original" → upstream sees the routed client Host
        let p = proxy_for(vec![format!("http://{addr}")], |p| {
            p.host_header = cfg::HostHeader::Original
        });
        let r = p.handle(req("/y"), &ctx("/y")).await;
        assert_eq!(r.status(), 200);
        r.into_body().collect().await.unwrap();
        assert_eq!(hosts.lock().unwrap().as_str(), "cli.example");
    }

    #[tokio::test]
    async fn rewrite_variants() {
        let (addr, _) = fake(200, "hi").await;
        let mk = |p: &Proxy, path: &str| p.rewrite_path(path);
        // strip_prefix
        let p = proxy_for(vec![format!("http://{addr}")], |p| {
            p.rewrite = Some(cfg::Rewrite {
                strip_prefix: Some("/api".into()),
                ..Default::default()
            });
        });
        assert_eq!(mk(&p, "/api/v1/x"), "/v1/x");
        assert_eq!(mk(&p, "/api"), "/", "empty result becomes /");
        // replace_prefix
        let p = proxy_for(vec![format!("http://{addr}")], |p| {
            p.rewrite = Some(cfg::Rewrite {
                replace_prefix: Some(cfg::PrefixPair {
                    from: "/old".into(),
                    to: "/new".into(),
                }),
                ..Default::default()
            });
        });
        assert_eq!(mk(&p, "/old/x"), "/new/x");
        // regex
        let p = proxy_for(vec![format!("http://{addr}")], |p| {
            p.rewrite = Some(cfg::Rewrite {
                regex: Some(cfg::RegexRewrite {
                    pattern: "^/a/(.*)".into(),
                    replace: "/b/$1".into(),
                }),
                ..Default::default()
            });
        });
        assert_eq!(mk(&p, "/a/q"), "/b/q");
        // no rewrite → verbatim
        let p = proxy_for(vec![format!("http://{addr}")], |_| {});
        assert_eq!(mk(&p, "/keep%2Fme"), "/keep%2Fme");
        // no leading slash after rewrite → prepended
        let p = proxy_for(vec![format!("http://{addr}")], |p| {
            p.rewrite = Some(cfg::Rewrite {
                regex: Some(cfg::RegexRewrite {
                    pattern: "^/".into(),
                    replace: "rel/".into(),
                }),
                ..Default::default()
            });
        });
        assert_eq!(mk(&p, "/x"), "/rel/x");
    }

    #[test]
    fn build_errors() {
        let empty = cfg::Config::default();
        let mut clusters = Clusters::build(&empty).unwrap();
        // unknown named upstream
        let mut p = base(vec![]);
        p.upstream = cfg::UpstreamRef::Name("nope".into());
        assert!(Proxy::build(&p, &mut clusters, "r").is_err());
        // bad rewrite regex
        let mut p = base(vec!["http://127.0.0.1:9".into()]);
        p.rewrite = Some(cfg::Rewrite {
            regex: Some(cfg::RegexRewrite {
                pattern: "(".into(),
                replace: "x".into(),
            }),
            ..Default::default()
        });
        assert!(Proxy::build(&p, &mut clusters, "r").is_err());
    }

    #[tokio::test]
    async fn unavailable_when_no_healthy_members() {
        let (addr, _) = fake(200, "hi").await;
        let p = proxy_for(vec![format!("http://{addr}")], |_| {});
        for m in &p.cluster.members {
            m.mark_sick(Duration::from_secs(60));
        }
        let r = p.handle(req("/"), &ctx("/")).await;
        assert_eq!(r.status(), 502);
    }

    #[tokio::test]
    async fn connect_failure_maps_to_502_and_retry_exhaustion() {
        // nothing listening on :1 → connect refused; GET is idempotent so
        // retries fire until max_per_request, then error_for(Connect)
        let p = proxy_for(vec!["http://127.0.0.1:1".into()], |p| {
            p.retries.max_per_request = 1;
        });
        let r = p.handle(req("/"), &ctx("/")).await;
        assert_eq!(r.status(), 502);
        // non-idempotent method skips the retry path entirely
        let rq = http::Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(http::header::HOST, "cli.example")
            .body(crate::body::empty())
            .unwrap();
        let r = p.handle(rq, &ctx("/")).await;
        assert_eq!(r.status(), 502);
    }

    #[test]
    fn error_for_maps_all_arms() {
        assert_eq!(Proxy::error_for(&UpError::ConnectTimeout).status(), 504);
        assert_eq!(Proxy::error_for(&UpError::HeaderTimeout).status(), 504);
        assert_eq!(Proxy::error_for(&UpError::Busy).status(), 503);
        assert_eq!(Proxy::error_for(&UpError::Connect).status(), 502);
        assert_eq!(Proxy::error_for(&UpError::Resolve).status(), 502);
        assert_eq!(Proxy::error_for(&UpError::Send("x".into())).status(), 502);
        assert_eq!(Proxy::error_for(&UpError::Tls("x".into())).status(), 502);
    }

    #[tokio::test]
    async fn unavailable_custom_response() {
        let (addr, _) = fake(200, "hi").await;
        let mut c = cfg::UpstreamConfig {
            servers: vec![format!("http://{addr}").into()],
            unavailable: cfg::UnavailableResponse {
                status: 503,
                body: Some("try later".into()),
            },
            ..Default::default()
        };
        let cluster = Arc::new(Cluster::build("t", &c).unwrap());
        let empty = cfg::Config::default();
        let mut clusters = Clusters::build(&empty).unwrap();
        let p = Proxy {
            cluster: cluster.clone(),
            rewrite: None,
            headers: None,
            retries: cfg::RetryPolicy::default(),
            host_header: cfg::HostHeader::Upstream,
        };
        for m in &p.cluster.members {
            m.mark_sick(Duration::from_secs(60));
        }
        let r = p.handle(req("/"), &ctx("/")).await;
        assert_eq!(r.status(), 503);
        let b = r.into_body().collect().await.unwrap().to_bytes();
        assert!(b.starts_with(b"try later"));
        let _ = (&mut c, &mut clusters);
    }

    #[test]
    fn clusters_resolve_and_iterate() {
        let cfg_text = r##"
            [upstream.u]
            servers = ["http://127.0.0.1:9"]
        "##;
        let cfg = crate::config::validate::parse_test_config(cfg_text);
        let mut clusters = Clusters::build(&cfg).unwrap();
        assert_eq!(clusters.iter().count(), 1);
        // named resolves
        let c = clusters
            .resolve(&cfg::UpstreamRef::Name("u".into()), "r")
            .unwrap();
        assert_eq!(c.name, "u");
        // anonymous urls materialize and dedupe on the same key
        let a = clusters
            .resolve(
                &cfg::UpstreamRef::Urls(vec!["http://127.0.0.1:8".into()]),
                "k",
            )
            .unwrap();
        let b = clusters
            .resolve(
                &cfg::UpstreamRef::Urls(vec!["http://127.0.0.1:8".into()]),
                "k",
            )
            .unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        // unknown name errors
        assert!(
            clusters
                .resolve(&cfg::UpstreamRef::Name("nope".into()), "r")
                .is_err()
        );
        // empty urls error
        assert!(
            clusters
                .resolve(&cfg::UpstreamRef::Urls(vec![]), "k2")
                .is_err()
        );
        // spawn_background on a cluster without active health → noop
        clusters.spawn_background(tokio_util::sync::CancellationToken::new());
    }

    #[test]
    fn retry_slot_gates_on_predicate_and_cap() {
        let p = proxy_for(vec!["http://127.0.0.1:1".into()], |p| {
            p.retries.max_per_request = 1;
        });
        // non-idempotent or non-replayable never gets a slot
        assert!(p.retry_slot(false, true, 0).is_none());
        assert!(p.retry_slot(true, false, 0).is_none());
        assert!(p.retry_slot(false, false, 0).is_none());
        // idempotent + replayable under the cap → a slot (the empty
        // cluster budget admits the first retry)
        assert!(p.retry_slot(true, true, 0).is_some());
        // per-request cap reached → no slot even with budget left
        assert!(p.retry_slot(true, true, 1).is_none());
    }
}
