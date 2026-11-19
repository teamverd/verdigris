//! QUIC/HTTP-3 listener: a `quinn` endpoint accept loop mirroring
//! `conn.rs`, an `h3` connection driver per connection, and one task
//! per request stream running the shared [`service::handle`] pipeline.
//!
//! h3 stream anatomy: `h3_conn.accept()` yields a resolver per request;
//! resolving it produces `(Request<()>, RequestStream)`. The stream is
//! split — the send half is parked in request extensions (the proxy's
//! upgrade path can claim it for RFC 9220 tunnels), the recv half
//! becomes the request body. Response data is pumped frame-by-frame so
//! `timeouts.send` bounds every write like `TimeoutIo` does on TCP.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::sync::watch;

use crate::body::{self, BoxBody};
use crate::errors::BoxError;
use crate::server::service::{self, ConnClose, ConnCtx};
use crate::server::timeout::DeadlineGate;
use crate::server::{Runtime, Shared};

/// QUIC-level close code used on normal teardown — `H3_NO_ERROR`
/// (0x100) from the application layer of the connection.
const H3_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x100);

/// The send half of a server-side h3 request stream.
type H3SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

/// The send half of an h3 request stream parked in request extensions.
/// `None` inside means a tunnel claimed it (RFC 9220 extended CONNECT)
/// — [`serve_request`] then skips the normal response path entirely.
#[derive(Clone)]
pub(crate) struct H3Send(
    // presence marks the request as h3-originated for the proxy's
    // extended-CONNECT detection; the half itself is handed to tunnels
    // via `H3TunnelStart`, never read back through this slot
    #[allow(dead_code)] pub(crate) Arc<Mutex<Option<H3SendStream>>>,
);

/// Placed on the *response* extensions when the proxy claimed the
/// request for an RFC 9220 tunnel: [`serve_request`] writes the
/// response head, then delivers the send half to the tunnel task
/// through this channel instead of pumping a normal body. (`Option`
/// inside because `Extensions` values must be `Clone`.)
#[derive(Clone)]
pub(crate) struct H3TunnelStart {
    pub(crate) tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<H3SendStream>>>>,
}

/// Accept loop for one QUIC endpoint — the UDP counterpart of
/// [`crate::server::conn::accept_loop`]. Admission happens on
/// `Incoming::remote_address` *before* the handshake, so an over-limit
/// peer costs one ignored datagram, not a TLS exchange.
pub async fn accept_loop(
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns = tokio::task::JoinSet::new();
    // A listener kept across a reload must still pick up the new
    // generation's certificates — the endpoint's server config is
    // re-synced per incoming handshake (cheap Arc compare).
    let mut current_cfg: Option<Arc<quinn::ServerConfig>> = None;
    loop {
        let incoming = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
            i = endpoint.accept() => i,
            _ = conns.join_next(), if !conns.is_empty() => continue,
        };
        // None = the endpoint itself was closed (socket gone) — nothing
        // more will ever arrive
        let Some(incoming) = incoming else { break };
        let rt = shared.load();
        if let Some(q) = rt.tls.as_ref().and_then(|t| t.quic.as_ref())
            && current_cfg.as_ref().is_none_or(|c| !Arc::ptr_eq(c, q))
        {
            endpoint.set_server_config(Some((**q).clone()));
            current_cfg = Some(q.clone());
        }
        let peer = incoming.remote_address();
        let Some(guard) = rt.limits.admit(peer.ip()) else {
            crate::observe::metrics::conn_rejected();
            tracing::debug!(
                %peer,
                "QUIC connection rejected — over server.max_connections or max_connections_per_ip"
            );
            // `ignore` sends nothing at all — the cheapest possible
            // refusal, and contributes nothing to a reflection attack
            incoming.ignore();
            continue;
        };
        crate::observe::metrics::conn_accepted();
        conns.spawn(serve_conn(incoming, peer, rt, guard, shutdown.clone()));
    }

    // stop accepting; each conn task sends GOAWAY on its shutdown watch
    // and drains in-flight streams within the outer drain budget.
    while conns.join_next().await.is_some() {}
    endpoint.close(H3_NO_ERROR, b"");
    endpoint.wait_idle().await;
}

/// One QUIC connection: handshake → h3 setup → per-stream dispatch.
/// Mirrors `conn::serve_conn` — same metrics, same `ConnCtx` shape,
/// same graceful-drain contract.
async fn serve_conn(
    incoming: quinn::Incoming,
    peer: SocketAddr,
    rt: Arc<Runtime>,
    conn_guard: crate::server::ConnGuard,
    mut shutdown: watch::Receiver<bool>,
) {
    let timeouts = &rt.config.timeouts;
    // `incoming` as a future is accept() + the QUIC/TLS handshake —
    // `tls_handshake` bounds it just like the TCP accept path.
    let conn = match tokio::time::timeout(timeouts.tls_handshake, incoming).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            crate::observe::metrics::tls_handshake_error();
            tracing::debug!(%peer, error = %e, "QUIC handshake failed");
            return;
        }
        Err(_) => {
            crate::observe::metrics::tls_handshake_error();
            tracing::debug!(%peer, "QUIC handshake timed out");
            return;
        }
    };
    crate::observe::metrics::conn_active(1.0);
    let h3_conn = h3::server::builder()
        .max_field_section_size(rt.config.limits.header_bytes.0)
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(conn.clone()))
        .await;
    let mut h3_conn = match h3_conn {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(%peer, error = %e, "h3 connection setup failed");
            crate::observe::metrics::conn_active(-1.0);
            return;
        }
    };
    let ctx = ConnCtx {
        remote: peer,
        // QUIC is TLS 1.3 over an authenticated transport by definition
        tls: true,
        tls_version: Some("TLSv1_3".to_string()),
        request_counter: Arc::new(AtomicUsize::new(0)),
        first_request_done: Arc::new(AtomicBool::new(false)),
        // there is no between-requests read watchdog on QUIC — the gate
        // exists only so the pipeline's inc/dec contract stays intact
        read_gate: DeadlineGate::default(),
        conn_guard,
        close: ConnClose::Quic(conn.clone()),
        // no Alt-Svc on h3 itself — the client is already there
        alt_svc: None,
    };
    let header_timeout = timeouts.header_read;
    let send_timeout = timeouts.send;
    let mut streams = tokio::task::JoinSet::new();
    let mut goaway = false;
    loop {
        tokio::select! {
            biased;
            _ = streams.join_next(), if !streams.is_empty() => continue,
            _ = shutdown.changed() => {
                if *shutdown.borrow() && !goaway {
                    goaway = true;
                    if let Err(e) = h3_conn.shutdown(usize::MAX).await {
                        tracing::debug!(%peer, error = %e, "h3 GOAWAY failed");
                        break;
                    }
                }
            }
            resolver = h3_conn.accept() => match resolver {
                Ok(Some(resolver)) => {
                    let ctx = ctx.clone();
                    let rt = rt.clone();
                    crate::observe::metrics::requests_inflight(1.0);
                    streams.spawn(async move {
                        serve_request(resolver, ctx, rt, header_timeout, send_timeout).await;
                        crate::observe::metrics::requests_inflight(-1.0);
                    });
                }
                // peer closed the connection gracefully
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "h3 accept error");
                    break;
                }
            },
        }
    }
    conn.close(H3_NO_ERROR, b"");
    // drain stream tasks — conn.close() aborts whatever is still stuck,
    // so this join always terminates
    while streams.join_next().await.is_some() {}
    ctx.read_gate.conn_ended();
    crate::observe::metrics::conn_active(-1.0);
}

/// One h3 request stream: header-read deadline on resolve, then the
/// shared pipeline, then the frame pump.
async fn serve_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    ctx: ConnCtx,
    rt: Arc<Runtime>,
    header_timeout: Duration,
    send_timeout: Duration,
) {
    let resolved = tokio::time::timeout(header_timeout, resolver.resolve_request()).await;
    let (mut req, stream) = match resolved {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::debug!(peer = %ctx.remote, error = %e, "h3 request resolve failed");
            return;
        }
        Err(_) => {
            tracing::debug!(peer = %ctx.remote, "h3 header read timed out");
            return;
        }
    };
    // the pipeline and the access log key off `version` — assert it
    // unconditionally (h3 sets it, but a wrong version is a silent bug)
    *req.version_mut() = http::Version::HTTP_3;
    let (send, recv) = stream.split();
    let (mut parts, ()) = req.into_parts();
    // park the send half for the upgrade path — the normal response
    // pump re-claims it after `handle` returns
    let send_slot = Arc::new(Mutex::new(Some(send)));
    parts.extensions.insert(H3Send(send_slot.clone()));
    let req = http::Request::from_parts(parts, body::boxed(H3Body::new(recv)));

    match service::handle(req, ctx.clone(), rt).await {
        // `close = true` semantics — the QUIC conn dies, every stream
        // on it resets, nothing more is written here
        Err(service::Abort) => ctx.close.close_now(),
        Ok(mut resp) => {
            let send = send_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            // `None` means a tunnel claimed the slot — it owns the
            // stream's whole lifetime now
            if let Some(mut send) = send {
                if let Some(start) = resp.extensions_mut().remove::<H3TunnelStart>() {
                    // tunnel claimed: response head only, then the
                    // send half belongs to the tunnel task — DATA
                    // frames on it are the websocket byte stream
                    let (parts, _body) = resp.into_parts();
                    let mut head = http::Response::from_parts(parts, ());
                    strip_h3_forbidden(head.headers_mut());
                    if let SendOutcome::Sent =
                        send_timed(send_timeout, send.send_response(head), ctx.remote).await
                        && let Some(tx) = start.tx.lock().unwrap_or_else(|e| e.into_inner()).take()
                    {
                        // receiver gone → tunnel died before it
                        // could start; dropping send resets the
                        // stream
                        let _ = tx.send(send);
                    }
                } else {
                    pump_response(send, resp, send_timeout, &ctx).await
                }
            }
        }
    }
}

/// Strip header fields HTTP/3 forbids — RFC 9114 §4.2: no
/// connection-specific fields, and `te` only with the value `trailers`.
/// h3 would treat a forbidden field as a stream error.
fn strip_h3_forbidden(headers: &mut http::HeaderMap) {
    for name in [
        http::header::CONNECTION,
        http::header::TRANSFER_ENCODING,
        http::header::UPGRADE,
        http::header::HeaderName::from_static("keep-alive"),
        http::header::HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
    let te_ok = headers.get_all(http::header::TE).iter().all(|v| {
        v.to_str()
            .is_ok_and(|s| s.trim().eq_ignore_ascii_case("trailers"))
    });
    if !te_ok {
        headers.remove(http::header::TE);
    }
}

/// Send one response on an h3 stream: head → body frames → trailers →
/// FIN. `timeouts.send` bounds every individual write — a stalled peer
/// loses the stream, mirroring `TimeoutIo`'s send watchdog.
async fn pump_response(
    mut send: h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    resp: http::Response<BoxBody>,
    send_timeout: Duration,
    ctx: &ConnCtx,
) {
    let (parts, mut body) = resp.into_parts();
    let mut head = http::Response::from_parts(parts, ());
    strip_h3_forbidden(head.headers_mut());
    match send_timed(send_timeout, send.send_response(head), ctx.remote).await {
        SendOutcome::Sent => {}
        SendOutcome::Failed => return,
        SendOutcome::TimedOut => {
            send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            return;
        }
    }
    loop {
        match body.frame().await {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    match send_timed(send_timeout, send.send_data(data), ctx.remote).await {
                        SendOutcome::Sent => {}
                        SendOutcome::Failed => return,
                        SendOutcome::TimedOut => {
                            send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                            return;
                        }
                    }
                }
                Err(frame) => {
                    // not data, not trailers — nothing representable
                    if let Ok(t) = frame.into_trailers() {
                        let _ = send.send_trailers(t).await;
                    }
                    break;
                }
            },
            // body error — the client sees truncation; reset the stream
            Some(Err(e)) => {
                tracing::debug!(peer = %ctx.remote, error = %e, "h3 response body error");
                send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                return;
            }
            None => break,
        }
    }
    let _ = send.finish().await;
}

/// Result of one timed h3 send operation.
enum SendOutcome {
    /// The frame was written.
    Sent,
    /// The stream errored — already logged; nothing more to do.
    Failed,
    /// `timeouts.send` elapsed — caller should stop the stream.
    TimedOut,
}

/// `send_op` under `send_timeout` — one send per deadline, so a stalled
/// peer loses the stream like `TimeoutIo`'s send watchdog does on TCP.
async fn send_timed<F>(send_timeout: Duration, op: F, peer: SocketAddr) -> SendOutcome
where
    F: std::future::Future<Output = Result<(), h3::error::StreamError>>,
{
    match tokio::time::timeout(send_timeout, op).await {
        Ok(Ok(())) => SendOutcome::Sent,
        Ok(Err(e)) => {
            tracing::debug!(%peer, error = %e, "h3 send failed");
            SendOutcome::Failed
        }
        Err(_) => {
            tracing::debug!(%peer, "h3 send timed out");
            SendOutcome::TimedOut
        }
    }
}

/// HTTP/3 request body: DATA frames → body data, the optional trailing
/// HEADERS frame → trailers. `StreamError` (reset, conn close) maps to
/// a body error, which the pipeline turns into a truncated read.
struct H3Body {
    recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
    /// DATA phase ended — subsequent polls read trailers.
    recv_done: bool,
    /// Stream fully consumed (trailers seen or confirmed absent).
    end: bool,
}

impl H3Body {
    fn new(recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>) -> Self {
        Self {
            recv,
            recv_done: false,
            end: false,
        }
    }
}

impl http_body::Body for H3Body {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let s = self.get_mut();
        if s.end {
            return Poll::Ready(None);
        }
        if !s.recv_done {
            match s.recv.poll_recv_data(cx) {
                Poll::Ready(Ok(Some(mut buf))) => {
                    let data = buf.copy_to_bytes(buf.remaining());
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Poll::Ready(Ok(None)) => s.recv_done = true,
                Poll::Ready(Err(e)) => {
                    s.end = true;
                    return Poll::Ready(Some(Err(Box::new(e))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        match s.recv.poll_recv_trailers(cx) {
            Poll::Ready(Ok(Some(t))) => {
                s.end = true;
                Poll::Ready(Some(Ok(Frame::trailers(t))))
            }
            Poll::Ready(Ok(None)) => {
                s.end = true;
                Poll::Ready(None)
            }
            Poll::Ready(Err(e)) => {
                s.end = true;
                Poll::Ready(Some(Err(Box::new(e))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.end
    }
}
