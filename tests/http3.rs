//! End-to-end HTTP/3: a real QUIC client (quinn + h3 + h3-quinn) against
//! a live listener. TLS is mandatory — the test trusts the site's
//! self-signed cert directly, like the TCP TLS tests do.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;

use verd::config::model::{Config, ListenAddr};
use verd::server::{self, Runtime};

const CONFIG: &str = r#"
[[site]]
hosts = ["example.test"]
tls = { cert = "{cert}", key = "{key}" }

[[site.route]]
prefix = "/"
respond = { status = 200, body = "root\n" }

[[site.route]]
prefix = "/echo"
proxy = "up"

[upstream.up]
servers = ["http://127.0.0.1:{upstream}"]
"#;

/// A `ListenAddr` builder line — every field explicit, like the other
/// e2e files do.
fn listen(addr: SocketAddr, tls: bool, http3: Option<bool>) -> ListenAddr {
    ListenAddr {
        addr,
        tls,
        external_port: None,
        http3,
    }
}

/// Start the server on one ephemeral port (TCP +, when enabled, UDP).
/// Returns the port and the shutdown sender.
async fn start(
    config: &str,
    http3: Option<bool>,
) -> (u16, Arc<Runtime>, tokio::sync::watch::Sender<bool>) {
    let port = portpicker::pick_unused_port().expect("free port");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg: Config = toml::from_str(config).unwrap();
    let mut cfg = cfg;
    cfg.server.listen = vec![listen(addr, true, http3)];
    cfg.admin.enabled = false;

    let rt = Runtime::build(Arc::new(cfg)).expect("runtime builds");
    let (tx, rx) = tokio::sync::watch::channel(false);
    {
        let rt = rt.clone();
        tokio::spawn(async move {
            server::serve(rt, async move {
                let _ = rx.clone().changed().await;
            })
            .await
        });
    }
    for _ in 0..100 {
        if rt.ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        rt.ready.load(Ordering::Relaxed),
        "server never became ready"
    );
    (port, rt, tx)
}

/// A live h3 client: QUIC endpoint + shared `SendRequest`. The
/// connection driver must keep running for streams to progress.
struct H3 {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    port: u16,
    _driver: tokio::task::JoinHandle<()>,
    _endpoint: quinn::Endpoint,
}

async fn h3_connect(port: u16, cert_pem: &str) -> H3 {
    let mut roots = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(der.expect("cert der")).expect("cert added");
    }
    let mut cc = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cc.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(cc).expect("quic client config");
    let client_cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_cfg);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let conn = endpoint
        .connect(addr, "example.test")
        .expect("connect")
        .await
        .expect("QUIC handshake");
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .expect("h3 setup");
    let driver = tokio::spawn(async move {
        futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    H3 {
        send,
        port,
        _driver: driver,
        _endpoint: endpoint,
    }
}

impl H3 {
    /// One request/response cycle: `(status, headers, body)`.
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: bytes::Bytes,
    ) -> (u16, http::HeaderMap, bytes::Bytes) {
        let req = http::Request::builder()
            .method(method)
            .uri(format!("https://example.test:{}{path}", self.port))
            .body(())
            .unwrap();
        let mut stream = self.send.send_request(req).await.expect("send_request");
        if !body.is_empty() {
            stream.send_data(body).await.expect("send_data");
        }
        stream.finish().await.expect("finish");
        let resp = stream.recv_response().await.expect("recv_response");
        let mut out = bytes::BytesMut::new();
        use bytes::Buf;
        while let Some(mut chunk) = stream.recv_data().await.expect("recv_data") {
            while chunk.has_remaining() {
                let c = chunk.chunk();
                out.extend_from_slice(c);
                let n = c.len();
                chunk.advance(n);
            }
        }
        (resp.status().as_u16(), resp.headers().clone(), out.freeze())
    }
}

/// The smallest HTTP/1.1 upstream that echoes the request body — proves
/// the h3 request-body path (H3Body) end to end.
async fn echo_upstream() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut s, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                // read until headers end + any body bytes the peer sent
                let _ = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let n = s.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        // enough to see headers + chunked body
                        if buf.windows(4).any(|w| w == b"\r\n\r\n")
                            && buf.windows(5).any(|w| w == b"\r\n0\r\n")
                        {
                            break;
                        }
                    }
                })
                .await;
                // extract everything after the header terminator —
                // chunked framing: strip "hex\r\n...\r\n0\r\n\r\n"
                let body = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    Some(p) => &buf[p + 4..],
                    None => &[][..],
                };
                // minimal chunk decode for the one-chunk case tests use
                let decoded = if body.first().is_some_and(|b| b.is_ascii_hexdigit())
                    && body.windows(2).any(|w| w == b"\r\n")
                {
                    let mut out = Vec::new();
                    let mut rest = body;
                    while let Some(crlf) = rest.windows(2).position(|w| w == b"\r\n") {
                        let size = usize::from_str_radix(
                            std::str::from_utf8(&rest[..crlf]).unwrap_or("0").trim(),
                            16,
                        )
                        .unwrap_or(0);
                        rest = &rest[crlf + 2..];
                        if size == 0 || rest.len() < size + 2 {
                            break;
                        }
                        out.extend_from_slice(&rest[..size]);
                        rest = &rest[size + 2..];
                    }
                    out
                } else {
                    body.to_vec()
                };
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                            decoded.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = s.write_all(&decoded).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn h3_get_alt_svc_and_pipeline_parity() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = verd::tls::selfsigned::generate_pems(&["example.test".into()]);
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &cert).unwrap();
    std::fs::write(&key_path, &key).unwrap();
    let config = CONFIG
        .replace("{cert}", &cert_path.display().to_string())
        .replace("{key}", &key_path.display().to_string())
        .replace("{upstream}", "1"); // placeholder — no /echo traffic here
    let (port, _rt, sd) = start(&config, Some(true)).await;

    // h3 request: full pipeline parity — body, Server/X-Request-Id
    let mut client = h3_connect(port, &cert).await;
    let (status, headers, body) = client.request("GET", "/", bytes::Bytes::new()).await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"root\n");
    assert!(
        headers.contains_key("x-request-id"),
        "pipeline headers must flow over h3"
    );

    // the TCP side of the same listener advertises Alt-Svc — pin DNS
    // to the cert's hostname so the chain + SAN verify for real
    let https = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.as_bytes()).unwrap())
        .resolve("example.test", format!("127.0.0.1:{port}").parse().unwrap())
        .build()
        .unwrap();
    let resp = https
        .get(format!("https://example.test:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("alt-svc").and_then(|v| v.to_str().ok()),
        Some(format!("h3=\":{port}\"; ma=86400").as_str()),
    );

    sd.send(true).unwrap();
}

#[tokio::test]
async fn h3_request_body_streams_to_proxy() {
    let upstream = echo_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = verd::tls::selfsigned::generate_pems(&["example.test".into()]);
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &cert).unwrap();
    std::fs::write(&key_path, &key).unwrap();
    let config = CONFIG
        .replace("{cert}", &cert_path.display().to_string())
        .replace("{key}", &key_path.display().to_string())
        .replace("{upstream}", &upstream.to_string());
    let (port, _rt, sd) = start(&config, Some(true)).await;

    let mut client = h3_connect(port, &cert).await;
    let payload = bytes::Bytes::from_static(b"hello over quic");
    let (status, _headers, body) = client.request("POST", "/echo", payload.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(body, payload);
    sd.send(true).unwrap();
}

const BACKEND: &str = r#"
[[site]]
hosts = ["127.0.0.1"]
tls = { cert = "{cert}", key = "{key}" }

[[site.route]]
prefix = "/"
respond = { status = 200, body = "via-h3\n" }

[[site.route]]
prefix = "/echo"
proxy = "echo"

[upstream.echo]
servers = ["http://127.0.0.1:{echo}"]
"#;

const FRONT_H3_UP: &str = r#"
[[site]]
hosts = ["front.test"]
tls = { cert = "{cert}", key = "{key}" }

[[site.route]]
prefix = "/"
proxy = "up"

[upstream.up]
servers = ["h3://127.0.0.1:{backend}"]

[upstream.up.tls]
verify = false
"#;

/// The whole chain: TCP client → verd (TLS) → `h3://` member → verd
/// (QUIC listener) → static/echo handler. Proves the shared QUIC conn,
/// the multiplexed checkout, body pumping both ways, and `tls.verify`
/// plumbing end to end.
#[tokio::test]
async fn h3_upstream_proxying() {
    let echo = echo_upstream().await;
    let dir = tempfile::tempdir().unwrap();

    // backend: h3 listener only — TLS is mandatory on QUIC
    let (bcert, bkey) = verd::tls::selfsigned::generate_pems(&["127.0.0.1".into()]);
    let bcert_path = dir.path().join("b-cert.pem");
    let bkey_path = dir.path().join("b-key.pem");
    std::fs::write(&bcert_path, &bcert).unwrap();
    std::fs::write(&bkey_path, &bkey).unwrap();
    let backend_cfg = BACKEND
        .replace("{cert}", &bcert_path.display().to_string())
        .replace("{key}", &bkey_path.display().to_string())
        .replace("{echo}", &echo.to_string());
    let (bport, _brt, bsd) = start(&backend_cfg, Some(true)).await;

    // front: plain TCP TLS listener, upstream is QUIC
    let (fcert, fkey) = verd::tls::selfsigned::generate_pems(&["front.test".into()]);
    let fcert_path = dir.path().join("f-cert.pem");
    let fkey_path = dir.path().join("f-key.pem");
    std::fs::write(&fcert_path, &fcert).unwrap();
    std::fs::write(&fkey_path, &fkey).unwrap();
    let front_cfg = FRONT_H3_UP
        .replace("{cert}", &fcert_path.display().to_string())
        .replace("{key}", &fkey_path.display().to_string())
        .replace("{backend}", &bport.to_string());
    let (fport, _frt, fsd) = start(&front_cfg, None).await;

    // pin "front.test" to the listener so the cert's SAN verifies
    let https = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(fcert.as_bytes()).unwrap())
        .resolve("front.test", format!("127.0.0.1:{fport}").parse().unwrap())
        .build()
        .unwrap();
    // GET over the h3 upstream
    let resp = https
        .get(format!("https://front.test:{fport}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "via-h3\n");

    // POST a body through the same upstream path — two streams on the
    // one shared QUIC conn
    let resp = https
        .post(format!("https://front.test:{fport}/echo"))
        .body("hi h3 upstream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hi h3 upstream");

    fsd.send(true).unwrap();
    bsd.send(true).unwrap();
}

/// A minimal "WebSocket" h1 upstream: reads the request head, asserts
/// the classic-upgrade bootstrap fields, answers 101, then echoes raw
/// bytes back — the tunnel is byte-transparent by design.
async fn ws_echo_upstream() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut s, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut used = 0;
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let n = s.read(&mut buf[used..]).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        used += n;
                        if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                })
                .await;
                let head = String::from_utf8_lossy(&buf[..used]).to_lowercase();
                // the RFC 9220→h1 translation must produce a complete
                // classic bootstrap even when the client skipped fields
                let ok = head.contains("upgrade: websocket")
                    && head.contains("connection: upgrade")
                    && head.contains("sec-websocket-key:")
                    && head.contains("sec-websocket-version: 13");
                if !ok {
                    let _ = s
                        .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                        .await;
                    return;
                }
                let proto = if head.contains("sec-websocket-protocol:") {
                    "sec-websocket-protocol: chat\r\n"
                } else {
                    ""
                };
                let _ = s
                    .write_all(
                        format!("HTTP/1.1 101 Switching Protocols\r\n{proto}\r\n").as_bytes(),
                    )
                    .await;
                // echo anything that follows — including whatever
                // arrived in the first read past the head
                let mut rest = buf[..used].to_vec();
                if let Some(p) = rest.windows(4).position(|w| w == b"\r\n\r\n") {
                    rest.drain(..p + 4);
                }
                if !rest.is_empty() {
                    let _ = s.write_all(&rest).await;
                }
                let mut chunk = [0u8; 4096];
                loop {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&chunk[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// h3 client → verd → classic `Upgrade` h1 upstream. Covers the RFC
/// 9220 downstream path: `:protocol=websocket` on the wire, `200` (not
/// 101) to the client, then DATA↔socket bridging both ways.
#[tokio::test]
async fn h3_websocket_tunnel_to_h1_upstream() {
    let ws = ws_echo_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = verd::tls::selfsigned::generate_pems(&["example.test".into()]);
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &cert).unwrap();
    std::fs::write(&key_path, &key).unwrap();
    let config = CONFIG
        .replace("{cert}", &cert_path.display().to_string())
        .replace("{key}", &key_path.display().to_string())
        .replace("{upstream}", &ws.to_string());
    let (port, _rt, sd) = start(&config, Some(true)).await;

    let mut client = h3_connect(port, &cert).await;
    // extended CONNECT: CONNECT + :protocol=websocket (+ ws fields as
    // ordinary headers — deliberately omit key/version: the proxy must
    // synthesize them for the h1 upstream)
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://example.test:{port}/echo"))
        .header("sec-websocket-protocol", "chat")
        .header("origin", "https://example.test")
        .body(())
        .unwrap();
    let mut req = req;
    req.extensions_mut().insert(h3::ext::Protocol::WEBSOCKET);
    let mut stream = client.send.send_request(req).await.expect("ext-CONNECT");
    // no finish(): the stream body IS the tunnel — closing it would end
    // the client→upstream direction immediately
    let resp = stream.recv_response().await.expect("recv_response");
    // RFC 9220: success is 2xx, not 101
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("chat"),
        "upstream's subprotocol pick must reach the client"
    );

    // DATA frames are the ws byte stream — echo proves both directions
    stream
        .send_data(bytes::Bytes::from_static(b"ping-123"))
        .await
        .expect("tunnel send");
    use bytes::Buf;
    let mut got = bytes::BytesMut::new();
    while got.len() < 8 {
        match stream.recv_data().await.expect("tunnel recv") {
            Some(mut chunk) => {
                let n = chunk.remaining();
                got.extend_from_slice(&chunk.copy_to_bytes(n)[..]);
            }
            None => break,
        }
    }
    assert_eq!(&got[..8], b"ping-123");
    sd.send(true).unwrap();
}

/// The full chain in both directions: classic `Upgrade` client →
/// verd (h1) → `h3://` upstream → verd (h3 listener) → classic h1 WS
/// upstream. The front proxy translates classic↔RFC 9220; the backend
/// proxy translates RFC 9220↔classic again.
#[tokio::test]
async fn classic_websocket_over_h3_upstream() {
    let ws = ws_echo_upstream().await;
    let dir = tempfile::tempdir().unwrap();

    // backend: h3 listener, /chat proxies to the h1 ws echo
    let (bcert, bkey) = verd::tls::selfsigned::generate_pems(&["127.0.0.1".into()]);
    let bcert_path = dir.path().join("b-cert.pem");
    let bkey_path = dir.path().join("b-key.pem");
    std::fs::write(&bcert_path, &bcert).unwrap();
    std::fs::write(&bkey_path, &bkey).unwrap();
    let backend_cfg = r#"
[[site]]
hosts = ["127.0.0.1"]
tls = { cert = "{cert}", key = "{key}" }

[[site.route]]
prefix = "/"
proxy = "up"

[upstream.up]
servers = ["http://127.0.0.1:{ws}"]
"#
    .replace("{cert}", &bcert_path.display().to_string())
    .replace("{key}", &bkey_path.display().to_string())
    .replace("{ws}", &ws.to_string());
    let (bport, _brt, bsd) = start(&backend_cfg, Some(true)).await;

    // front: TCP TLS listener, upstream h3://
    let (fcert, fkey) = verd::tls::selfsigned::generate_pems(&["front.test".into()]);
    let fcert_path = dir.path().join("f-cert.pem");
    let fkey_path = dir.path().join("f-key.pem");
    std::fs::write(&fcert_path, &fcert).unwrap();
    std::fs::write(&fkey_path, &fkey).unwrap();
    let front_cfg = FRONT_H3_UP
        .replace("{cert}", &fcert_path.display().to_string())
        .replace("{key}", &fkey_path.display().to_string())
        .replace("{backend}", &bport.to_string());
    let (fport, _frt, fsd) = start(&front_cfg, None).await;

    // classic h1 WebSocket client on a raw socket
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates({
            let mut roots = rustls::RootCertStore::empty();
            for der in rustls::pki_types::CertificateDer::pem_slice_iter(fcert.as_bytes()) {
                roots.add(der.unwrap()).unwrap();
            }
            roots
        })
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
    let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{fport}"))
        .await
        .unwrap();
    let mut s = connector
        .connect(
            rustls::pki_types::ServerName::try_from("front.test").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    s.write_all(
        b"GET /chat HTTP/1.1\r\n\
          host: front.test\r\n\
          connection: upgrade\r\n\
          upgrade: websocket\r\n\
          sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          sec-websocket-version: 13\r\n\
          sec-websocket-protocol: chat\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 8192];
    let mut used = 0;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = s.read(&mut buf[used..]).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            used += n;
            if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await;
    let head = String::from_utf8_lossy(&buf[..used]).to_lowercase();
    assert!(
        head.starts_with("http/1.1 101"),
        "expected 101, got: {head}"
    );
    assert!(head.contains("upgrade: websocket"), "{head}");
    assert!(head.contains("sec-websocket-accept:"), "{head}");
    // echo check on the upgraded socket
    let mut rest = buf[..used].to_vec();
    if let Some(p) = rest.windows(4).position(|w| w == b"\r\n\r\n") {
        rest.drain(..p + 4);
    }
    s.write_all(b"echo-456").await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 1024];
        while got.len() < 8 {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    let mut echoed = rest;
    echoed.extend_from_slice(&got);
    assert!(
        echoed.windows(8).any(|w| w == b"echo-456"),
        "tunnel echo missing: {echoed:?}"
    );
    fsd.send(true).unwrap();
    bsd.send(true).unwrap();
}

#[tokio::test]
async fn no_quic_when_http3_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = verd::tls::selfsigned::generate_pems(&["example.test".into()]);
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &cert).unwrap();
    std::fs::write(&key_path, &key).unwrap();
    let config = CONFIG
        .replace("{cert}", &cert_path.display().to_string())
        .replace("{key}", &key_path.display().to_string())
        .replace("{upstream}", "1");
    // TLS listener, no http3 — TCP serves fine, UDP is silent
    let (port, _rt, sd) = start(&config, None).await;

    let mut roots = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_slice_iter(cert.as_bytes()) {
        roots.add(der.unwrap()).unwrap();
    }
    let mut cc = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cc.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(cc).unwrap();
    let mut transport = quinn::TransportConfig::default();
    // don't wait the default ~10s idle timeout to prove silence
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(1500).into()));
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(crypto));
    client_cfg.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_cfg);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        endpoint.connect(addr, "example.test").unwrap(),
    )
    .await;
    match result {
        Err(_) => {}     // timed out waiting — nothing is listening on UDP
        Ok(Err(_)) => {} // handshake died early — same conclusion
        Ok(Ok(_)) => panic!("QUIC handshake succeeded with http3 disabled"),
    }
    sd.send(true).unwrap();
}
