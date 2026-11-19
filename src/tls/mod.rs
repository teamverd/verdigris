//! Inbound TLS: certificate resolution (SNI → site cert), PEM loading with
//! hot reload, self-signed generation and the acceptor construction.
//! Upstream (client-side) TLS lives in `proxy::cluster`; ACME lands in P8
//! and plugs into the same [`CertResolver`].

pub mod manual;
pub mod resolver;
pub mod selfsigned;

use std::sync::Arc;

use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::model as cfg;
use crate::tls::manual::WatchEntry;
use crate::tls::resolver::CertResolver;

/// TLS state for one config generation: the acceptor handed to connection
/// tasks plus the resolver the cert watcher updates in place.
pub struct TlsRuntime {
    /// Per-connection acceptor (ALPN: h2, http/1.1).
    pub acceptor: TlsAcceptor,
    /// SNI → cert map; shared with the hot-reload watcher.
    pub resolver: Arc<CertResolver>,
    /// Cert files watched for in-place reload.
    pub watch: Vec<WatchEntry>,
    /// QUIC server config for HTTP/3 listeners — a second rustls
    /// `ServerConfig` over the *same* resolver (ALPN `h3`), so SNI,
    /// cert hot-reload, self-signed and ACME certs apply identically.
    /// `Some` when any listener resolves `http3`.
    pub quic: Option<Arc<quinn::ServerConfig>>,
}

impl TlsRuntime {
    /// Build certificates for every site that needs them:
    /// `manual` → load PEMs (+watch), `selfsigned` → generate, `auto` →
    /// deferred to the ACME phase (nothing is inserted yet). Returns `None`
    /// when no TLS listeners exist. `mode` [`crate::BuildMode::Check`]
    /// parses cert files that exist but skips missing ones — the
    /// validator already warns about those, and certs may live on the
    /// deploy host rather than the validation environment.
    pub fn build(config: &cfg::Config, mode: crate::BuildMode) -> Result<Option<Self>, String> {
        if !config.server.listen.iter().any(|l| l.tls) {
            return Ok(None);
        }
        let resolver = Arc::new(CertResolver::default());
        let mut watch = Vec::new();
        let mut default_hosts: Option<Vec<String>> = None;

        for site in &config.site {
            let hosts = &site.hosts;
            match &site.tls {
                cfg::SiteTls::Manual(m) if !mode.live() => {
                    manual::check_pair(m).map_err(|e| {
                        format!("site {:?}: {e}", site.name.as_deref().unwrap_or("?"))
                    })?;
                }
                cfg::SiteTls::Manual(m) => {
                    let key = manual::load_pair(m).map_err(|e| {
                        format!("site {:?}: {e}", site.name.as_deref().unwrap_or("?"))
                    })?;
                    resolver.insert(hosts, key);
                    watch.push(WatchEntry {
                        cert: m.cert.clone(),
                        key: m.key.clone(),
                        hosts: hosts.clone(),
                    });
                    if site.default {
                        default_hosts = Some(hosts.clone());
                    }
                }
                cfg::SiteTls::Mode(cfg::TlsMode::SelfSigned) => {
                    let key = selfsigned::generate(hosts).map_err(|e| {
                        format!("site {:?}: {e}", site.name.as_deref().unwrap_or("?"))
                    })?;
                    resolver.insert(hosts, key);
                    if site.default {
                        default_hosts = Some(hosts.clone());
                    }
                }
                cfg::SiteTls::Mode(cfg::TlsMode::Auto) => {
                    // P8: the ACME issuer will insert certs dynamically;
                    // handshakes for these hosts fail until then.
                    tracing::debug!(
                        site = site.name.as_deref().unwrap_or("?"),
                        "tls = \"auto\": certificate pending ACME issuance"
                    );
                }
                cfg::SiteTls::Mode(cfg::TlsMode::Off) => {}
            }
        }

        // The default site's cert answers no-SNI clients when present.
        if let Some(hosts) = default_hosts
            && let Some(first) = hosts.first()
            && let Some(k) = resolver.lookup(first)
        {
            resolver.set_default(k);
        }

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        // `acme-tls/1` so TLS-ALPN-01 challenge handshakes negotiate ALPN
        // and reach the resolver's challenge-cert branch; without a
        // pending challenge there's nothing to resolve and the handshake
        // still aborts.
        server_config.alpn_protocols = vec![
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
            crate::acme::challenge::ACME_TLS_ALPN.to_vec(),
        ];

        // QUIC needs its own `ServerConfig` (ALPN `h3` — TLS-ALPN-01 is
        // TCP-only, h2/http1.1 don't exist over QUIC) but the *same*
        // resolver: SNI, hot-reload, self-signed and ACME-issued certs
        // then apply to QUIC handshakes identically. `max_early_data_size`
        // stays at the rustls default 0 — no 0-RTT (replay risk for a
        // server that proxies non-idempotent requests).
        let quic = if config
            .server
            .listen
            .iter()
            .any(|l| l.http3_enabled(config.server.http3))
        {
            let mut qcfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver.clone());
            qcfg.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(qcfg)
                .map_err(|e| format!("quic server config: {e}"))?;
            let mut sc = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            let mut transport = quinn::TransportConfig::default();
            // parity with the h2 `max_concurrent_streams(200)` hardening
            transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(200));
            if !config.timeouts.idle.is_zero() {
                transport.max_idle_timeout(Some(
                    quinn::VarInt::from_u32(
                        u32::try_from(config.timeouts.idle.as_millis()).unwrap_or(u32::MAX),
                    )
                    .into(),
                ));
            }
            sc.transport_config(Arc::new(transport));
            Some(Arc::new(sc))
        } else {
            None
        };

        Ok(Some(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            resolver,
            watch,
            quic,
        }))
    }

    /// Arm the certificate hot-reload watcher; stops with the runtime.
    pub fn spawn_watcher(self: &Arc<Self>, stop: CancellationToken) {
        manual::spawn_watcher(Arc::downgrade(&self.resolver), self.watch.clone(), stop);
    }
}
