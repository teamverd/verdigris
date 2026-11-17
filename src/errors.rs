//! Shared error types.

/// A boxed error usable across the async data plane.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A fix hint for the usual `bind(2)` failures — one text shared by the
/// server and admin listeners so both report the same remediation.
pub fn bind_hint(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::AddrInUse => {
            "address already in use — is another process (or verd instance) already listening on this port?"
        }
        std::io::ErrorKind::PermissionDenied => {
            "permission denied — ports below 1024 need root or CAP_NET_BIND_SERVICE"
        }
        std::io::ErrorKind::AddrNotAvailable => {
            "address not available — the IP is not assigned to a local interface"
        }
        _ => "check the address is a local interface and the port is free",
    }
}
