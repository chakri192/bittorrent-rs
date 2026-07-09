//! HTTPS tracker announce. Most public trackers today only offer
//! `https://` announce URLs (Ubuntu's included), so `http`-only support
//! isn't "complete" in practice. TLS itself is exactly the kind of thing
//! this project does NOT hand-rolled: it's provided by `rustls` (pure
//! Rust, no OpenSSL/system TLS dependency) with the `ring` crypto
//! backend. Everything *around* the TLS session -- the HTTP request
//! line, response parsing, bencode decoding -- is the same code
//! `tracker::http` uses, just handed a TLS-wrapped stream instead of a
//! bare `TcpStream`.

use super::http::{parse_authority_and_path, perform_request_and_parse, ParsedUrl};
use super::{AnnounceRequest, AnnounceResponse, TrackerError};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::net::TcpStream;
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

fn parse_https_url(url: &str) -> Result<ParsedUrl, TrackerError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| TrackerError::UnsupportedScheme(url.split("://").next().unwrap_or(url).to_string()))?;
    parse_authority_and_path(url, rest, 443)
}

/// Installs the `ring` crypto provider as rustls's process-wide default,
/// exactly once. Needed because this crate disables rustls's default
/// `aws_lc_rs` feature (heavier build requirements) in favor of `ring`.
fn ensure_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            ensure_crypto_provider();
            let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// Performs an HTTPS GET announce against `tracker_url`. Certificate
/// validation is never skipped or overridable -- rustls's API doesn't
/// offer a way to disable it, which is the point: a tracker MITM could
/// otherwise hand out arbitrary peer addresses.
pub fn announce(tracker_url: &str, req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    let url = parse_https_url(tracker_url)?;

    let server_name = ServerName::try_from(url.host.clone()).map_err(|e| TrackerError::Tls(format!("invalid hostname {:?}: {}", url.host, e)))?;
    let config = tls_client_config();
    let conn = ClientConnection::new(config, server_name).map_err(|e| TrackerError::Tls(e.to_string()))?;

    let sock = TcpStream::connect((url.host.as_str(), url.port))?;
    sock.set_read_timeout(Some(Duration::from_secs(15)))?;
    sock.set_write_timeout(Some(Duration::from_secs(15)))?;

    let mut tls_stream = StreamOwned::new(conn, sock);
    perform_request_and_parse(&mut tls_stream, &url, req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_url_default_port() {
        let u = parse_https_url("https://torrent.ubuntu.com/announce").unwrap();
        assert_eq!(u.host, "torrent.ubuntu.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path_and_query, "/announce");
    }

    #[test]
    fn parses_https_url_explicit_port() {
        let u = parse_https_url("https://tracker.example.com:8443/announce").unwrap();
        assert_eq!(u.port, 8443);
    }

    #[test]
    fn rejects_non_https_scheme() {
        assert!(matches!(parse_https_url("http://example.com/announce"), Err(TrackerError::UnsupportedScheme(_))));
    }

    #[test]
    fn tls_config_is_cached_across_calls() {
        // Not much to assert on `Arc<ClientConfig>` directly, but this at
        // least exercises the OnceLock path twice without panicking --
        // e.g. a double-install of the crypto provider would fail loudly.
        let a = tls_client_config();
        let b = tls_client_config();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
