use native_tls::TlsConnector;
use std::net::TcpStream;
use std::time::Duration;
use x509_parser::parse_x509_certificate;

/// ip: the resolved IP (e.g. "104.21.39.152")
/// port: usually 443
/// domain: original domain name (e.g. "mannykimani.com") — used for SNI
pub async fn fetch_tls_info(ip: &str, port: u16, domain: &str) -> Option<(String, String, String)> {
    let ip = ip.to_string();
    let domain = domain.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", ip, port);

        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .ok()?;

        let stream =
            TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(3)).ok()?;

        // ✅ Use `domain` here for proper SNI-based TLS handshake
        let tls_stream = connector.connect(&domain, stream).ok()?;

        let cert = tls_stream.peer_certificate().ok().and_then(|c| c)?;

        let parsed = cert.to_der().ok()?;
        let cert = parse_x509_certificate(&parsed).ok()?.1;

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("Unknown CN")
            .to_string();

        let issuer = cert
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("Unknown Issuer")
            .to_string();

        let expiry = cert.validity().not_after.to_string();

        Some((cn, issuer, expiry))
    })
    .await
    .ok()
    .flatten()
}
