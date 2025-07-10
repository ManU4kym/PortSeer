use reqwest::Client;
use std::time::Duration;

pub async fn probe_http(ip: &str, port: u16) -> Option<(u16, Option<String>)> {
    let url = format!("http://{}:{}/", ip, port);
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .danger_accept_invalid_certs(true) // for self-signed servers
        .build()
        .ok()?;

    match client.get(&url).send().await {
        Ok(resp) => {
            let server = resp
                .headers()
                .get("Server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            Some((port, server))
        }
        Err(_) => None,
    }
}
