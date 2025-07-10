// use std::io;
use std::net::SocketAddr;
use tokio::{
    net::TcpStream,
    time::{Duration, timeout},
};

pub struct ScanResult {
    pub port: u16,
    pub banner: Option<String>,
}

pub async fn scan_port(ip: &str, port: u16) -> Option<ScanResult> {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
    let duration = Duration::from_millis(300);

    match timeout(duration, TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let mut buffer = [0; 1024];
            let banner = match timeout(Duration::from_millis(200), stream.readable()).await {
                Ok(_) => match stream.try_read(&mut buffer) {
                    Ok(n) if n > 0 => Some(String::from_utf8_lossy(&buffer[..n]).to_string()),
                    _ => None,
                },
                _ => None,
            };

            Some(ScanResult { port, banner })
        }
        _ => None,
    }
}
