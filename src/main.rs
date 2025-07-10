mod modules;

use modules::http_probe::probe_http;
use modules::ping_flash::scan_subnet;
use modules::scanner::scan_port;
use modules::tls_probe::fetch_tls_info;
use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::task;

#[derive(Serialize)]
struct ReportEntry {
    ip: String,
    port: u16,
    banner: Option<String>,
    server: Option<String>,
    tls_cn: Option<String>,
    tls_issuer: Option<String>,
    tls_expiry: Option<String>,
}

fn resolve_all_addrs(domain: &str) -> Vec<SocketAddr> {
    (domain, 0)
        .to_socket_addrs()
        .map(|iter| iter.collect::<Vec<_>>())
        .unwrap_or_default()
}

#[tokio::main]

async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <domain or IP>", args[0]);
        std::process::exit(1);
    }

    let target = args[1].clone();
    let mut alive_devices: Vec<String> = vec![];

    if target.starts_with("192.") || target.starts_with("10.") || target.starts_with("172.") {
        println!("\n🔍 Scanning local subnet for live devices...");

        let parts: Vec<&str> = target.split('.').collect();
        if parts.len() == 4 {
            let subnet = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
            alive_devices = scan_subnet(&subnet, 1, 254).await;

            println!("🟢 Found {} live devices:", alive_devices.len());
            for ip in &alive_devices {
                println!("→ {}", ip);
            }

            // Export to devices.json
            let json = serde_json::to_string_pretty(&alive_devices).unwrap();
            let mut file = File::create("devices.json").expect("Cannot create devices.json");
            file.write_all(json.as_bytes())
                .expect("Failed to write devices.json");
            println!("📁 Saved live devices to devices.json");
        }
    }

    let addresses = resolve_all_addrs(&target);

    if addresses.is_empty() {
        eprintln!("❌ Could not resolve any address for {}", target);
        std::process::exit(1);
    }

    println!("🌐 Resolved {} to:", target);
    for addr in &addresses {
        println!("→ {}", addr);
    }

    let mut report: Vec<ReportEntry> = vec![];

    for addr in addresses {
        println!("\n🔍 Scanning {} ...", addr);

        let mut handles = vec![];
        let ip = addr.ip().to_string();

        for port in 1..=1024 {
            let ip = ip.clone();
            let domain = target.clone();
            handles.push(task::spawn(async move {
                if let Some(result) = scan_port(&ip, port).await {
                    let http = probe_http(&ip, port).await;

                    let tls_info = if [443, 8443, 9443].contains(&port) {
                        fetch_tls_info(&ip, port, &domain).await
                    } else {
                        None
                    };

                    if let Some((cn, issuer, expiry)) = &tls_info {
                        println!(
                            "🔒 TLS @ {}:{} — CN: {}, Issuer: {}, Expires: {}",
                            ip, port, cn, issuer, expiry
                        );
                    }

                    return Some(ReportEntry {
                        ip,
                        port: result.port,
                        banner: result.banner,
                        server: http.and_then(|(_, s)| s),
                        tls_cn: tls_info.as_ref().map(|(cn, _, _)| cn.clone()),
                        tls_issuer: tls_info.as_ref().map(|(_, issuer, _)| issuer.clone()),
                        tls_expiry: tls_info.as_ref().map(|(_, _, expiry)| expiry.clone()),
                    });
                }
                None
            }));
        }
        for device_ip in &alive_devices {
            println!("\n📡 Scanning live device: {} ...", device_ip);

            let mut handles = vec![];

            for port in 1..=1024 {
                let ip = device_ip.clone();
                let domain = ip.clone();
                handles.push(task::spawn(async move {
                    if let Some(result) = scan_port(&ip, port).await {
                        let http = probe_http(&ip, port).await;
                        let tls_info = if [443, 8443, 9443].contains(&port) {
                            fetch_tls_info(&ip, port, &domain).await
                        } else {
                            None
                        };

                        return Some(ReportEntry {
                            ip,
                            port: result.port,
                            banner: result.banner,
                            server: http.and_then(|(_, s)| s),
                            tls_cn: tls_info.as_ref().map(|(cn, _, _)| cn.clone()),
                            tls_issuer: tls_info.as_ref().map(|(_, issuer, _)| issuer.clone()),
                            tls_expiry: tls_info.as_ref().map(|(_, _, expiry)| expiry.clone()),
                        });
                    }
                    None
                }));
            }

            for handle in handles {
                if let Ok(Some(entry)) = handle.await {
                    println!(
                        "✅ Port {} is open{}{}",
                        entry.port,
                        entry
                            .banner
                            .as_ref()
                            .map(|b| format!(" — Banner: {}", b.trim()))
                            .unwrap_or_default(),
                        entry
                            .server
                            .as_ref()
                            .map(|s| format!(" — Server Header: {}", s.trim()))
                            .unwrap_or_default()
                    );

                    report.push(entry);
                }
            }
        }

        for handle in handles {
            if let Ok(Some(entry)) = handle.await {
                println!(
                    "✅ Port {} is open{}{}",
                    entry.port,
                    entry
                        .banner
                        .as_ref()
                        .map(|b| format!(" — Banner: {}", b.trim()))
                        .unwrap_or_default(),
                    entry
                        .server
                        .as_ref()
                        .map(|s| format!(" — Server Header: {}", s.trim()))
                        .unwrap_or_default()
                );

                report.push(entry);
            }
        }
    }

    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            std::fs::write("report.json", json).expect("Failed to write report.json");
            println!("\n📄 Report saved to report.json");
        }
        Err(e) => eprintln!("❌ Failed to serialize report: {}", e),
    }
    save_html_report(&report);
}

fn save_html_report(entries: &[ReportEntry]) {
    use std::collections::HashMap;

    let mut html = String::from(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Network Scan Report</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; padding: 2rem; }
            h1 { color: #64ffda; }
            .device { margin: 2rem 0; padding: 1rem; background: #1e1e1e; border-radius: 8px; }
            .port { margin: 0.5rem 0; padding: 0.5rem; background: #2c2c2c; border-radius: 6px; }
            .tls { font-size: 0.9em; color: #ffd166; }
            .server { color: #82aaff; }
        </style>
    </head>
    <body>
        <h1>📡 Network Scan Report</h1>
    "#,
    );

    let mut grouped: HashMap<&str, Vec<&ReportEntry>> = HashMap::new();
    for entry in entries {
        grouped.entry(&entry.ip).or_default().push(entry);
    }

    for (ip, ports) in grouped {
        html += &format!(r#"<div class="device"><h2>🔹 {}</h2>"#, ip);
        for entry in ports {
            html += &format!(r#"<div class="port"><strong>Port {}</strong>"#, entry.port);
            if let Some(server) = &entry.server {
                html += &format!(r#"<div class="server">Server: {}</div>"#, server);
            }
            if let Some(banner) = &entry.banner {
                html += &format!(r#"<div class="server">Banner: {}</div>"#, banner);
            }
            if let Some(cn) = &entry.tls_cn {
                html += &format!(
                    r#"<div class="tls">TLS: CN: {}, Issuer: {}, Expires: {}</div>"#,
                    cn,
                    entry.tls_issuer.as_deref().unwrap_or("Unknown"),
                    entry.tls_expiry.as_deref().unwrap_or("Unknown")
                );
            }
            html += "</div>";
        }
        html += "</div>";
    }

    html += "</body></html>";

    let mut file = File::create("report.html").expect("Could not create report.html");
    file.write_all(html.as_bytes())
        .expect("Failed to write HTML report");
    println!("📄 HTML report saved to report.html");
}
