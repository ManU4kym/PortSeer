use futures::future::join_all;
use tokio::process::Command;

pub async fn scan_subnet(subnet_base: &str, start: u8, end: u8) -> Vec<String> {
    let mut tasks = vec![];

    for i in start..=end {
        let ip = format!("{}.{}", subnet_base, i);
        tasks.push(tokio::spawn(async move {
            let is_alive = ping(&ip).await;
            if is_alive { Some(ip) } else { None }
        }));
    }

    let results = join_all(tasks).await;
    results
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect()
}

async fn ping(ip: &str) -> bool {
    #[cfg(target_os = "windows")]
    let output = Command::new("ping")
        .args(["-n", "1", "-w", "100", ip])
        .output()
        .await;

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "1", ip])
        .output()
        .await;

    output.map(|o| o.status.success()).unwrap_or(false)
}
