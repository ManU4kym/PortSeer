````md

# PortSeer

PortSeer is a fast, async network scanning tool built in Rust. It detects open ports, fingerprints services via banners and HTTP headers, analyzes TLS certificates, and even finds devices on your local subnet. It also generates clean reports in both JSON and HTML.

---

## 🚀 Features

- ✅ Async port scanning (`tokio`)
- 🌐 HTTP Server detection via `GET /`
- 🔐 TLS Certificate details (CN, Issuer, Expiry)
- 📡 Local subnet scanner (pings devices in LAN)
- 📄 Output:
  - `report.json` – structured scan data
  - `report.html` – sleek HTML dashboard
  - `devices.json` – discovered devices on LAN



## 🛠️ Installation

```bash
git clone https://github.com/yourusername/portseer.git
cd portseer
cargo build --release


---

## 📦 Usage

```bash
cargo run --release -- <target>
```

**Examples:**

```bash
cargo run --release -- google.com
cargo run --release -- 192.168.1.1
```

---

## 📁 Output Files

* `report.json`: Full scan results with banners, HTTP headers, and TLS certs.
* `report.html`: Visual scan dashboard.
* `devices.json`: Local subnet live devices (only for LAN targets).

---

## 📚 Modules Breakdown

| Module          | Description                                    |
| --------------- | ---------------------------------------------- |
| `scanner.rs`    | Async TCP port scanner                         |
| `http_probe.rs` | Sends HTTP GET / to extract Server headers     |
| `tls_probe.rs`  | Connects using TLS and parses certificate data |
| `ping_flash.rs` | Pings local subnet for active devices (1–254)  |
| `mod.rs`        | Central mod file re-exporting the rest         |

---

## 🤓 Why Rust?

Beacause I don't like my life
