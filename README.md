# wifi-scan

**ARP-based local Wi-Fi device discovery with ICMP fallback**

> **Author:** Ankush Cybersecurity Developer V  
> **License:** MIT

---

## ⚠️ Legal Notice

**Use `wifi-scan` only on networks and devices that you own or have explicit written permission to scan.  
Unauthorized scanning may violate local laws and regulations (e.g., Computer Fraud and Abuse Act, GDPR, etc.).  
The author accepts no liability for misuse.**

---

## Description

`wifi-scan` is a lightweight Go CLI tool that discovers devices on your local network.  
It first attempts an ARP-based scan (fastest, requires root/admin privileges), then falls back to an ICMP echo (ping) sweep if ARP is unavailable or returns no results.

Discovered hosts are reported with:
- **IP address**
- **MAC address** (when available via ARP or system ARP cache)
- **Hostname** (reverse DNS lookup)

Output is available in **table** (human-readable), **JSON**, and **CSV** formats.

---

## Installation

### Prerequisites

- [Go 1.21+](https://golang.org/dl/)

### Build from source

```bash
git clone https://github.com/ahirankush771/wifi-scan.git
cd wifi-scan
go build -o wifi-scan ./cmd/wifi-scan
```

### Install globally

```bash
go install github.com/ahirankush771/wifi-scan/cmd/wifi-scan@latest
```

---

## Usage

```
wifi-scan [flags]

Flags:
  -i, --interface string     network interface to use (default: auto-detect)
  -r, --range     string     CIDR range to scan (default: auto-detect subnet of selected interface)
  -o, --output    string     output format: table (default), json, csv
  -w, --workers   int        concurrency for ICMP/ping fallback (default: 100)
  -t, --timeout   duration   per-host timeout (default: 500ms)
  -v, --verbose              verbose logging
      --version              print version and exit
```

### Examples

```bash
# Auto-detect interface and subnet, print table
sudo wifi-scan

# Scan a specific interface, output as JSON
sudo wifi-scan -i eth0 -o json

# Scan a custom CIDR range, output as CSV
sudo wifi-scan -r 192.168.1.0/24 -o csv

# Verbose scan with longer timeout and fewer workers
sudo wifi-scan -i wlan0 -t 1s -w 50 -v

# Print version
wifi-scan --version
```

> **Note:** ARP-based discovery requires **root** (Linux/macOS) or **Administrator** (Windows) privileges.  
> If run without elevated privileges, the tool automatically falls back to ICMP ping sweep.

---

## Output Formats

### Table (default)

```
IP                 MAC                  HOSTNAME
------------------------------------------------------------
192.168.1.1        aa:bb:cc:dd:ee:ff    router.local
192.168.1.42       11:22:33:44:55:66    my-laptop.local
192.168.1.100      -                    -

Total: 3 host(s) discovered.
```

### JSON (`-o json`)

```json
[
  {
    "ip": "192.168.1.1",
    "mac": "aa:bb:cc:dd:ee:ff",
    "hostname": "router.local"
  },
  {
    "ip": "192.168.1.42",
    "mac": "11:22:33:44:55:66",
    "hostname": "my-laptop.local"
  }
]
```

### CSV (`-o csv`)

```
ip,mac,hostname
192.168.1.1,aa:bb:cc:dd:ee:ff,router.local
192.168.1.42,11:22:33:44:55:66,my-laptop.local
192.168.1.100,,
```

---

## How It Works

1. **Interface & subnet detection:** Auto-detects a suitable network interface and its IPv4 subnet, or uses values provided via `-i` and `-r`.
2. **ARP sweep:** Sends ARP `who-has` requests to every host in the subnet and listens for `ARP reply` packets to collect IP-MAC pairs. This is fast and accurate but requires elevated privileges.
3. **ICMP fallback:** If ARP is unavailable (permission denied) or returns no results, performs a concurrent ICMP echo (ping) sweep using `golang.org/x/net/icmp`. Responds with alive hosts and attempts to look up MAC addresses from the OS ARP cache (`/proc/net/arp` on Linux).
4. **Reverse DNS:** Attempts a reverse DNS lookup for each discovered host.
5. **Output:** Formats and prints results in the requested format.

---

## Building for Different Platforms

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o wifi-scan-linux ./cmd/wifi-scan

# macOS
GOOS=darwin GOARCH=amd64 go build -o wifi-scan-macos ./cmd/wifi-scan

# Windows
GOOS=windows GOARCH=amd64 go build -o wifi-scan.exe ./cmd/wifi-scan
```

---

## Author

**Ankush Cybersecurity Developer V**  
GitHub: [ahirankush771](https://github.com/ahirankush771)

---

## License

This project is licensed under the [MIT License](LICENSE).
