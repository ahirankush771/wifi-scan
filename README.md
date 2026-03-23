# wifi-scan

**wifi-scan** is a Go-based CLI tool for local Wi-Fi device discovery. It uses ARP-based scanning with an ICMP echo fallback to enumerate all connected devices on your local network and report their IP addresses, MAC addresses, and hostnames.

**Author: Ankush Cybersecurity Developer V**

---

## Features

- ARP-based host discovery (fast, retrieves IP + MAC)
- ICMP echo fallback for hosts not responding to ARP
- Hostname resolution for discovered devices
- Output formats: table (default), JSON, CSV
- Configurable concurrency, timeout, and network interface
- Works on Linux and macOS (requires root/CAP_NET_RAW for raw socket access)

---

## Installation

### Prerequisites

- [Go 1.20+](https://golang.org/dl/)

### Build from source

```bash
git clone https://github.com/ahirankush771/wifi-scan.git
cd wifi-scan
go build -o bin/wifi-scan ./cmd/wifi-scan
```

### Run directly

```bash
go run ./cmd/wifi-scan [flags]
```

---

## Usage

```
wifi-scan [flags]

Flags:
  -i, --interface string   Network interface to use (e.g. eth0, wlan0)
  -r, --range string       IP range in CIDR notation (e.g. 192.168.1.0/24)
  -o, --output string      Output format: table, json, csv (default "table")
  -w, --workers int        Number of concurrent workers (default 50)
  -t, --timeout duration   Timeout per host probe (default 500ms)
  -v, --verbose            Enable verbose logging
      --version            Print version and exit
```

---

## Examples

**Scan default interface (auto-detected):**
```bash
sudo wifi-scan
```

**Scan a specific interface:**
```bash
sudo wifi-scan -i wlan0
```

**Scan a custom IP range:**
```bash
sudo wifi-scan -r 192.168.0.0/24
```

**Output as JSON:**
```bash
sudo wifi-scan -i eth0 -o json
```

**Output as CSV:**
```bash
sudo wifi-scan -r 10.0.0.0/24 -o csv > results.csv
```

**Verbose mode with custom timeout and workers:**
```bash
sudo wifi-scan -i wlan0 -w 100 -t 1s -v
```

**Print version:**
```bash
wifi-scan --version
```

---

## Sample Output

```
IP ADDRESS         MAC ADDRESS          HOSTNAME
------------------------------------------------------------
192.168.1.1        aa:bb:cc:dd:ee:ff    router.local
192.168.1.5        11:22:33:44:55:66    laptop.local
192.168.1.12       (unknown)            (unknown)

Total: 3 device(s) discovered
```

---

## Security Notice

> ⚠️ **Important:** Use this tool only on networks and devices that you own or have **explicit written authorization** to scan. Unauthorized network scanning may violate computer crime laws in your jurisdiction (e.g., CFAA in the US, Computer Misuse Act in the UK).
>
> The author and contributors assume **no liability** for misuse of this tool.

**I, Ankush Cybersecurity Developer V, confirm that this tool is intended solely for authorized security testing and network administration on networks I own or have explicit permission to scan.**

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/mdlayher/arp` | ARP-based host discovery |
| `github.com/mdlayher/ethernet` | Ethernet frame handling |
| `golang.org/x/net/icmp` | ICMP echo fallback |
| `golang.org/x/net/ipv4` | IPv4 packet control |

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Author

**Ankush Cybersecurity Developer V**  
GitHub: [ahirankush771](https://github.com/ahirankush771)
