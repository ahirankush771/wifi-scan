# wifi-scan

**wifi-scan** — local Wi‑Fi device discovery tool (ARP + ICMP fallback)

> **Author: Ankush Cybersecurity Developer V**

Discover all devices connected to your local Wi‑Fi network. The tool first performs a fast ARP sweep; if ARP is unavailable (e.g., due to OS permissions), it automatically falls back to a concurrent ICMP (ping) sweep.

---

## Features

- **ARP-based discovery** — fast, gets MAC addresses directly
- **ICMP fallback** — works when ARP is unavailable
- **Multiple output formats**: pretty table, JSON, CSV
- **Auto-detects** the active network interface and subnet
- Configurable concurrency, timeout, and output options

---

## Installation

**Using `go install`:**
```bash
go install github.com/ahirankush771/wifi-scan/cmd/wifi-scan@latest
```

**Build from source:**
```bash
git clone https://github.com/ahirankush771/wifi-scan.git
cd wifi-scan
go build -o wifi-scan ./cmd/wifi-scan
```

---

## Usage

```
wifi-scan [flags]

Flags:
  -i, --interface string    Network interface to use (default: auto-detect)
  -r, --range    string     CIDR range to scan (default: auto-detect from interface)
  -o, --output   string     Output format: table, json, csv (default: table)
  -w, --workers  int        Concurrency for ICMP ping fallback (default: 100)
  -t, --timeout  duration   Per-host timeout (default: 500ms)
  -v, --verbose             Verbose logging
      --version             Print version and exit
```

### Examples

Auto-detect interface and scan:
```bash
wifi-scan
```

Scan a specific interface with JSON output:
```bash
wifi-scan --interface wlan0 --output json
```

Scan a specific CIDR range and save as CSV:
```bash
wifi-scan --range 192.168.1.0/24 --output csv > devices.csv
```

Verbose mode with custom timeout:
```bash
wifi-scan --verbose --timeout 1s
```

---

## Permissions

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| ARP sweep | `sudo` or `CAP_NET_RAW` | `sudo` | Run as Administrator |
| ICMP sweep | `sudo` or `CAP_NET_RAW` | `sudo` | Run as Administrator |

On Linux, you can grant the binary raw socket access without running as root:
```bash
sudo setcap cap_net_raw+ep ./wifi-scan
```

---

## Security & Legal Notice

> **You must have authorization to scan any network.** Only use this tool on networks and devices you own or have explicit written permission to test. Unauthorized network scanning may be illegal in your jurisdiction and could violate computer fraud and abuse laws.
>
> **The user has confirmed:** "Haan, main sirf apne khud ke network aur devices par hi use karunga." (I will only use this on my own networks and devices.)

The author and contributors of this tool assume no responsibility for misuse.

---

## License

[MIT](LICENSE)

---

## Author

**Ankush Cybersecurity Developer V**
