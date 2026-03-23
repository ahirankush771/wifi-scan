# wifi-scan

**wifi-scan** is a fast, lightweight command-line tool for discovering devices on your local Wi-Fi network. It uses ARP-based host discovery with an automatic ICMP (ping) fallback, and reports each device's IP address, MAC address, and hostname.

---

## Features

- **ARP sweep** — fast Layer-2 discovery (requires root/administrator privileges)
- **ICMP fallback** — ping-based sweep when ARP is unavailable
- **Reverse-DNS lookup** — resolves hostnames for each discovered device
- **Multiple output formats** — pretty table, JSON, and CSV
- **Configurable concurrency and timeout** — tune performance for your network
- **Auto-detection** — automatically selects the network interface and subnet

---

## Installation

> Requires [Go 1.20+](https://go.dev/dl/).

```bash
go install github.com/ahirankush771/wifi-scan/cmd/wifi-scan@latest
```

Or build from source:

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
  -i string       network interface to use (default: auto-detect)
  -r string       CIDR range to scan (default: auto-detect subnet)
  -o string       output format: table (default), json, csv
  -w int          concurrency for ICMP/ping fallback (default: 100)
  -t duration     per-host timeout (default: 500ms)
  -v              verbose logging
  --version       print version and author credit
```

**ARP scan requires root/administrator privileges.** If the tool is not run as root, it automatically falls back to ICMP.

---

## Examples

### Default (table output, auto-detect interface)

```bash
sudo wifi-scan
```

```
IP              MAC                HOSTNAME
--              ---                --------
192.168.1.1     aa:bb:cc:dd:ee:ff  router.local
192.168.1.42    11:22:33:44:55:66  my-laptop.local
192.168.1.100   -                  -

3 host(s) found.
```

### JSON output

```bash
sudo wifi-scan -o json
```

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

### CSV output

```bash
sudo wifi-scan -o csv
```

```
ip,mac,hostname
192.168.1.1,aa:bb:cc:dd:ee:ff,router.local
192.168.1.42,11:22:33:44:55:66,my-laptop.local
192.168.1.100,,
```

### Specify interface and CIDR range

```bash
sudo wifi-scan -i eth0 -r 10.0.0.0/24
```

### ICMP-only sweep (no root required on some systems)

```bash
wifi-scan -r 192.168.1.0/24 -w 50 -t 1s
```

### Print version

```bash
wifi-scan --version
```

---

## Output Formats

| Format  | Description                              |
|---------|------------------------------------------|
| `table` | Human-readable aligned table (default)  |
| `json`  | JSON array of host objects               |
| `csv`   | Comma-separated values with header row   |

Each host record contains:

| Field      | Description                                     |
|------------|-------------------------------------------------|
| `ip`       | IPv4 address of the discovered device           |
| `mac`      | MAC (hardware) address — available via ARP only |
| `hostname` | Reverse-DNS hostname (if resolvable)            |

---

## Permissions

| Scan method | Privilege required          |
|-------------|-----------------------------|
| ARP sweep   | Root / Administrator        |
| ICMP sweep  | Root on Linux; may vary on macOS/Windows |

---

## ⚠️ Security & Legal Notice

> **Use this tool only on networks and devices you own or have explicit written authorization to scan.**
>
> Unauthorized network scanning may violate computer-fraud and abuse laws in your jurisdiction. The author and contributors accept no liability for misuse of this tool.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author

**Ankush Cybersecurity Developer V**
