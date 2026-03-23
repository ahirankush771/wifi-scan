// wifi-scan: ARP-based local Wi-Fi device discovery with ICMP fallback.
// Author: Ankush Cybersecurity Developer V
//
// IMPORTANT: Use this tool only on networks and devices you own or have explicit
// written permission to scan. Unauthorized scanning may violate local laws.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	version    = "1.0.0"
	authorLine = "Ankush Cybersecurity Developer V"
)

// Host represents a discovered network device.
type Host struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// flagDuration is a wrapper to support both -t and --timeout flags.
var (
	iface       string
	cidrRange   string
	outputFmt   string
	workers     int
	timeout     time.Duration
	verbose     bool
	showVersion bool
)

func init() {
	flag.StringVar(&iface, "i", "", "network interface to use (default: auto-detect)")
	flag.StringVar(&iface, "interface", "", "network interface to use (default: auto-detect)")
	flag.StringVar(&cidrRange, "r", "", "CIDR range to scan (default: auto-detect subnet of selected interface)")
	flag.StringVar(&cidrRange, "range", "", "CIDR range to scan (default: auto-detect subnet of selected interface)")
	flag.StringVar(&outputFmt, "o", "table", "output format: table, json, csv")
	flag.StringVar(&outputFmt, "output", "table", "output format: table, json, csv")
	flag.IntVar(&workers, "w", 100, "concurrency for ICMP/ping fallback")
	flag.IntVar(&workers, "workers", 100, "concurrency for ICMP/ping fallback")
	flag.DurationVar(&timeout, "t", 500*time.Millisecond, "per-host timeout")
	flag.DurationVar(&timeout, "timeout", 500*time.Millisecond, "per-host timeout")
	flag.BoolVar(&verbose, "v", false, "verbose logging")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `wifi-scan %s — ARP-based local Wi-Fi device discovery with ICMP fallback
Author: %s

LEGAL NOTICE: Use only on networks you own or have explicit written permission to scan.

Usage:
  wifi-scan [flags]

Flags:
  -i, --interface string     network interface to use (default: auto-detect)
  -r, --range     string     CIDR range to scan (default: auto-detect subnet of selected interface)
  -o, --output    string     output format: table (default), json, csv
  -w, --workers   int        concurrency for ICMP/ping fallback (default: 100)
  -t, --timeout   duration   per-host timeout (default: 500ms)
  -v, --verbose              verbose logging
      --version              print version and exit

Examples:
  wifi-scan
  wifi-scan -i eth0 -o json
  wifi-scan -r 192.168.1.0/24 -o csv
  wifi-scan -i wlan0 -t 1s -w 50 -v

NOTE: ARP discovery requires root/administrator privileges.
      On Linux, run with: sudo wifi-scan
      On Windows, run as Administrator.
`, version, authorLine)
	}
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Printf("wifi-scan %s\nAuthor: %s\n", version, authorLine)
		os.Exit(0)
	}

	logf := func(format string, a ...interface{}) {
		if verbose {
			log.Printf("[INFO] "+format, a...)
		}
	}

	// Resolve interface and subnet.
	netIface, network, err := resolveInterfaceAndNetwork(iface, cidrRange)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	logf("Using interface: %s, scanning: %s", netIface.Name, network)

	// Enumerate all host addresses in the subnet.
	hosts := hostsInNetwork(network)
	logf("Total hosts to probe: %d", len(hosts))

	var discovered []Host

	// Step 1: ARP-based discovery.
	arpHosts, arpErr := arpScan(netIface, hosts, timeout, logf)
	if arpErr != nil {
		logf("ARP scan failed (%v), falling back to ICMP sweep", arpErr)
	} else {
		discovered = arpHosts
		logf("ARP discovered %d host(s)", len(discovered))
	}

	// Step 2: ICMP fallback if ARP failed or found nothing.
	if arpErr != nil || len(discovered) == 0 {
		logf("Running ICMP sweep (workers=%d, timeout=%s)...", workers, timeout)
		icmpHosts := icmpSweep(hosts, workers, timeout, logf)
		// Merge: avoid duplicates by IP.
		seen := make(map[string]bool)
		for _, h := range discovered {
			seen[h.IP] = true
		}
		for _, h := range icmpHosts {
			if !seen[h.IP] {
				discovered = append(discovered, h)
				seen[h.IP] = true
			}
		}
		logf("After ICMP sweep: %d host(s) total", len(discovered))
	}

	// Attempt reverse DNS for each host.
	for i := range discovered {
		if names, err := net.LookupAddr(discovered[i].IP); err == nil && len(names) > 0 {
			discovered[i].Hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	// Output results.
	switch strings.ToLower(outputFmt) {
	case "json":
		if err := outputJSON(discovered); err != nil {
			log.Fatalf("JSON output error: %v", err)
		}
	case "csv":
		outputCSV(discovered)
	default:
		outputTable(discovered)
	}

	os.Exit(0)
}

// resolveInterfaceAndNetwork picks the network interface and CIDR to scan.
func resolveInterfaceAndNetwork(ifaceName, cidr string) (*net.Interface, *net.IPNet, error) {
	var netIface *net.Interface
	var err error

	if ifaceName != "" {
		netIface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
		}
	} else {
		netIface, err = autoDetectInterface()
		if err != nil {
			return nil, nil, fmt.Errorf("auto-detect interface: %w", err)
		}
	}

	if cidr != "" {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		return netIface, network, nil
	}

	// Auto-detect subnet from interface.
	addrs, err := netIface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("get addresses for %s: %w", netIface.Name, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		var network *net.IPNet
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
			network = v
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if network != nil {
				_, n, _ := net.ParseCIDR(addr.String())
				return netIface, n, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address found on interface %s", netIface.Name)
}

// autoDetectInterface returns the first non-loopback interface with an IPv4 address.
func autoDetectInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable network interface found")
}

// hostsInNetwork enumerates all usable host IPs in a /CIDR (excludes network/broadcast).
func hostsInNetwork(network *net.IPNet) []net.IP {
	var hosts []net.IP
	for ip := cloneIP(network.IP.Mask(network.Mask)); network.Contains(ip); incrementIP(ip) {
		// Skip network address and broadcast.
		if ip.Equal(network.IP) {
			continue
		}
		broadcast := broadcastIP(network)
		if ip.Equal(broadcast) {
			continue
		}
		hosts = append(hosts, cloneIP(ip))
	}
	return hosts
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func broadcastIP(network *net.IPNet) net.IP {
	broadcast := make(net.IP, len(network.IP))
	for i := range network.IP {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return broadcast
}

// arpScan sends ARP who-has requests and returns replies. Requires root/admin.
func arpScan(iface *net.Interface, targets []net.IP, perHostTimeout time.Duration, logf func(string, ...interface{})) ([]Host, error) {
	client, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("arp.Dial: %w (hint: run as root/administrator)", err)
	}
	defer client.Close()

	// Set overall deadline.
	deadline := time.Now().Add(perHostTimeout * time.Duration(len(targets)) / 10)
	if d := time.Now().Add(perHostTimeout * 3); d.Before(deadline) {
		deadline = d
	}
	if d := time.Now().Add(10 * time.Second); d.Before(deadline) {
		deadline = d
	}

	// Send ARP requests concurrently.
	go func() {
		for _, ip := range targets {
			addr, ok := netip.AddrFromSlice(ip.To4())
			if !ok {
				continue
			}
			if err := client.SetWriteDeadline(time.Now().Add(perHostTimeout)); err != nil {
				return
			}
			if err := client.Request(addr); err != nil {
				logf("ARP request to %s failed: %v", ip, err)
			}
		}
	}()

	// Collect replies until deadline.
	seen := make(map[string]Host)
	if err := client.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	for {
		pkt, _, err := client.Read()
		if err != nil {
			break
		}
		if pkt.Operation == arp.OperationReply {
			ipStr := pkt.SenderIP.String()
			mac := pkt.SenderHardwareAddr.String()
			if _, ok := seen[ipStr]; !ok {
				seen[ipStr] = Host{IP: ipStr, MAC: mac}
				logf("ARP reply: %s at %s", ipStr, mac)
			}
		}
	}

	hosts := make([]Host, 0, len(seen))
	for _, h := range seen {
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// icmpSweep performs concurrent ICMP echo requests and returns responding hosts.
func icmpSweep(targets []net.IP, numWorkers int, perHostTimeout time.Duration, logf func(string, ...interface{})) []Host {
	jobs := make(chan net.IP, len(targets))
	for _, ip := range targets {
		jobs <- ip
	}
	close(jobs)

	var mu sync.Mutex
	var found []Host

	var wg sync.WaitGroup
	if numWorkers > len(targets) {
		numWorkers = len(targets)
	}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if pingHost(ip, perHostTimeout, logf) {
					h := Host{IP: ip.String()}
					// Try to get MAC from system ARP table.
					if mac := lookupARPTable(ip.String()); mac != "" {
						h.MAC = mac
					}
					mu.Lock()
					found = append(found, h)
					mu.Unlock()
					logf("ICMP alive: %s", ip)
				}
			}
		}()
	}
	wg.Wait()
	return found
}

// pingHost sends a single ICMP echo request and waits for a reply.
func pingHost(ip net.IP, timeout time.Duration, logf func(string, ...interface{})) bool {
	// On Linux, privileged raw sockets require root; try unprivileged UDP first.
	proto := "udp4"
	if runtime.GOOS == "windows" {
		proto = "ip4:icmp"
	}

	conn, err := icmp.ListenPacket(proto, "0.0.0.0")
	if err != nil {
		// Fallback to privileged if UDP fails.
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			logf("icmp listen error: %v", err)
			return false
		}
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("wifi-scan"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	dest := &net.UDPAddr{IP: ip}
	if proto == "ip4:icmp" {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return false
		}
		if _, err := conn.WriteTo(wb, &net.IPAddr{IP: ip}); err != nil {
			return false
		}
	} else {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return false
		}
		if _, err := conn.WriteTo(wb, dest); err != nil {
			return false
		}
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return false
		}
		rm, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), rb[:n])
		if err != nil {
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			peerStr := peer.String()
			// Strip port if present (UDP mode returns "ip:port").
			if idx := strings.LastIndex(peerStr, ":"); idx != -1 {
				peerStr = peerStr[:idx]
			}
			if peerStr == ip.String() || peer.String() == ip.String() {
				return true
			}
		}
	}
}

// lookupARPTable reads the OS ARP cache for a given IP and returns its MAC.
func lookupARPTable(ip string) string {
	if runtime.GOOS == "windows" {
		return "" // Would need exec("arp -a"); skip for simplicity.
	}
	// Linux: /proc/net/arp
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ip {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	return ""
}

// --- Output formatters ---

func outputTable(hosts []Host) {
	if len(hosts) == 0 {
		fmt.Println("No hosts discovered.")
		return
	}
	fmt.Printf("%-18s %-20s %s\n", "IP", "MAC", "HOSTNAME")
	fmt.Println(strings.Repeat("-", 60))
	for _, h := range hosts {
		fmt.Printf("%-18s %-20s %s\n", h.IP, orDash(h.MAC), orDash(h.Hostname))
	}
	fmt.Printf("\nTotal: %d host(s) discovered.\n", len(hosts))
}

func outputJSON(hosts []Host) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(hosts)
}

func outputCSV(hosts []Host) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"ip", "mac", "hostname"})
	for _, h := range hosts {
		_ = w.Write([]string{h.IP, h.MAC, h.Hostname})
	}
	w.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
