// wifi-scan — local Wi‑Fi device discovery tool (ARP + ICMP fallback)
// Author: Ankush Cybersecurity Developer V
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const version = "1.0.0"
const author = "Ankush Cybersecurity Developer V"

// Host represents a discovered network device.
type Host struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

func main() {
	var (
		iface   string
		cidr    string
		output  string
		workers int
		timeout time.Duration
		verbose bool
		ver     bool
	)

	flag.StringVar(&iface, "interface", "", "Network interface to use (default: auto-detect)")
	flag.StringVar(&iface, "i", "", "Network interface to use (shorthand)")
	flag.StringVar(&cidr, "range", "", "CIDR range to scan (default: auto-detect from interface)")
	flag.StringVar(&cidr, "r", "", "CIDR range to scan (shorthand)")
	flag.StringVar(&output, "output", "table", "Output format: table, json, csv")
	flag.StringVar(&output, "o", "table", "Output format (shorthand)")
	flag.IntVar(&workers, "workers", 100, "Concurrency for ICMP ping fallback")
	flag.IntVar(&workers, "w", 100, "Concurrency for ICMP ping fallback (shorthand)")
	flag.DurationVar(&timeout, "timeout", 500*time.Millisecond, "Per-host timeout")
	flag.DurationVar(&timeout, "t", 500*time.Millisecond, "Per-host timeout (shorthand)")
	flag.BoolVar(&verbose, "verbose", false, "Verbose logging")
	flag.BoolVar(&verbose, "v", false, "Verbose logging (shorthand)")
	flag.BoolVar(&ver, "version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "wifi-scan v%s — local Wi‑Fi device discovery tool (ARP + ICMP fallback)\n", version)
		fmt.Fprintf(os.Stderr, "Author: %s\n\n", author)
		fmt.Fprintf(os.Stderr, "Usage:\n  wifi-scan [flags]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  wifi-scan
  wifi-scan --interface wlan0 --output json
  wifi-scan --range 192.168.1.0/24 --output csv > devices.csv

Note: ARP-based discovery requires elevated privileges (root/sudo) on most systems.
      ICMP (ping) fallback also typically requires root or CAP_NET_RAW capability.
      Only scan networks you own or are authorized to test.
`)
	}

	flag.Parse()

	if ver {
		fmt.Printf("wifi-scan v%s — Author: %s\n", version, author)
		os.Exit(0)
	}

	if verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// Resolve interface
	netIface, err := resolveInterface(iface, verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving interface: %v\n", err)
		os.Exit(1)
	}
	if verbose {
		log.Printf("Using interface: %s", netIface.Name)
	}

	// Resolve CIDR
	if cidr == "" {
		cidr, err = detectCIDR(netIface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error detecting subnet: %v\n", err)
			os.Exit(1)
		}
	}
	if verbose {
		log.Printf("Scanning range: %s", cidr)
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid CIDR %q: %v\n", cidr, err)
		os.Exit(1)
	}

	hosts := allHosts(ipNet)
	if verbose {
		log.Printf("Total addresses to probe: %d", len(hosts))
	}

	// 1. Try ARP sweep
	discovered, arpErr := arpSweep(netIface, hosts, timeout, verbose)
	if arpErr != nil {
		if verbose {
			log.Printf("ARP sweep failed (%v), falling back to ICMP ping sweep", arpErr)
		} else {
			fmt.Fprintf(os.Stderr, "ARP unavailable (%v) — using ICMP fallback\n", arpErr)
		}
	}

	// 2. If ARP found nothing or failed, fall back to ICMP
	if len(discovered) == 0 {
		if verbose {
			log.Printf("No ARP results; starting ICMP ping sweep (workers=%d timeout=%s)", workers, timeout)
		}
		discovered = icmpSweep(hosts, workers, timeout, verbose)
	}

	// 3. Resolve hostnames best-effort
	for i := range discovered {
		names, err := net.LookupAddr(discovered[i].IP)
		if err == nil && len(names) > 0 {
			discovered[i].Hostname = names[0]
		}
	}

	// 4. Output
	switch output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(discovered); err != nil {
			fmt.Fprintf(os.Stderr, "JSON encode error: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"ip", "mac", "hostname"})
		for _, h := range discovered {
			_ = w.Write([]string{h.IP, h.MAC, h.Hostname})
		}
		w.Flush()
	default: // table
		fmt.Printf("wifi-scan v%s — %s\n", version, author)
		fmt.Printf("Discovered %d device(s) on %s\n\n", len(discovered), cidr)
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("IP Address", "MAC Address", "Hostname")
		for _, h := range discovered {
			_ = table.Append([]interface{}{h.IP, h.MAC, h.Hostname})
		}
		_ = table.Render()
	}
}

// resolveInterface returns the network interface to use.
func resolveInterface(name string, verbose bool) (*net.Interface, error) {
	if name != "" {
		return net.InterfaceByName(name)
	}
	// Auto-detect: pick first interface that has an IPv4 non-loopback address
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
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
			if ip != nil && ip.To4() != nil {
				if verbose {
					log.Printf("Auto-detected interface: %s", iface.Name)
				}
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable network interface found; use --interface to specify one")
}

// detectCIDR returns the IPv4 CIDR of the given interface.
func detectCIDR(iface *net.Interface) (string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				return ipNet.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 address found on interface %s", iface.Name)
}

// allHosts returns all usable host IPs in the given network.
func allHosts(ipNet *net.IPNet) []net.IP {
	var hosts []net.IP
	for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); incIP(ip) {
		// skip network and broadcast addresses
		if ip.Equal(ipNet.IP) {
			continue
		}
		bcast := broadcastIP(ipNet)
		if ip.Equal(bcast) {
			continue
		}
		h := make(net.IP, len(ip))
		copy(h, ip)
		hosts = append(hosts, h)
	}
	return hosts
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcastIP(ipNet *net.IPNet) net.IP {
	bcast := make(net.IP, len(ipNet.IP))
	for i := range ipNet.IP {
		bcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	return bcast
}

// arpSweep sends ARP who-has requests for each host and collects replies.
func arpSweep(iface *net.Interface, hosts []net.IP, timeout time.Duration, verbose bool) ([]Host, error) {
	client, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("arp.Dial: %w", err)
	}
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(timeout * time.Duration(len(hosts)+1)))

	var mu sync.Mutex
	results := make(map[string]Host)

	// Send ARP requests concurrently
	var wg sync.WaitGroup
	for _, ip := range hosts {
		wg.Add(1)
		go func(target net.IP) {
			defer wg.Done()
			addr, ok := netip.AddrFromSlice(target.To4())
			if !ok {
				return
			}
			if err := client.Request(addr); err != nil {
				if verbose {
					log.Printf("ARP request to %s failed: %v", target, err)
				}
			}
		}(ip)
	}

	// Read replies in a separate goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(timeout * time.Duration(len(hosts)+2))
		for time.Now().Before(deadline) {
			pkt, _, err := client.Read()
			if err != nil {
				break
			}
			ipStr := pkt.SenderIP.String()
			macStr := pkt.SenderHardwareAddr.String()
			mu.Lock()
			results[ipStr] = Host{IP: ipStr, MAC: macStr}
			mu.Unlock()
		}
	}()

	wg.Wait()
	// Give reader a moment to catch trailing replies
	select {
	case <-done:
	case <-time.After(timeout):
	}

	var discovered []Host
	for _, h := range results {
		discovered = append(discovered, h)
	}
	if verbose {
		log.Printf("ARP sweep found %d host(s)", len(discovered))
	}
	return discovered, nil
}

// icmpSweep pings all hosts concurrently and returns those that respond.
func icmpSweep(hosts []net.IP, workers int, timeout time.Duration, verbose bool) []Host {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ICMP listen failed (%v) — try running with sudo/root\n", err)
		return nil
	}
	defer conn.Close()

	var mu sync.Mutex
	alive := make(map[string]bool)

	// Reader goroutine
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 1500)
		deadline := time.Now().Add(timeout * time.Duration(len(hosts)+2))
		_ = conn.SetReadDeadline(deadline)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
			if err != nil {
				continue
			}
			if msg.Type == ipv4.ICMPTypeEchoReply {
				ip := peer.(*net.IPAddr).IP.String()
				mu.Lock()
				alive[ip] = true
				mu.Unlock()
			}
		}
	}()

	// Worker pool to send pings
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, ip := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(seq int, target net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   os.Getpid() & 0xffff,
					Seq:  seq,
					Data: []byte("wifi-scan"),
				},
			}
			wb, err := msg.Marshal(nil)
			if err != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			_, _ = conn.WriteTo(wb, &net.IPAddr{IP: target})
		}(i, ip)
	}
	wg.Wait()

	// Wait for reader to finish (or timeout)
	select {
	case <-readerDone:
	case <-time.After(timeout * 2):
	}

	var discovered []Host
	mu.Lock()
	for ip := range alive {
		discovered = append(discovered, Host{IP: ip})
	}
	mu.Unlock()

	if verbose {
		log.Printf("ICMP sweep found %d host(s)", len(discovered))
	}
	return discovered
}
