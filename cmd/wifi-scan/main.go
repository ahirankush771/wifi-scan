package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	version    = "1.0.0"
	authorName = "Ankush Cybersecurity Developer V"
)

// Device represents a discovered network device.
type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

func main() {
	var (
		iface   string
		ipRange string
		output  string
		workers int
		timeout time.Duration
		verbose bool
		showVer bool
	)

	flag.StringVar(&iface, "interface", "", "Network interface to use (e.g. eth0, wlan0)")
	flag.StringVar(&iface, "i", "", "Network interface to use (shorthand)")
	flag.StringVar(&ipRange, "range", "", "IP range in CIDR notation (e.g. 192.168.1.0/24)")
	flag.StringVar(&ipRange, "r", "", "IP range in CIDR notation (shorthand)")
	flag.StringVar(&output, "output", "table", "Output format: table, json, csv")
	flag.StringVar(&output, "o", "table", "Output format: table, json, csv (shorthand)")
	flag.IntVar(&workers, "workers", 50, "Number of concurrent workers")
	flag.IntVar(&workers, "w", 50, "Number of concurrent workers (shorthand)")
	flag.DurationVar(&timeout, "timeout", 500*time.Millisecond, "Timeout per host probe")
	flag.DurationVar(&timeout, "t", 500*time.Millisecond, "Timeout per host probe (shorthand)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging (shorthand)")
	flag.BoolVar(&showVer, "version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `wifi-scan %s — Local Wi-Fi device discovery tool
Author: %s

Usage:
  wifi-scan [flags]

Flags:
`, version, authorName)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  wifi-scan -i wlan0
  wifi-scan -r 192.168.1.0/24 -o json
  wifi-scan -i eth0 -w 100 -t 1s -o csv

Security Notice:
  Use this tool only on networks and devices you own or have explicit
  authorization to scan. Unauthorized scanning may be illegal.
`)
	}

	flag.Parse()

	if showVer {
		fmt.Printf("wifi-scan version %s\nAuthor: %s\n", version, authorName)
		os.Exit(0)
	}

	// Resolve interface and subnet.
	netIface, subnet, err := resolveInterface(iface, ipRange)
	if err != nil {
		log.Fatalf("Error resolving interface/range: %v", err)
	}
	if verbose {
		log.Printf("Using interface: %s, scanning subnet: %s", netIface.Name, subnet)
	}

	// Generate all host IPs in the subnet.
	hosts := hostsInSubnet(subnet)
	if verbose {
		log.Printf("Total hosts to probe: %d", len(hosts))
	}

	// Phase 1: ARP-based discovery.
	arpResults := arpScan(netIface, hosts, timeout, verbose)

	// Phase 2: ICMP fallback for hosts not found via ARP.
	arpSeen := make(map[string]bool)
	for _, d := range arpResults {
		arpSeen[d.IP] = true
	}
	var icmpTargets []net.IP
	for _, h := range hosts {
		if !arpSeen[h.String()] {
			icmpTargets = append(icmpTargets, h)
		}
	}
	icmpResults := icmpScan(icmpTargets, workers, timeout, verbose)

	// Merge results.
	all := append(arpResults, icmpResults...)

	// Resolve hostnames.
	for i := range all {
		names, err := net.LookupAddr(all[i].IP)
		if err == nil && len(names) > 0 {
			all[i].Hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return ipToUint32(net.ParseIP(all[i].IP)) < ipToUint32(net.ParseIP(all[j].IP))
	})

	if verbose {
		log.Printf("Discovered %d device(s)", len(all))
	}

	// Output results.
	switch strings.ToLower(output) {
	case "json":
		printJSON(all)
	case "csv":
		printCSV(all)
	default:
		printTable(all)
	}
}

// resolveInterface returns the network interface and subnet to scan.
func resolveInterface(ifaceName, ipRange string) (*net.Interface, *net.IPNet, error) {
	if ipRange != "" {
		_, subnet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR range %q: %w", ipRange, err)
		}
		var iface *net.Interface
		if ifaceName != "" {
			iface, err = net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
			}
		} else {
			// Pick first suitable interface.
			iface, err = pickInterface()
			if err != nil {
				return nil, nil, err
			}
		}
		return iface, subnet, nil
	}

	// Auto-detect subnet from interface.
	var netIface *net.Interface
	var err error
	if ifaceName != "" {
		netIface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
		}
	} else {
		netIface, err = pickInterface()
		if err != nil {
			return nil, nil, err
		}
	}

	addrs, err := netIface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get addresses for interface %s: %w", netIface.Name, err)
	}
	for _, addr := range addrs {
		var ipNet *net.IPNet
		switch v := addr.(type) {
		case *net.IPNet:
			ipNet = v
		case *net.IPAddr:
			ipNet = &net.IPNet{IP: v.IP, Mask: v.IP.DefaultMask()}
		}
		if ipNet != nil && ipNet.IP.To4() != nil {
			// Return subnet (network address).
			_, subnet, err := net.ParseCIDR(ipNet.String())
			if err != nil {
				continue
			}
			return netIface, subnet, nil
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address found on interface %s", netIface.Name)
}

// pickInterface finds the first non-loopback, up interface with an IPv4 address.
func pickInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				return iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable network interface found; use --interface to specify one")
}

// hostsInSubnet enumerates all usable host IPs in a subnet (excluding network and broadcast).
func hostsInSubnet(subnet *net.IPNet) []net.IP {
	var ips []net.IP
	ip := cloneIP(subnet.IP.To4())
	for subnet.Contains(ip) {
		// Skip network address and broadcast.
		if !ip.Equal(subnet.IP) {
			broadcast := broadcastIP(subnet)
			if !ip.Equal(broadcast) {
				ips = append(ips, cloneIP(ip))
			}
		}
		incrementIP(ip)
	}
	return ips
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := n.Mask
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// arpScan performs ARP-based host discovery on the given interface.
func arpScan(iface *net.Interface, hosts []net.IP, timeout time.Duration, verbose bool) []Device {
	client, err := arp.Dial(iface)
	if err != nil {
		if verbose {
			log.Printf("ARP scan unavailable (may need root): %v", err)
		}
		return nil
	}
	defer client.Close()

	var mu sync.Mutex
	var found []Device
	seen := make(map[string]bool)

	// Set overall deadline for ARP phase: enough time for 50 workers to
	// sweep the subnet in batches, plus a fixed buffer, capped at 30s.
	batches := time.Duration((len(hosts)+49)/50 + 2)
	arpDeadline := timeout * batches
	if arpDeadline > 30*time.Second {
		arpDeadline = 30 * time.Second
	}
	_ = client.SetDeadline(time.Now().Add(arpDeadline))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			addr, ok := netip.AddrFromSlice(ip.To4())
			if !ok {
				return
			}
			if err := client.Request(addr); err != nil {
				if verbose {
					log.Printf("ARP request error for %s: %v", ip, err)
				}
			}
		}(cloneIP(h))
	}
	wg.Wait()

	// Collect replies with a short read loop.
	deadline := time.Now().Add(timeout * 2)
	for time.Now().Before(deadline) {
		_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		pkt, _, err := client.Read()
		if err != nil {
			break
		}
		if pkt == nil {
			continue
		}
		ipStr := pkt.SenderIP.String()
		macStr := pkt.SenderHardwareAddr.String()
		mu.Lock()
		if !seen[ipStr] {
			seen[ipStr] = true
			found = append(found, Device{IP: ipStr, MAC: macStr})
		}
		mu.Unlock()
	}

	return found
}

// icmpScan probes a list of IPs using ICMP echo requests and returns responding ones.
func icmpScan(targets []net.IP, workers int, timeout time.Duration, verbose bool) []Device {
	if len(targets) == 0 {
		return nil
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if verbose {
			log.Printf("ICMP scan unavailable (may need root): %v", err)
		}
		return nil
	}
	defer conn.Close()

	var mu sync.Mutex
	responding := make(map[string]bool)

	// Reader goroutine. Use ceiling division to ensure at least one full
	// sweep timeout even when targets < workers.
	batches := time.Duration((len(targets)+workers-1)/workers + 2)
	ctx, cancel := context.WithTimeout(context.Background(), timeout*batches)
	defer cancel()

	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
			if err != nil {
				continue
			}
			if msg.Type == ipv4.ICMPTypeEchoReply {
				ipStr := peer.String()
				mu.Lock()
				responding[ipStr] = true
				mu.Unlock()
			}
		}
	}()

	// Send ICMP echo requests concurrently.
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			sendICMP(conn, ip, timeout, verbose)
		}(target)
	}
	wg.Wait()

	// Allow time for final replies.
	time.Sleep(timeout)
	cancel()

	mu.Lock()
	defer mu.Unlock()
	var result []Device
	for ip := range responding {
		result = append(result, Device{IP: ip})
	}
	return result
}

func sendICMP(conn *icmp.PacketConn, ip net.IP, timeout time.Duration, verbose bool) {
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
		if verbose {
			log.Printf("ICMP marshal error: %v", err)
		}
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: ip}); err != nil {
		if verbose {
			log.Printf("ICMP write error for %s: %v", ip, err)
		}
	}
}

// printTable outputs results in a human-readable table.
func printTable(devices []Device) {
	if len(devices) == 0 {
		fmt.Println("No devices found.")
		return
	}
	fmt.Printf("%-18s %-20s %s\n", "IP ADDRESS", "MAC ADDRESS", "HOSTNAME")
	fmt.Println(strings.Repeat("-", 60))
	for _, d := range devices {
		mac := d.MAC
		if mac == "" {
			mac = "(unknown)"
		}
		hostname := d.Hostname
		if hostname == "" {
			hostname = "(unknown)"
		}
		fmt.Printf("%-18s %-20s %s\n", d.IP, mac, hostname)
	}
	fmt.Printf("\nTotal: %d device(s) discovered\n", len(devices))
}

// printJSON outputs results as JSON.
func printJSON(devices []Device) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(devices); err != nil {
		log.Fatalf("JSON encode error: %v", err)
	}
}

// printCSV outputs results as CSV.
func printCSV(devices []Device) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"ip", "mac", "hostname"})
	for _, d := range devices {
		_ = w.Write([]string{d.IP, d.MAC, d.Hostname})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatalf("CSV write error: %v", err)
	}
}
