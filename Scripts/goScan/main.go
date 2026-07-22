// goScan — a small, bounded TCP connect scanner.
//
// Hardened rewrite. The original used net.IPToBigInt / net.BigIntToIP (which do
// not exist, so it never compiled) and launched one goroutine per port for all
// 65535 ports simultaneously per host — an unbounded connection storm.
//
// This version: real IP-range/CIDR expansion, a bounded worker pool, a safe
// default port set, a size guard, and an authorization confirmation prompt.
//
// Authorized testing only. See ../../LEGAL.md.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// topPorts is the default set scanned when -ports is "top": common services,
// not all 65535. Full coverage is still available via e.g. -ports 1-65535.
func topPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
	}
}

// parsePorts parses a spec like "top", "1-1024", "80,443", or a mix.
func parsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "top" {
		return topPorts(), nil
	}
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			b := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(b[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(b[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			if lo < 1 || hi > 65535 {
				return nil, fmt.Errorf("ports out of range 1-65535: %q", part)
			}
			for p := lo; p <= hi; p++ {
				set[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			set[p] = true
		}
	}
	if len(set) == 0 {
		return nil, errors.New("no valid ports")
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// expandTargets parses comma-separated IPs, CIDRs, and IPv4 ranges (a-b).
func expandTargets(spec string) ([]netip.Addr, error) {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	add := func(a netip.Addr) {
		if a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case strings.Contains(tok, "/"):
			p, err := netip.ParsePrefix(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", tok, err)
			}
			for a := p.Masked().Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
				add(a)
			}
		case strings.Contains(tok, "-"):
			b := strings.SplitN(tok, "-", 2)
			lo, err1 := netip.ParseAddr(strings.TrimSpace(b[0]))
			hi, err2 := netip.ParseAddr(strings.TrimSpace(b[1]))
			if err1 != nil || err2 != nil || !lo.Is4() || !hi.Is4() {
				return nil, fmt.Errorf("invalid IPv4 range %q", tok)
			}
			lu := binary.BigEndian.Uint32(lo.AsSlice())
			hu := binary.BigEndian.Uint32(hi.AsSlice())
			if lu > hu {
				lu, hu = hu, lu
			}
			for u := lu; ; u++ {
				var raw [4]byte
				binary.BigEndian.PutUint32(raw[:], u)
				add(netip.AddrFrom4(raw))
				if u == hu {
					break
				}
			}
		default:
			a, err := netip.ParseAddr(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid IP %q (hostnames unsupported for scanning)", tok)
			}
			add(a)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no valid targets")
	}
	return out, nil
}

func scan(targets []netip.Addr, ports []int, concurrency int, timeout time.Duration) int {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	open := 0
	for _, t := range targets {
		for _, p := range ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(addr string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				d := net.Dialer{Timeout: timeout}
				conn, err := d.Dial("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
				if err != nil {
					return
				}
				conn.Close()
				mu.Lock()
				open++
				mu.Unlock()
				fmt.Printf("%s:%d open\n", addr, port)
			}(t.String(), p)
		}
	}
	wg.Wait()
	return open
}

func main() {
	targetsFlag := flag.String("targets", "", "comma-separated IPs, CIDRs, or IPv4 ranges (a-b) — required")
	portsFlag := flag.String("ports", "top", "ports: 'top', '1-1024', '80,443', or a mix")
	concurrency := flag.Int("concurrency", 100, "max concurrent connections")
	timeout := flag.Duration("timeout", 3*time.Second, "per-port dial timeout")
	yes := flag.Bool("yes", false, "skip the authorization confirmation prompt")
	maxConns := flag.Int("max-connections", 50000, "refuse more than this many (targets*ports) unless -yes")
	flag.Parse()

	if *targetsFlag == "" {
		fmt.Fprintln(os.Stderr, "error: -targets is required")
		flag.Usage()
		os.Exit(2)
	}
	targets, err := expandTargets(*targetsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ports, err := parsePorts(*portsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	total := len(targets) * len(ports)
	fmt.Printf("Targets: %d  Ports: %d  Total connections: %d  Concurrency: %d  Timeout: %s\n",
		len(targets), len(ports), total, *concurrency, *timeout)

	if total > *maxConns && !*yes {
		fmt.Fprintf(os.Stderr,
			"Refusing: %d connections exceeds -max-connections=%d. Re-run with -yes to override.\n",
			total, *maxConns)
		os.Exit(2)
	}
	if !*yes {
		fmt.Print("Only scan hosts you are authorized to test. Proceed? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			fmt.Println("Aborted.")
			os.Exit(1)
		}
	}

	start := time.Now()
	open := scan(targets, ports, *concurrency, *timeout)
	fmt.Printf("Done: %d open port(s) across %d host(s) in %s\n",
		open, len(targets), time.Since(start).Round(time.Millisecond))
}
