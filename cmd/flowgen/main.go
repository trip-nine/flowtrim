// Command flowgen generates, records and replays NetFlow traffic for
// testing and demonstrating FlowTrim.
//
//	flowgen gen    -format ipfix -rate 2000 -duration 30s -target 127.0.0.1:4739
//	flowgen gen    -format ipfix -duration 30s -pcap sample.pcap -manifest sample.json -send=false
//	flowgen replay -pcap demo/samples/enterprise-mix.ipfix.pcap -target 127.0.0.1:4739 -retime
//
// The traffic mix contains boring patterns (chatty east-west HTTPS, DNS/NTP
// to internal servers, mDNS), security-relevant ones (a 2-second beacon, an
// internal SMB/SSH sweep, a threat-intel destination, denied flows), web
// egress, IPv6, and duplicate re-exports from a second router.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	if cmd[0] == '-' { // backwards compatible: flowgen -rate ...
		cmd = "gen"
	} else {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	switch cmd {
	case "gen":
		gen()
	case "replay":
		replay()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: flowgen gen|replay [flags]  (flowgen gen -h for flags)")
	os.Exit(2)
}

// ---------- generation ----------

type rec struct {
	pattern      string
	src, dst     netip.Addr
	sport, dport uint16
	proto, flags uint8
	pkts, octets uint64
	start, end   time.Time
	inIf, outIf  uint32
}

type exporter struct {
	ip   netip.Addr // address written into pcaps
	bind string     // local address used when sending
	conn *net.UDPConn
	enc  *encoder
}

func gen() {
	format := flag.String("format", "v5", "v5 | v9 | ipfix")
	target := flag.String("target", "127.0.0.1:2055", "collector address")
	rate := flag.Int("rate", 2000, "flows per second")
	dur := flag.Duration("duration", 10*time.Second, "how long to generate")
	send := flag.Bool("send", true, "send packets over UDP")
	pcapOut := flag.String("pcap", "", "also write packets to this .pcap file")
	manifest := flag.String("manifest", "", "write ground-truth counts per pattern to this JSON file")
	dup := flag.String("dup-from", "127.0.0.2", "second exporter (local bind IP) for duplicate re-exports; \"\" = off")
	dupFrac := flag.Float64("dup-fraction", 0.3, "fraction of packets re-exported by the second router")
	v6 := flag.Float64("ipv6-fraction", 0.05, "fraction of web-egress flows that are IPv6 (v9/ipfix only)")
	seed := flag.Uint64("seed", 1, "random seed (same seed = same traffic)")
	fast := flag.Bool("fast", false, "generate as fast as possible (with -send=false for files)")
	flag.Parse()

	rng := rand.New(rand.NewPCG(*seed, 7))
	collector := netip.MustParseAddrPort(*target)
	ex1 := &exporter{ip: netip.MustParseAddr("192.0.2.1"), bind: "127.0.0.1"}
	exs := []*exporter{ex1}
	if *dup != "" {
		exs = append(exs, &exporter{ip: netip.MustParseAddr("192.0.2.2"), bind: *dup})
	}
	var pw *pcapWriter
	if *pcapOut != "" {
		var err error
		if pw, err = newPcap(*pcapOut); err != nil {
			fail(err)
		}
		defer pw.close()
	}
	for i, e := range exs {
		e.enc = newEncoder(*format, uint32(100+i))
		if *send {
			c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(e.bind)}, net.UDPAddrFromAddrPort(collector))
			if err != nil {
				if i == 0 {
					fail(err)
				}
				fmt.Fprintf(os.Stderr, "flowgen: second exporter %s unavailable (%v); duplicates come from the first exporter\n", e.bind, err)
				e.conn = exs[0].conn
			} else {
				e.conn = c
			}
		}
	}

	counts := map[string]int{}
	sent, dupSent, packets := 0, 0, 0
	clock := time.Now()
	startWall := clock
	tickDur := 100 * time.Millisecond
	perTick := max(*rate/10, 1)
	var lastBeacon time.Time
	scanIdx := 0
	ticks := int(*dur / tickDur)
	tk := time.NewTicker(tickDur)
	defer tk.Stop()
	for t := 0; t < ticks; t++ {
		if *fast {
			clock = clock.Add(tickDur)
		} else {
			<-tk.C
			clock = time.Now()
		}
		var batch []rec
		for i := 0; i < perTick; i++ {
			r := pick(rng, clock, &scanIdx, *format != "v5" && rng.Float64() < *v6)
			batch = append(batch, r)
		}
		if clock.Sub(lastBeacon) >= 2*time.Second {
			lastBeacon = clock
			batch = append(batch, rec{pattern: "beacon_c2_candidate", src: ip("10.1.5.5"), dst: ip("203.0.113.66"), sport: uint16(40000 + rng.IntN(20000)), dport: 443, proto: 6, flags: 0x1b, pkts: 6, octets: 820, start: clock.Add(-150 * time.Millisecond), end: clock, inIf: 3, outIf: 7})
		}
		for _, r := range batch {
			counts[r.pattern]++
		}
		for len(batch) > 0 {
			n := min(e1max(*format), len(batch))
			pkt := ex1.enc.encode(batch[:n], clock)
			emit(ex1, collector, pkt, pw, clock)
			packets++
			sent += n
			if len(exs) > 1 && rng.Float64() < *dupFrac {
				p2 := exs[1].enc.encode(batch[:n], clock) // same flows, second router, own sequence numbers
				emit(exs[1], collector, p2, pw, clock)
				packets++
				dupSent += n
			}
			batch = batch[n:]
		}
	}
	fmt.Printf("flowgen: %s, %d flows (+%d duplicate re-exports) in %d packets over %s\n", *format, sent, dupSent, packets, clock.Sub(startWall).Round(time.Millisecond))
	if *manifest != "" {
		m := map[string]any{
			"format": *format, "seed": *seed, "rate_per_s": *rate, "duration_s": dur.Seconds(),
			"flows_unique": sent, "duplicate_reexports": dupSent, "flows_on_wire": sent + dupSent, "packets": packets,
			"exporters": []string{"192.0.2.1", "192.0.2.2"}, "patterns": sortedCounts(counts),
			"expected": map[string]string{
				"dedup":               "≈ duplicate_reexports (plus identical NTP/mDNS records inside 1 s)",
				"drop:multicast":      "mdns_multicast",
				"drop:dns_to_corp":    "dns_to_corp_resolvers",
				"drop:ntp_to_corp":    "ntp_to_corp_servers",
				"bypass:lateral":      "internal_smb_ssh_sweep (+ any internal 22/445 traffic)",
				"bypass:threat_intel": "threat_intel_destination",
				"bypass:denied":       "denied_inbound",
				"rollup":              "east_west_api_chatter + beacon_c2_candidate (+ repeated egress pairs)",
				"fanout_summary":      "1 per window for 10.1.9.9 (the sweeper)",
				"raw":                 "web_egress (mostly unique pairs)",
			},
		}
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(*manifest, b, 0o644); err != nil {
			fail(err)
		}
	}
}

func e1max(format string) int {
	if format == "v5" {
		return 30
	}
	return 20
}

func sortedCounts(m map[string]int) map[string]int {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]int, len(m))
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

func emit(e *exporter, collector netip.AddrPort, pkt []byte, pw *pcapWriter, ts time.Time) {
	if pw != nil {
		pw.write(ts, e.ip, collector, pkt)
	}
	if e.conn != nil {
		if _, err := e.conn.Write(pkt); err != nil {
			fail(err)
		}
	}
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func v4(a, b, c, d int) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(a), byte(b), byte(c), byte(d)})
}

func pick(r *rand.Rand, now time.Time, scanIdx *int, ipv6 bool) rec {
	x := r.Float64()
	start := now.Add(-time.Duration(r.IntN(5000)) * time.Millisecond)
	host := func(n int) netip.Addr { return v4(10, 1, r.IntN(4), 10+r.IntN(n)) }
	switch {
	case x < 0.40:
		return rec{pattern: "east_west_api_chatter", src: host(20), dst: ip("10.2.0.10"), sport: uint16(32768 + r.IntN(28000)), dport: 443, proto: 6, flags: 0x1b, pkts: uint64(8 + r.IntN(20)), octets: uint64(2000 + r.IntN(9000)), start: start, end: now, inIf: 3, outIf: 5}
	case x < 0.55:
		return rec{pattern: "dns_to_corp_resolvers", src: host(50), dst: ip("10.0.0.53"), sport: uint16(32768 + r.IntN(28000)), dport: 53, proto: 17, pkts: 1, octets: uint64(60 + r.IntN(40)), start: now, end: now, inIf: 3, outIf: 5}
	case x < 0.62:
		return rec{pattern: "ntp_to_corp_servers", src: host(50), dst: ip("10.0.0.123"), sport: 123, dport: 123, proto: 17, pkts: 1, octets: 76, start: now, end: now, inIf: 3, outIf: 5}
	case x < 0.70:
		return rec{pattern: "mdns_multicast", src: host(50), dst: ip("224.0.0.251"), sport: 5353, dport: 5353, proto: 17, pkts: 1, octets: 120, start: now, end: now, inIf: 3, outIf: 1}
	case x < 0.73:
		*scanIdx++
		port := uint16(445)
		if *scanIdx%2 == 0 {
			port = 22
		}
		return rec{pattern: "internal_smb_ssh_sweep", src: ip("10.1.9.9"), dst: v4(10, 3, 0, 1+*scanIdx%254), sport: uint16(50000 + r.IntN(1000)), dport: port, proto: 6, flags: 0x02, pkts: 1, octets: 60, start: now, end: now, inIf: 3, outIf: 5}
	case x < 0.735:
		return rec{pattern: "threat_intel_destination", src: ip("10.1.7.7"), dst: ip("198.51.100.7"), sport: uint16(40000 + r.IntN(20000)), dport: 8443, proto: 6, flags: 0x1b, pkts: 12, octets: 4400, start: start, end: now, inIf: 3, outIf: 7}
	case x < 0.745:
		return rec{pattern: "denied_inbound", src: v4(45, 33, r.IntN(255), r.IntN(255)), dst: ip("10.1.0.20"), sport: uint16(40000 + r.IntN(20000)), dport: 3389, proto: 6, flags: 0x02, pkts: 1, octets: 60, start: now, end: now, inIf: 7, outIf: 0}
	default:
		if ipv6 {
			return rec{pattern: "web_egress_ipv6", src: netip.MustParseAddr(fmt.Sprintf("fd00:10:1::%x", 10+r.IntN(50))), dst: netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::%x", r.IntN(8), r.IntN(250))), sport: uint16(32768 + r.IntN(28000)), dport: 443, proto: 6, flags: 0x1b, pkts: uint64(10 + r.IntN(200)), octets: uint64(3000 + r.IntN(200000)), start: start, end: now, inIf: 3, outIf: 7}
		}
		return rec{pattern: "web_egress", src: host(50), dst: v4(93, 184, r.IntN(8), r.IntN(250)), sport: uint16(32768 + r.IntN(28000)), dport: 443, proto: 6, flags: 0x1b, pkts: uint64(10 + r.IntN(200)), octets: uint64(3000 + r.IntN(200000)), start: start, end: now, inIf: 3, outIf: 7}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "flowgen:", err)
	os.Exit(1)
}
