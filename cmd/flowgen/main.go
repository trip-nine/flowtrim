// Command flowgen sends synthetic NetFlow v5 traffic with a realistic mix of
// boring and security-relevant patterns, for testing FlowTrim rules locally.
//
// Patterns: chatty east-west HTTPS, DNS/NTP to internal servers, mDNS
// multicast, a 2-second beacon to an external host, an internal SMB/SSH
// sweep, a threat-intel hit, generic web egress, and (optionally) the same
// packets re-exported from a second "router" to exercise dedup.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"time"
)

type rec struct {
	src, dst        netip.Addr
	sport, dport    uint16
	proto, flags    uint8
	pkts, octets    uint32
	firstMs, lastMs uint32
}

func main() {
	target := flag.String("target", "127.0.0.1:2055", "collector address")
	rate := flag.Int("rate", 2000, "flows per second")
	dur := flag.Duration("duration", 10*time.Second, "how long to send")
	dup := flag.String("dup-from", "127.0.0.2", "second exporter source IP for duplicate exports (\"\" = off)")
	dupFrac := flag.Float64("dup-fraction", 0.3, "fraction of packets also sent from -dup-from")
	seed := flag.Uint64("seed", 1, "random seed")
	flag.Parse()

	rng := rand.New(rand.NewPCG(*seed, 7))
	raddr, err := net.ResolveUDPAddr("udp", *target)
	must(err)
	c1, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, raddr)
	must(err)
	var c2 *net.UDPConn
	if *dup != "" {
		c2, err = net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(*dup)}, raddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dup exporter disabled:", err)
		}
	}

	boot := time.Now().Add(-time.Hour)
	var seq uint32
	sent, dupSent := 0, 0
	start := time.Now()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	perTick := max(*rate/10, 1)
	var lastBeacon time.Time
	scanIdx := 0

	for time.Since(start) < *dur {
		<-tick.C
		now := time.Now()
		up := uint32(now.Sub(boot).Milliseconds())
		var batch []rec
		for i := 0; i < perTick; i++ {
			batch = append(batch, pick(rng, up, &scanIdx))
		}
		if now.Sub(lastBeacon) >= 2*time.Second {
			lastBeacon = now
			batch = append(batch, rec{src: ip("10.1.5.5"), dst: ip("203.0.113.66"), sport: uint16(40000 + rng.IntN(20000)), dport: 443, proto: 6, flags: 0x1b, pkts: 6, octets: 820, firstMs: up - 150, lastMs: up})
		}
		for len(batch) > 0 {
			n := min(30, len(batch))
			pkt := encode(batch[:n], up, now, seq)
			seq += uint32(n)
			_, err := c1.Write(pkt)
			must(err)
			sent += n
			if c2 != nil && rng.Float64() < *dupFrac {
				_, _ = c2.Write(pkt)
				dupSent += n
			}
			batch = batch[n:]
		}
	}
	fmt.Printf("flowgen: sent %d flows (+%d duplicate re-exports from %s) in %s\n", sent, dupSent, *dup, time.Since(start).Round(time.Millisecond))
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func pick(r *rand.Rand, up uint32, scanIdx *int) rec {
	x := r.Float64()
	first := up - uint32(r.IntN(5000))
	switch {
	case x < 0.40: // chatty east-west to an internal API
		return rec{src: netip.AddrFrom4([4]byte{10, 1, byte(r.IntN(4)), byte(10 + r.IntN(20))}), dst: ip("10.2.0.10"), sport: uint16(32768 + r.IntN(28000)), dport: 443, proto: 6, flags: 0x1b, pkts: uint32(8 + r.IntN(20)), octets: uint32(2000 + r.IntN(9000)), firstMs: first, lastMs: up}
	case x < 0.55: // DNS to internal resolvers
		return rec{src: netip.AddrFrom4([4]byte{10, 1, byte(r.IntN(4)), byte(10 + r.IntN(50))}), dst: ip("10.0.0.53"), sport: uint16(32768 + r.IntN(28000)), dport: 53, proto: 17, pkts: 1, octets: uint32(60 + r.IntN(40)), firstMs: up, lastMs: up}
	case x < 0.62: // NTP to internal servers
		return rec{src: netip.AddrFrom4([4]byte{10, 1, byte(r.IntN(4)), byte(10 + r.IntN(50))}), dst: ip("10.0.0.123"), sport: 123, dport: 123, proto: 17, pkts: 1, octets: 76, firstMs: up, lastMs: up}
	case x < 0.70: // mDNS multicast
		return rec{src: netip.AddrFrom4([4]byte{10, 1, byte(r.IntN(4)), byte(10 + r.IntN(50))}), dst: ip("224.0.0.251"), sport: 5353, dport: 5353, proto: 17, pkts: 1, octets: 120, firstMs: up, lastMs: up}
	case x < 0.73: // internal sweep: SYN-only to SMB/SSH across a /24
		*scanIdx++
		port := uint16(445)
		if *scanIdx%2 == 0 {
			port = 22
		}
		return rec{src: ip("10.1.9.9"), dst: netip.AddrFrom4([4]byte{10, 3, 0, byte(1 + *scanIdx%254)}), sport: uint16(50000 + r.IntN(1000)), dport: port, proto: 6, flags: 0x02, pkts: 1, octets: 60, firstMs: up, lastMs: up}
	case x < 0.735: // threat-intel destination
		return rec{src: ip("10.1.7.7"), dst: ip("198.51.100.7"), sport: uint16(40000 + r.IntN(20000)), dport: 8443, proto: 6, flags: 0x1b, pkts: 12, octets: 4400, firstMs: first, lastMs: up}
	default: // web egress to many external hosts
		return rec{src: netip.AddrFrom4([4]byte{10, 1, byte(r.IntN(4)), byte(10 + r.IntN(50))}), dst: netip.AddrFrom4([4]byte{93, 184, byte(r.IntN(8)), byte(r.IntN(250))}), sport: uint16(32768 + r.IntN(28000)), dport: 443, proto: 6, flags: 0x1b, pkts: uint32(10 + r.IntN(200)), octets: uint32(3000 + r.IntN(200000)), firstMs: first, lastMs: up}
	}
}

func encode(rs []rec, up uint32, now time.Time, seq uint32) []byte {
	b := make([]byte, 24+48*len(rs))
	be := binary.BigEndian
	be.PutUint16(b[0:], 5)
	be.PutUint16(b[2:], uint16(len(rs)))
	be.PutUint32(b[4:], up)
	be.PutUint32(b[8:], uint32(now.Unix()))
	be.PutUint32(b[12:], uint32(now.Nanosecond()))
	be.PutUint32(b[16:], seq)
	for i, r := range rs {
		o := 24 + 48*i
		s, d := r.src.As4(), r.dst.As4()
		copy(b[o:], s[:])
		copy(b[o+4:], d[:])
		be.PutUint16(b[o+12:], 1) // input ifIndex
		be.PutUint16(b[o+14:], 2) // output ifIndex
		be.PutUint32(b[o+16:], r.pkts)
		be.PutUint32(b[o+20:], r.octets)
		be.PutUint32(b[o+24:], r.firstMs)
		be.PutUint32(b[o+28:], r.lastMs)
		be.PutUint16(b[o+32:], r.sport)
		be.PutUint16(b[o+34:], r.dport)
		b[o+37] = r.flags
		b[o+38] = r.proto
	}
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
