package main

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestPcapRoundTripAndRetime(t *testing.T) {
	for _, format := range []string{"v5", "v9", "ipfix"} {
		path := filepath.Join(t.TempDir(), format+".pcap")
		pw, err := newPcap(path)
		if err != nil {
			t.Fatal(err)
		}
		enc := newEncoder(format, 100)
		then := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		r := rec{src: ip("10.1.5.5"), dst: ip("203.0.113.66"), sport: 40000, dport: 443, proto: 6, pkts: 6, octets: 820, start: then.Add(-time.Second), end: then}
		pkt := enc.encode([]rec{r}, then)
		pw.write(then, ip("192.0.2.1"), netip.MustParseAddrPort("127.0.0.1:4739"), pkt)
		pw.close()

		got, err := readPcap(path)
		if err != nil || len(got) != 1 {
			t.Fatalf("%s: read %d packets, err %v", format, len(got), err)
		}
		if got[0].src != ip("192.0.2.1") || string(got[0].payload) != string(pkt) {
			t.Fatalf("%s: payload or exporter mismatch", format)
		}
		delta := 400 * 24 * time.Hour
		out := newRetimer().shift(got[0].src, got[0].payload, delta)
		switch format {
		case "v5", "v9":
			if binary.BigEndian.Uint32(out[8:])-binary.BigEndian.Uint32(pkt[8:]) != uint32(delta/time.Second) {
				t.Fatalf("%s: header clock not shifted", format)
			}
		case "ipfix":
			if binary.BigEndian.Uint32(out[4:])-binary.BigEndian.Uint32(pkt[4:]) != uint32(delta/time.Second) {
				t.Fatal("ipfix export time not shifted")
			}
			// find flowEndMilliseconds of the single data record: last 8+8 bytes before in/out ifindex
			n := len(out)
			// data record layout ends with ...start(8) end(8) inIf(4) outIf(4) [+padding]
			found := false
			for off := 16; off+16 <= n; off++ {
				if binary.BigEndian.Uint64(pkt[off:]) == uint64(r.end.UnixMilli()) {
					if binary.BigEndian.Uint64(out[off:]) == uint64(r.end.Add(delta).UnixMilli()) {
						found = true
					}
				}
			}
			if !found {
				t.Fatal("ipfix flowEndMilliseconds not shifted")
			}
		}
	}
}
