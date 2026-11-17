package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

// ---------- pcap writing (classic libpcap, Ethernet) ----------

type pcapWriter struct {
	f *os.File
	w *bufio.Writer
}

func newPcap(path string) (*pcapWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(f)
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], 1) // LINKTYPE_ETHERNET
	_, _ = w.Write(h)
	return &pcapWriter{f: f, w: w}, nil
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func (p *pcapWriter) write(ts time.Time, src netip.Addr, dst netip.AddrPort, payload []byte) {
	udpLen := 8 + len(payload)
	frame := make([]byte, 14+20+udpLen)
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, byte(src.As4()[3])})
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	iph := frame[14:34]
	iph[0] = 0x45
	binary.BigEndian.PutUint16(iph[2:], uint16(20+udpLen))
	iph[8], iph[9] = 64, 17
	s4, d4 := src.As4(), dst.Addr().As4()
	if !dst.Addr().Is4() {
		d4 = [4]byte{127, 0, 0, 1}
	}
	copy(iph[12:], s4[:])
	copy(iph[16:], d4[:])
	binary.BigEndian.PutUint16(iph[10:], csum(iph))
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:], 50000)
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)
	rh := make([]byte, 16)
	binary.LittleEndian.PutUint32(rh[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rh[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rh[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rh[12:], uint32(len(frame)))
	_, _ = p.w.Write(rh)
	_, _ = p.w.Write(frame)
}

func (p *pcapWriter) close() {
	_ = p.w.Flush()
	_ = p.f.Close()
}

// ---------- pcap reading + replay ----------

type packet struct {
	ts      time.Time
	src     netip.Addr
	payload []byte
}

func readPcap(path string) ([]packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	gh := make([]byte, 24)
	if _, err := io.ReadFull(r, gh); err != nil {
		return nil, err
	}
	var bo binary.ByteOrder = binary.LittleEndian
	nano := false
	switch binary.LittleEndian.Uint32(gh) {
	case 0xa1b2c3d4:
	case 0xa1b23c4d:
		nano = true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nano = binary.BigEndian, true
	default:
		return nil, errors.New("not a classic pcap file (pcapng is not supported; convert with editcap -F pcap)")
	}
	link := bo.Uint32(gh[20:])
	var out []packet
	for {
		rh := make([]byte, 16)
		if _, err := io.ReadFull(r, rh); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, err
		}
		sec, frac, incl := bo.Uint32(rh[0:]), bo.Uint32(rh[4:]), bo.Uint32(rh[8:])
		data := make([]byte, incl)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		ns := int64(frac) * 1000
		if nano {
			ns = int64(frac)
		}
		off := 0
		switch link {
		case 1: // Ethernet (with optional 802.1Q)
			if len(data) < 14 {
				continue
			}
			et := binary.BigEndian.Uint16(data[12:])
			off = 14
			if et == 0x8100 && len(data) >= 18 {
				et = binary.BigEndian.Uint16(data[16:])
				off = 18
			}
			if et != 0x0800 && et != 0x86dd {
				continue
			}
		case 101, 228, 229: // raw IP
		case 113: // Linux cooked
			off = 16
		default:
			return nil, fmt.Errorf("unsupported link type %d", link)
		}
		p := data[off:]
		if len(p) < 20 {
			continue
		}
		var src netip.Addr
		var l4 []byte
		switch p[0] >> 4 {
		case 4:
			ihl := int(p[0]&0x0f) * 4
			if p[9] != 17 || len(p) < ihl+8 {
				continue
			}
			src = netip.AddrFrom4([4]byte(p[12:16]))
			l4 = p[ihl:]
		case 6:
			if p[6] != 17 || len(p) < 48 {
				continue
			}
			src = netip.AddrFrom16([16]byte(p[8:24]))
			l4 = p[40:]
		default:
			continue
		}
		ulen := int(binary.BigEndian.Uint16(l4[4:]))
		if ulen < 8 || ulen > len(l4) {
			ulen = len(l4)
		}
		out = append(out, packet{ts: time.Unix(int64(sec), ns), src: src, payload: append([]byte(nil), l4[8:ulen]...)})
	}
	return out, nil
}

func replay() {
	path := flag.String("pcap", "", "pcap file to replay (required)")
	target := flag.String("target", "127.0.0.1:2055", "collector address")
	speed := flag.Float64("speed", 1, "1 = original pacing, 10 = 10x faster, 0 = as fast as possible")
	retime := flag.Bool("retime", true, "shift flow timestamps so the capture looks like it happened now")
	loop := flag.Int("loop", 1, "replay this many times (0 = forever)")
	bind := flag.String("bind", "auto", "local source IPs: auto = map each exporter to 127.0.0.N where possible; none = OS default")
	flag.Parse()
	if *path == "" {
		fail(errors.New("-pcap is required"))
	}
	pkts, err := readPcap(*path)
	if err != nil {
		fail(err)
	}
	if len(pkts) == 0 {
		fail(errors.New("no UDP packets in capture"))
	}
	dst, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		fail(err)
	}
	conns := map[netip.Addr]*net.UDPConn{}
	next := 1
	conn := func(src netip.Addr) *net.UDPConn {
		if c, ok := conns[src]; ok {
			return c
		}
		var laddr *net.UDPAddr
		if *bind == "auto" {
			laddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, byte(next))}
			next++
		}
		c, err := net.DialUDP("udp", laddr, dst)
		if err != nil && laddr != nil { // e.g. macOS: only 127.0.0.1 exists
			c, err = net.DialUDP("udp", nil, dst)
		}
		if err != nil {
			fail(err)
		}
		conns[src] = c
		return c
	}
	rt := newRetimer()
	total := 0
	for i := 0; *loop == 0 || i < *loop; i++ {
		base := pkts[0].ts
		wall := time.Now()
		// as-fast-as-possible: one constant shift that puts the last packet at
		// "now", preserving the capture's original spacing (beacon intervals)
		fixed := wall.Sub(pkts[len(pkts)-1].ts)
		for _, p := range pkts {
			delta := fixed
			if *speed > 0 {
				due := wall.Add(time.Duration(float64(p.ts.Sub(base)) / *speed))
				if d := time.Until(due); d > 0 {
					time.Sleep(d)
				}
				delta = due.Sub(p.ts)
			}
			payload := p.payload
			if *retime {
				payload = rt.shift(p.src, payload, delta)
			}
			if _, err := conn(p.src).Write(payload); err != nil {
				fail(err)
			}
			total++
		}
	}
	fmt.Printf("flowgen replay: %d packets from %d exporter(s) sent to %s\n", total, len(conns), *target)
}

// retimer shifts NetFlow v5/v9 header clocks and IPFIX/v9 absolute
// timestamp fields (IEs 150-153) by delta, tracking templates per exporter.
type retimer struct {
	tmpl map[string][]field // exporter|domain|id -> fields
}

func newRetimer() *retimer { return &retimer{tmpl: map[string][]field{}} }

func (rt *retimer) shift(src netip.Addr, in []byte, delta time.Duration) []byte {
	b := append([]byte(nil), in...)
	if len(b) < 4 {
		return b
	}
	dSec := uint32(delta / time.Second)
	switch binary.BigEndian.Uint16(b) {
	case 5:
		if len(b) >= 24 {
			binary.BigEndian.PutUint32(b[8:], binary.BigEndian.Uint32(b[8:])+dSec)
		}
	case 9:
		if len(b) < 20 {
			return b
		}
		binary.BigEndian.PutUint32(b[8:], binary.BigEndian.Uint32(b[8:])+dSec)
		rt.sets(src, b, 20, binary.BigEndian.Uint32(b[16:]), 0, 1, delta)
	case 10:
		if len(b) < 16 {
			return b
		}
		binary.BigEndian.PutUint32(b[4:], binary.BigEndian.Uint32(b[4:])+dSec)
		rt.sets(src, b, 16, binary.BigEndian.Uint32(b[12:]), 2, 3, delta)
	}
	return b
}

func (rt *retimer) sets(src netip.Addr, b []byte, off int, domain uint32, tmplID, optID uint16, delta time.Duration) {
	key := func(id uint16) string { return fmt.Sprintf("%s|%d|%d", src, domain, id) }
	for off+4 <= len(b) {
		sid := binary.BigEndian.Uint16(b[off:])
		slen := int(binary.BigEndian.Uint16(b[off+2:]))
		if slen < 4 || off+slen > len(b) {
			return
		}
		body := b[off+4 : off+slen]
		switch {
		case sid == tmplID:
			p := 0
			for p+4 <= len(body) {
				id, n := binary.BigEndian.Uint16(body[p:]), int(binary.BigEndian.Uint16(body[p+2:]))
				p += 4
				var fs []field
				for j := 0; j < n && p+4 <= len(body); j++ {
					fid, flen := binary.BigEndian.Uint16(body[p:]), binary.BigEndian.Uint16(body[p+2:])
					p += 4
					if tmplID == 2 && fid&0x8000 != 0 { // IPFIX enterprise bit: skip PEN
						fid &= 0x7fff
						p += 4
						fid = 0xffff // never treat enterprise IEs as timestamps
					}
					fs = append(fs, field{fid, flen})
				}
				rt.tmpl[key(id)] = fs
			}
		case sid == optID:
			// options templates carry no flow timestamps we need to shift
		case sid >= 256:
			fs, ok := rt.tmpl[key(sid)]
			if !ok {
				break
			}
			rl := 0
			for _, f := range fs {
				if f.length == 0xffff {
					rl = -1
					break
				}
				rl += int(f.length)
			}
			if rl <= 0 {
				break
			}
			for p := 0; p+rl <= len(body); p += rl {
				q := p
				for _, f := range fs {
					switch {
					case f.id == 150 && f.length == 4: // flowStartSeconds
						binary.BigEndian.PutUint32(body[q:], binary.BigEndian.Uint32(body[q:])+uint32(delta/time.Second))
					case f.id == 151 && f.length == 4: // flowEndSeconds
						binary.BigEndian.PutUint32(body[q:], binary.BigEndian.Uint32(body[q:])+uint32(delta/time.Second))
					case (f.id == 152 || f.id == 153) && f.length == 8: // flowStart/EndMilliseconds
						binary.BigEndian.PutUint64(body[q:], binary.BigEndian.Uint64(body[q:])+uint64(delta/time.Millisecond))
					}
					q += int(f.length)
				}
			}
		}
		off += slen
	}
}
