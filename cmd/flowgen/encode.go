package main

import (
	"encoding/binary"
	"time"
)

var be = binary.BigEndian

// encoder keeps per-exporter state (sequence numbers, boot time).
type encoder struct {
	format string
	domain uint32
	seq    uint32
	boot   time.Time
}

func newEncoder(format string, domain uint32) *encoder {
	return &encoder{format: format, domain: domain, boot: time.Now().Add(-time.Hour)}
}

func (e *encoder) encode(rs []rec, now time.Time) []byte {
	switch e.format {
	case "v9":
		return e.v9(rs, now)
	case "ipfix":
		return e.ipfix(rs, now)
	default:
		return e.v5(rs, now)
	}
}

func (e *encoder) uptime(t time.Time) uint32 { return uint32(t.Sub(e.boot).Milliseconds()) }

// ---- NetFlow v5 (IPv4 only) ----

func (e *encoder) v5(rs []rec, now time.Time) []byte {
	var v4s []rec
	for _, r := range rs {
		if r.src.Is4() && r.dst.Is4() {
			v4s = append(v4s, r)
		}
	}
	b := make([]byte, 24+48*len(v4s))
	be.PutUint16(b[0:], 5)
	be.PutUint16(b[2:], uint16(len(v4s)))
	be.PutUint32(b[4:], e.uptime(now))
	be.PutUint32(b[8:], uint32(now.Unix()))
	be.PutUint32(b[12:], uint32(now.Nanosecond()))
	be.PutUint32(b[16:], e.seq)
	e.seq += uint32(len(v4s))
	for i, r := range v4s {
		o := 24 + 48*i
		s, d := r.src.As4(), r.dst.As4()
		copy(b[o:], s[:])
		copy(b[o+4:], d[:])
		be.PutUint16(b[o+12:], uint16(r.inIf))
		be.PutUint16(b[o+14:], uint16(r.outIf))
		be.PutUint32(b[o+16:], uint32(r.pkts))
		be.PutUint32(b[o+20:], uint32(r.octets))
		be.PutUint32(b[o+24:], e.uptime(r.start))
		be.PutUint32(b[o+28:], e.uptime(r.end))
		be.PutUint16(b[o+32:], r.sport)
		be.PutUint16(b[o+34:], r.dport)
		b[o+37] = r.flags
		b[o+38] = r.proto
	}
	return b
}

// field is an (information element id, length) pair.
type field struct{ id, length uint16 }

// IPFIX templates (IANA IEs): absolute millisecond timestamps.
var ipfix4 = []field{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {6, 2}, {1, 8}, {2, 8}, {152, 8}, {153, 8}, {10, 4}, {14, 4}}
var ipfix6 = []field{{27, 16}, {28, 16}, {7, 2}, {11, 2}, {4, 1}, {6, 2}, {1, 8}, {2, 8}, {152, 8}, {153, 8}, {10, 4}, {14, 4}}

// NetFlow v9 templates: FIRST/LAST_SWITCHED relative to sysUptime.
var v9t4 = []field{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {6, 1}, {1, 8}, {2, 8}, {22, 4}, {21, 4}, {10, 4}, {14, 4}}
var v9t6 = []field{{27, 16}, {28, 16}, {7, 2}, {11, 2}, {4, 1}, {6, 1}, {1, 8}, {2, 8}, {22, 4}, {21, 4}, {10, 4}, {14, 4}}

const tmpl4, tmpl6 = 256, 257

func templateSet(setID uint16, defs map[uint16][]field) []byte {
	var body []byte
	for _, id := range []uint16{tmpl4, tmpl6} {
		fs := defs[id]
		h := make([]byte, 4)
		be.PutUint16(h[0:], id)
		be.PutUint16(h[2:], uint16(len(fs)))
		body = append(body, h...)
		for _, f := range fs {
			x := make([]byte, 4)
			be.PutUint16(x[0:], f.id)
			be.PutUint16(x[2:], f.length)
			body = append(body, x...)
		}
	}
	hdr := make([]byte, 4)
	be.PutUint16(hdr[0:], setID)
	be.PutUint16(hdr[2:], uint16(4+len(body)))
	return append(hdr, body...)
}

func (e *encoder) record(r rec, fs []field) []byte {
	var out []byte
	put := func(n int, v uint64) {
		b := make([]byte, n)
		switch n {
		case 1:
			b[0] = byte(v)
		case 2:
			be.PutUint16(b, uint16(v))
		case 4:
			be.PutUint32(b, uint32(v))
		case 8:
			be.PutUint64(b, v)
		}
		out = append(out, b...)
	}
	for _, f := range fs {
		switch f.id {
		case 8, 12, 27, 28:
			a := r.src
			if f.id == 12 || f.id == 28 {
				a = r.dst
			}
			out = append(out, a.AsSlice()...)
		case 7:
			put(2, uint64(r.sport))
		case 11:
			put(2, uint64(r.dport))
		case 4:
			put(1, uint64(r.proto))
		case 6:
			put(int(f.length), uint64(r.flags))
		case 1:
			put(8, r.octets)
		case 2:
			put(8, r.pkts)
		case 152:
			put(8, uint64(r.start.UnixMilli()))
		case 153:
			put(8, uint64(r.end.UnixMilli()))
		case 22:
			put(4, uint64(e.uptime(r.start)))
		case 21:
			put(4, uint64(e.uptime(r.end)))
		case 10:
			put(4, uint64(r.inIf))
		case 14:
			put(4, uint64(r.outIf))
		}
	}
	return out
}

func dataSets(e *encoder, rs []rec, f4, f6 []field) ([]byte, int) {
	var out []byte
	n := 0
	for _, grp := range []struct {
		id uint16
		fs []field
		v6 bool
	}{{tmpl4, f4, false}, {tmpl6, f6, true}} {
		var body []byte
		for _, r := range rs {
			if r.src.Is6() == grp.v6 {
				body = append(body, e.record(r, grp.fs)...)
				n++
			}
		}
		if len(body) == 0 {
			continue
		}
		for (4+len(body))%4 != 0 {
			body = append(body, 0)
		}
		hdr := make([]byte, 4)
		be.PutUint16(hdr[0:], grp.id)
		be.PutUint16(hdr[2:], uint16(4+len(body)))
		out = append(out, hdr...)
		out = append(out, body...)
	}
	return out, n
}

// ---- NetFlow v9 ----

func (e *encoder) v9(rs []rec, now time.Time) []byte {
	ts := templateSet(0, map[uint16][]field{tmpl4: v9t4, tmpl6: v9t6})
	ds, n := dataSets(e, rs, v9t4, v9t6)
	h := make([]byte, 20)
	be.PutUint16(h[0:], 9)
	be.PutUint16(h[2:], uint16(n+2)) // count = data records + template records
	be.PutUint32(h[4:], e.uptime(now))
	be.PutUint32(h[8:], uint32(now.Unix()))
	be.PutUint32(h[12:], e.seq)
	be.PutUint32(h[16:], e.domain)
	e.seq++
	return append(append(h, ts...), ds...)
}

// ---- IPFIX ----

func (e *encoder) ipfix(rs []rec, now time.Time) []byte {
	ts := templateSet(2, map[uint16][]field{tmpl4: ipfix4, tmpl6: ipfix6})
	ds, n := dataSets(e, rs, ipfix4, ipfix6)
	h := make([]byte, 16)
	be.PutUint16(h[0:], 10)
	be.PutUint32(h[4:], uint32(now.Unix()))
	be.PutUint32(h[8:], e.seq)
	be.PutUint32(h[12:], e.domain)
	e.seq += uint32(n)
	msg := append(append(h, ts...), ds...)
	be.PutUint16(msg[2:], uint16(len(msg)))
	return msg
}
