package enrich

import (
	"crypto/sha1" //nolint:gosec // Community ID v1 is defined over SHA-1
	"encoding/base64"
	"encoding/binary"
	"net/netip"
)

// ICMP type pairs that form two-way "conversations" for Community ID.
var icmp4Pairs = map[uint8]uint8{8: 0, 0: 8, 13: 14, 14: 13, 15: 16, 16: 15, 10: 9, 9: 10, 17: 18, 18: 17}
var icmp6Pairs = map[uint8]uint8{128: 129, 129: 128, 133: 134, 134: 133, 135: 136, 136: 135, 130: 131, 131: 130}

// CommunityID computes the Community ID v1 string ("1:<base64>") per
// https://github.com/corelight/community-id-spec. ok=false when the flow
// lacks the fields (e.g. a rollup that folded several source ports).
func CommunityID(seed uint16, src, dst netip.Addr, sport, dport uint16, proto, icmpType, icmpCode uint8) (string, bool) {
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() {
		return "", false
	}
	oneWay := false
	switch proto {
	case 6, 17, 132:
	case 1, 58:
		pairs := icmp4Pairs
		if proto == 58 {
			pairs = icmp6Pairs
		}
		sport, dport = uint16(icmpType), uint16(icmpCode)
		if peer, ok := pairs[icmpType]; ok {
			dport = uint16(peer)
		} else {
			oneWay = true
		}
	default:
		sport, dport = 0, 0
	}
	if !oneWay && !ordered(src, dst, sport, dport) {
		src, dst = dst, src
		sport, dport = dport, sport
	}
	h := sha1.New() //nolint:gosec
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], seed)
	h.Write(b[:])
	h.Write(src.AsSlice())
	h.Write(dst.AsSlice())
	h.Write([]byte{proto, 0})
	if proto == 6 || proto == 17 || proto == 132 || proto == 1 || proto == 58 {
		binary.BigEndian.PutUint16(b[:], sport)
		h.Write(b[:])
		binary.BigEndian.PutUint16(b[:], dport)
		h.Write(b[:])
	}
	return "1:" + base64.StdEncoding.EncodeToString(h.Sum(nil)), true
}

func ordered(a, b netip.Addr, ap, bp uint16) bool {
	if c := a.Compare(b); c != 0 {
		return c < 0
	}
	return ap <= bp
}
