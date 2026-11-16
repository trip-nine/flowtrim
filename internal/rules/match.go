package rules

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tripnine/flowtrim/internal/config"
	"github.com/tripnine/flowtrim/internal/flow"
	"github.com/tripnine/flowtrim/internal/netset"
)

// Matcher is a compiled config.Match.
type Matcher struct {
	src, dst, any       *netset.Set
	srcList, dstList    *netset.Set
	anyList             *netset.Set
	srcPort, dstPort    []portRange
	proto               map[uint8]bool
	exporter            *netset.Set
	action, logStatus   map[string]bool
	direction, source   map[string]bool
	bytesLT, bytesGT    *uint64
	pktsLT, pktsGT      *uint64
	flagsAny, flagsNone *uint8
	not                 *Matcher
	empty               bool
}

type portRange struct{ lo, hi uint16 }

// ListLoader loads named IP lists (files). baseDir resolves relative paths.
type ListLoader struct {
	BaseDir string
	cache   map[string]*netset.Set
}

func (l *ListLoader) load(p string) (*netset.Set, error) {
	if p == "" {
		return nil, nil
	}
	if !filepath.IsAbs(p) && l.BaseDir != "" {
		p = filepath.Join(l.BaseDir, p)
	}
	if l.cache == nil {
		l.cache = map[string]*netset.Set{}
	}
	if s, ok := l.cache[p]; ok {
		return s, nil
	}
	s, err := netset.LoadFile(p)
	if err != nil {
		return nil, fmt.Errorf("load list %s: %w", p, err)
	}
	l.cache[p] = s
	return s, nil
}

// Compile builds a Matcher.
func Compile(m config.Match, ll *ListLoader) (*Matcher, error) {
	c := &Matcher{empty: m.IsEmpty()}
	var err error
	set := func(items []string) (*netset.Set, error) {
		if len(items) == 0 {
			return nil, nil
		}
		return netset.Parse(items)
	}
	if c.src, err = set(m.SrcCIDR); err != nil {
		return nil, err
	}
	if c.dst, err = set(m.DstCIDR); err != nil {
		return nil, err
	}
	if c.any, err = set(m.AnyCIDR); err != nil {
		return nil, err
	}
	if c.exporter, err = set(m.Exporter); err != nil {
		return nil, err
	}
	if c.srcList, err = ll.load(m.SrcInList); err != nil {
		return nil, err
	}
	if c.dstList, err = ll.load(m.DstInList); err != nil {
		return nil, err
	}
	if c.anyList, err = ll.load(m.AnyInList); err != nil {
		return nil, err
	}
	if c.srcPort, err = ports(m.SrcPort); err != nil {
		return nil, err
	}
	if c.dstPort, err = ports(m.DstPort); err != nil {
		return nil, err
	}
	if len(m.Proto) > 0 {
		c.proto = map[uint8]bool{}
		for _, p := range m.Proto {
			p = strings.ToLower(strings.TrimSpace(p))
			if n, ok := flow.ProtoNumber(p); ok {
				c.proto[n] = true
				continue
			}
			n, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid proto %q", p)
			}
			c.proto[uint8(n)] = true
		}
	}
	c.action = upperSet(m.Action)
	c.logStatus = upperSet(m.LogStatus)
	c.direction = lowerSet(m.Direction)
	c.source = lowerSet(m.Source)
	for d := range c.direction {
		switch d {
		case flow.DirInternal, flow.DirInbound, flow.DirOutbound, flow.DirExternal:
		default:
			return nil, fmt.Errorf("invalid direction %q (internal|inbound|outbound|external)", d)
		}
	}
	c.bytesLT, c.bytesGT, c.pktsLT, c.pktsGT = m.BytesLT, m.BytesGT, m.PacketsLT, m.PacketsGT
	c.flagsAny, c.flagsNone = m.TCPFlagsAny, m.TCPFlagsNone
	if m.Not != nil {
		if c.not, err = Compile(*m.Not, ll); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func upperSet(v []string) map[string]bool {
	if len(v) == 0 {
		return nil
	}
	m := map[string]bool{}
	for _, s := range v {
		m[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	return m
}

func lowerSet(v []string) map[string]bool {
	if len(v) == 0 {
		return nil
	}
	m := map[string]bool{}
	for _, s := range v {
		m[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return m
}

func ports(items []string) ([]portRange, error) {
	var out []portRange
	for _, it := range items {
		it = strings.TrimSpace(it)
		lo, hi := it, it
		if i := strings.IndexByte(it, '-'); i > 0 {
			lo, hi = it[:i], it[i+1:]
		}
		l, err1 := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		h, err2 := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
		if err1 != nil || err2 != nil || l > h {
			return nil, fmt.Errorf("invalid port or range %q", it)
		}
		out = append(out, portRange{uint16(l), uint16(h)})
	}
	return out, nil
}

func inPorts(rs []portRange, p uint16) bool {
	for _, r := range rs {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

func inSet(s *netset.Set, a netip.Addr) bool { return s.Contains(a) }

// Match evaluates the matcher against a flow.
func (c *Matcher) Match(f *flow.Flow) bool {
	if c.empty {
		return true
	}
	if c.src != nil && !inSet(c.src, f.Src) {
		return false
	}
	if c.dst != nil && !inSet(c.dst, f.Dst) {
		return false
	}
	if c.any != nil && !inSet(c.any, f.Src) && !inSet(c.any, f.Dst) {
		return false
	}
	if c.srcList != nil && !inSet(c.srcList, f.Src) {
		return false
	}
	if c.dstList != nil && !inSet(c.dstList, f.Dst) {
		return false
	}
	if c.anyList != nil && !inSet(c.anyList, f.Src) && !inSet(c.anyList, f.Dst) {
		return false
	}
	if c.srcPort != nil && !inPorts(c.srcPort, f.SrcPort) {
		return false
	}
	if c.dstPort != nil && !inPorts(c.dstPort, f.DstPort) {
		return false
	}
	if c.proto != nil && !c.proto[f.Proto] {
		return false
	}
	if c.exporter != nil && !inSet(c.exporter, f.Exporter) {
		return false
	}
	if c.action != nil && !c.action[strings.ToUpper(f.Action)] {
		return false
	}
	if c.logStatus != nil && !c.logStatus[strings.ToUpper(f.LogStatus)] {
		return false
	}
	if c.direction != nil && !c.direction[f.Direction] {
		return false
	}
	if c.source != nil && !c.source[f.Source] {
		return false
	}
	if c.bytesLT != nil && !(f.Bytes < *c.bytesLT) {
		return false
	}
	if c.bytesGT != nil && !(f.Bytes > *c.bytesGT) {
		return false
	}
	if c.pktsLT != nil && !(f.Packets < *c.pktsLT) {
		return false
	}
	if c.pktsGT != nil && !(f.Packets > *c.pktsGT) {
		return false
	}
	if c.flagsAny != nil && f.TCPFlags&*c.flagsAny == 0 {
		return false
	}
	if c.flagsNone != nil && f.TCPFlags&*c.flagsNone != 0 {
		return false
	}
	if c.not != nil && c.not.Match(f) {
		return false
	}
	return true
}

// Classify sets f.Direction from the internal network set.
func Classify(f *flow.Flow, internal *netset.Set) {
	si, di := internal.Contains(f.Src), internal.Contains(f.Dst)
	switch {
	case si && di:
		f.Direction = flow.DirInternal
	case si:
		f.Direction = flow.DirOutbound
	case di:
		f.Direction = flow.DirInbound
	default:
		f.Direction = flow.DirExternal
	}
}
