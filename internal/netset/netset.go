// Package netset provides a fast set of IP prefixes and exact addresses,
// used for CIDR matchers, internal-network classification, and intel lists.
package netset

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Set holds exact addresses and prefixes grouped by length. Lookup cost is
// O(number of distinct prefix lengths), at most 33 for IPv4 and 129 for IPv6,
// independent of how many entries the set holds.
type Set struct {
	exact  map[netip.Addr]struct{}
	byBits map[int]map[netip.Prefix]struct{}
	bits4  []int
	bits6  []int
	n      int
}

// New returns an empty set.
func New() *Set {
	return &Set{exact: map[netip.Addr]struct{}{}, byBits: map[int]map[netip.Prefix]struct{}{}}
}

// Parse builds a set from strings like "10.0.0.0/8", "192.0.2.7", "2001:db8::/32".
func Parse(items []string) (*Set, error) {
	s := New()
	for _, it := range items {
		if err := s.Add(it); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Add inserts one address or prefix.
func (s *Set) Add(item string) error {
	item = strings.TrimSpace(item)
	if item == "" {
		return nil
	}
	if strings.Contains(item, "/") {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", item, err)
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.IsSingleIP() {
			s.exact[p.Addr()] = struct{}{}
			s.n++
			return nil
		}
		// key on family+bits so v4 /8 and v6 /8 don't collide
		k := p.Bits()
		if p.Addr().Is6() {
			k += 1000
		}
		m, ok := s.byBits[k]
		if !ok {
			m = map[netip.Prefix]struct{}{}
			s.byBits[k] = m
			if p.Addr().Is4() {
				s.bits4 = append(s.bits4, p.Bits())
				sort.Sort(sort.Reverse(sort.IntSlice(s.bits4)))
			} else {
				s.bits6 = append(s.bits6, p.Bits())
				sort.Sort(sort.Reverse(sort.IntSlice(s.bits6)))
			}
		}
		m[p] = struct{}{}
		s.n++
		return nil
	}
	a, err := netip.ParseAddr(item)
	if err != nil {
		return fmt.Errorf("invalid IP %q: %w", item, err)
	}
	s.exact[a.Unmap()] = struct{}{}
	s.n++
	return nil
}

// Contains reports whether a is in the set.
func (s *Set) Contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if _, ok := s.exact[a]; ok {
		return true
	}
	bits, off := s.bits4, 0
	if a.Is6() {
		bits, off = s.bits6, 1000
	}
	for _, b := range bits {
		p, err := a.Prefix(b)
		if err != nil {
			continue
		}
		if _, ok := s.byBits[b+off][p]; ok {
			return true
		}
	}
	return false
}

// Len returns the number of entries added.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return s.n
}

// LoadFile reads one IP or CIDR per line; '#' starts a comment.
func LoadFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read parses a list from r.
func Read(r io.Reader) (*Set, error) {
	s := New()
	sc := bufio.NewScanner(r)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		// allow "ip,comment" style feeds: take first field
		if i := strings.IndexAny(line, ", \t"); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if err := s.Add(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", ln, err)
		}
	}
	return s, sc.Err()
}
