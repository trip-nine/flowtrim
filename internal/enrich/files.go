package enrich

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/trip-nine/flowtrim/internal/netset"
)

func resolve(base, p string) string {
	if p == "" || filepath.IsAbs(p) || base == "" {
		return p
	}
	return filepath.Join(base, p)
}

func readYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// loadHostnames: YAML map ip -> hostname.
func loadHostnames(path string) (map[netip.Addr]string, error) {
	raw := map[string]string{}
	if err := readYAML(path, &raw); err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]string, len(raw))
	for k, v := range raw {
		a, err := netip.ParseAddr(strings.TrimSpace(k))
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", path, k, err)
		}
		out[a.Unmap()] = v
	}
	return out, nil
}

// prefixTable maps CIDRs to values with longest-prefix match.
type prefixTable[T any] struct {
	byLen []int // descending
	m     map[int]map[netip.Prefix]T
}

func newPrefixTable[T any]() *prefixTable[T] {
	return &prefixTable[T]{m: map[int]map[netip.Prefix]T{}}
}

func (t *prefixTable[T]) add(cidr string, v T) error {
	cidr = strings.TrimSpace(cidr)
	if !strings.Contains(cidr, "/") {
		a, err := netip.ParseAddr(cidr)
		if err != nil {
			return err
		}
		cidr = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String()
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	p = p.Masked()
	k := p.Bits()
	if p.Addr().Is6() {
		k += 1000
	}
	if t.m[k] == nil {
		t.m[k] = map[netip.Prefix]T{}
		t.byLen = append(t.byLen, k)
		sort.Sort(sort.Reverse(sort.IntSlice(t.byLen)))
	}
	t.m[k][p] = v
	return nil
}

func (t *prefixTable[T]) lookup(a netip.Addr) (T, bool) {
	var zero T
	if t == nil || !a.IsValid() {
		return zero, false
	}
	a = a.Unmap()
	for _, k := range t.byLen {
		bits := k
		if k >= 1000 {
			if !a.Is6() {
				continue
			}
			bits = k - 1000
		} else if !a.Is4() {
			continue
		}
		p, err := a.Prefix(bits)
		if err != nil {
			continue
		}
		if v, ok := t.m[k][p]; ok {
			return v, true
		}
	}
	return zero, false
}

// loadMetadata: YAML list of {cidr, tags{key: value}}.
func loadMetadata(path string) (*prefixTable[map[string]string], error) {
	var raw []struct {
		CIDR string            `yaml:"cidr"`
		Tags map[string]string `yaml:"tags"`
	}
	if err := readYAML(path, &raw); err != nil {
		return nil, err
	}
	t := newPrefixTable[map[string]string]()
	for _, r := range raw {
		if err := t.add(r.CIDR, r.Tags); err != nil {
			return nil, fmt.Errorf("%s: %q: %w", path, r.CIDR, err)
		}
	}
	return t, nil
}

// loadApps: YAML map app name -> [cidr...] (e.g. Microsoft 365, Salesforce, Zoom ranges).
func loadApps(path string) (*prefixTable[string], error) {
	raw := map[string][]string{}
	if err := readYAML(path, &raw); err != nil {
		return nil, err
	}
	t := newPrefixTable[string]()
	for name, cidrs := range raw {
		for _, c := range cidrs {
			if err := t.add(c, name); err != nil {
				return nil, fmt.Errorf("%s: app %q: %w", path, name, err)
			}
		}
	}
	return t, nil
}

// loadServices: YAML map "tcp/8443" -> name.
func loadServices(path string) (map[string]string, error) {
	raw := map[string]string{}
	if err := readYAML(path, &raw); err != nil {
		return nil, err
	}
	for k := range raw {
		parts := strings.SplitN(k, "/", 2)
		if len(parts) != 2 || (parts[0] != "tcp" && parts[0] != "udp" && parts[0] != "sctp") {
			return nil, fmt.Errorf("%s: key %q must look like tcp/8443", path, k)
		}
		if _, err := strconv.ParseUint(parts[1], 10, 16); err != nil {
			return nil, fmt.Errorf("%s: key %q: bad port", path, k)
		}
	}
	return raw, nil
}

// loadInterfaces: YAML map exporter_ip -> ifindex -> Iface.
func loadInterfaces(path string) (ifTable, error) {
	raw := map[string]map[uint32]Iface{}
	if err := readYAML(path, &raw); err != nil {
		return nil, err
	}
	out := ifTable{}
	for k, v := range raw {
		a, err := netip.ParseAddr(strings.TrimSpace(k))
		if err != nil {
			return nil, fmt.Errorf("%s: exporter %q: %w", path, k, err)
		}
		out[a.Unmap()] = v
	}
	return out, nil
}

type threatList struct {
	name, severity string
	set            *netset.Set
}
