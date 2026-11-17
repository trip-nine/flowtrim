package enrich

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/trip-nine/flowtrim/internal/config"
	"github.com/trip-nine/flowtrim/internal/netset"
)

// dnsCache does reverse lookups off the hot path: a cache miss queues the
// IP for background workers and returns "" immediately, so a slow DNS
// server never slows the pipeline. The next record for that IP gets the name.
type dnsCache struct {
	mu       sync.RWMutex
	entries  map[netip.Addr]dnsEntry
	pending  map[netip.Addr]struct{}
	q        chan netip.Addr
	res      *net.Resolver
	timeout  time.Duration
	ttl      time.Duration
	negTTL   time.Duration
	max      int
	include  *netset.Set
	exclude  *netset.Set
	internal *netset.Set // set when include_cidrs contains "internal"
	done     chan struct{}
	wg       sync.WaitGroup
	onLookup func(result string)
}

type dnsEntry struct {
	name string
	exp  time.Time
}

func newDNS(c config.DNS, internal *netset.Set, onLookup func(string)) (*dnsCache, error) {
	d := &dnsCache{
		entries: map[netip.Addr]dnsEntry{}, pending: map[netip.Addr]struct{}{},
		q: make(chan netip.Addr, c.Queue), timeout: c.Timeout.D(), ttl: c.CacheTTL.D(),
		negTTL: c.NegativeTTL.D(), max: c.MaxEntries, done: make(chan struct{}), onLookup: onLookup,
	}
	inc := netset.New()
	for _, x := range c.Include {
		if x == "internal" {
			d.internal = internal
			continue
		}
		if err := inc.Add(x); err != nil {
			return nil, err
		}
	}
	d.include = inc
	var err error
	if d.exclude, err = netset.Parse(c.Exclude); err != nil {
		return nil, err
	}
	d.res = net.DefaultResolver
	if c.Nameserver != "" {
		ns := c.Nameserver
		if !strings.Contains(ns, ":") || strings.Count(ns, ":") > 1 && !strings.HasPrefix(ns, "[") {
			ns = net.JoinHostPort(ns, "53")
		}
		d.res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, network, ns)
		}}
	}
	for i := 0; i < c.Workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	go d.sweeper()
	return d, nil
}

func (d *dnsCache) inScope(a netip.Addr) bool {
	if d.exclude.Contains(a) {
		return false
	}
	return d.include.Contains(a) || d.internal.Contains(a)
}

// Get returns a cached hostname, or "" (and queues a lookup) on a miss.
func (d *dnsCache) Get(a netip.Addr) string {
	if !a.IsValid() || !d.inScope(a) {
		return ""
	}
	now := time.Now()
	d.mu.RLock()
	e, ok := d.entries[a]
	_, isPending := d.pending[a]
	d.mu.RUnlock()
	if ok && now.Before(e.exp) {
		return e.name
	}
	if isPending {
		return e.name
	}
	d.mu.Lock()
	if len(d.pending) < cap(d.q) {
		d.pending[a] = struct{}{}
		select {
		case d.q <- a:
		default:
			delete(d.pending, a)
		}
	}
	d.mu.Unlock()
	return e.name // stale name (if any) is better than none while refreshing
}

func (d *dnsCache) worker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.done:
			return
		case a := <-d.q:
			ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
			names, err := d.res.LookupAddr(ctx, a.String())
			cancel()
			name, ttl, result := "", d.negTTL, "miss"
			if err == nil && len(names) > 0 {
				name, ttl, result = strings.TrimSuffix(names[0], "."), d.ttl, "hit"
			}
			d.mu.Lock()
			delete(d.pending, a)
			if len(d.entries) < d.max {
				d.entries[a] = dnsEntry{name: name, exp: time.Now().Add(ttl)}
			}
			d.mu.Unlock()
			if d.onLookup != nil {
				d.onLookup(result)
			}
		}
	}
}

func (d *dnsCache) sweeper() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-d.done:
			return
		case now := <-t.C:
			d.mu.Lock()
			for k, v := range d.entries {
				if now.After(v.exp.Add(d.ttl)) { // keep stale entries one extra TTL
					delete(d.entries, k)
				}
			}
			d.mu.Unlock()
		}
	}
}

func (d *dnsCache) close() {
	close(d.done)
	d.wg.Wait()
}
