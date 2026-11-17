// Package rules is the reduction engine. It is single-threaded by design:
// the app feeds it from one goroutine, which keeps state handling simple and
// deterministic. Pipeline per flow:
//
//	dedup(if apply_to_bypass) -> bypass -> dedup -> drop -> fanout observe -> rollup | raw
//
// Golden rule: reduction only touches known-boring traffic. Bypass rules
// (intel hits, denies, lateral-movement ports) always pass through raw.
package rules

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"math"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trip-nine/flowtrim/internal/config"
	"github.com/trip-nine/flowtrim/internal/flow"
	"github.com/trip-nine/flowtrim/internal/netset"
	"github.com/trip-nine/flowtrim/internal/ocsf"
)

// Decision labels (used in metrics).
const (
	DecBypass = "bypass"
	DecDrop   = "drop"
	DecDedup  = "dedup"
	DecRollup = "rollup"
	DecRaw    = "raw"
)

// Hooks lets the caller observe decisions (metrics) without this package
// depending on Prometheus.
type Hooks struct {
	Decision func(decision, rule string)
	Gauge    func(name string, v float64)
}

// Engine holds compiled rules and reduction state.
type Engine struct {
	cfg         *config.Config
	internal    *netset.Set
	bypass      []namedMatcher
	drop        []namedMatcher
	rollupMatch *Matcher
	prune       [][]string
	scale       bool
	samplingOv  []samplingOverride
	emit        func(ocsf.Event)
	hooks       Hooks
	shadow      bool

	seed maphash.Seed

	// dedup
	dedupOn      bool
	dedupFirst   bool
	dedupKey     []string
	dedupTol     int64 // ns
	dedupWin     time.Duration
	dedupMax     int
	dedupSeen    map[uint64]int64 // hash -> expiry unix ns
	dedupFIFO    []dedupEntry
	dedupFIFOpos int

	// rollup
	rollOn   bool
	rollKey  []string
	rollWin  time.Duration
	rollMax  int
	rollIAT  int
	aggs     map[string]*agg
	aggFIFO  []string
	aggPos   int
	keySrcPt bool

	// fanout
	fanOn   bool
	fanCfg  config.Fanout
	fans    map[netip.Addr]*fan
	fanFIFO []netip.Addr
	fanPos  int

	// drop summary
	dsOn       bool
	dsInterval time.Duration
	dsNext     time.Time
	dsCounts   map[string]*dropCount

	keyBuf []byte
}

type samplingOverride struct {
	set   *netset.Set
	rate  uint64
	force bool
}

type namedMatcher struct {
	name string
	m    *Matcher
}

type dedupEntry struct {
	h   uint64
	exp int64
}

type agg struct {
	tmpl      flow.Flow
	opened    time.Time
	first     time.Time
	last      time.Time
	count     uint64
	bytes     uint64
	packets   uint64
	flags     uint8
	exporters []netip.Addr
	srcPorts  map[uint16]struct{}
	starts    []int64
}

type fan struct {
	opened time.Time
	host   string
	dsts   map[netip.Addr]struct{}
	ports  map[uint16]struct{}
	flows  uint64
	bytes  uint64
	capped bool
}

type dropCount struct{ flows, bytes, packets uint64 }

// New compiles rules. configDir resolves relative list paths.
func New(cfg *config.Config, configDir string, emit func(ocsf.Event), hooks Hooks, shadow bool) (*Engine, error) {
	internal, err := netset.Parse(cfg.Networks.Internal)
	if err != nil {
		return nil, err
	}
	ll := &ListLoader{BaseDir: configDir}
	e := &Engine{cfg: cfg, internal: internal, emit: emit, hooks: hooks, shadow: shadow, seed: maphash.MakeSeed()}
	if e.hooks.Decision == nil {
		e.hooks.Decision = func(string, string) {}
	}
	if e.hooks.Gauge == nil {
		e.hooks.Gauge = func(string, float64) {}
	}
	for _, r := range cfg.Rules.Bypass {
		m, err := Compile(r.Match, ll)
		if err != nil {
			return nil, ruleErr("bypass", r.Name, err)
		}
		e.bypass = append(e.bypass, namedMatcher{r.Name, m})
	}
	for _, r := range cfg.Rules.Drop {
		m, err := Compile(r.Match, ll)
		if err != nil {
			return nil, ruleErr("drop", r.Name, err)
		}
		e.drop = append(e.drop, namedMatcher{r.Name, m})
	}
	e.scale = cfg.Normalize.ScaleBySamplingRate != nil && *cfg.Normalize.ScaleBySamplingRate
	for _, o := range cfg.Normalize.SamplingOverrides {
		s, err := netset.Parse([]string{o.Exporter})
		if err != nil {
			return nil, fmt.Errorf("normalize.sampling_overrides: %w", err)
		}
		e.samplingOv = append(e.samplingOv, samplingOverride{set: s, rate: o.Rate, force: o.Force})
	}
	for _, p := range cfg.Rules.PruneFields {
		e.prune = append(e.prune, strings.Split(p, "."))
	}

	d := cfg.Rules.Dedup
	e.dedupOn = d.Enabled
	e.dedupFirst = d.ApplyToBypass != nil && *d.ApplyToBypass
	e.dedupKey = d.Key
	e.dedupTol = int64(d.StartTolerance.D())
	if e.dedupTol <= 0 {
		e.dedupTol = 1
	}
	e.dedupWin = d.Window.D()
	e.dedupMax = d.MaxEntries
	e.dedupSeen = map[uint64]int64{}

	r := cfg.Rules.Rollup
	e.rollOn = r.Enabled
	if e.rollOn {
		if e.rollupMatch, err = Compile(r.Match, ll); err != nil {
			return nil, ruleErr("rollup", "match", err)
		}
	}
	e.rollKey = r.Key
	e.rollWin = r.Window.D()
	e.rollMax = r.MaxKeys
	e.rollIAT = r.IATSamples
	e.aggs = map[string]*agg{}
	for _, k := range r.Key {
		if k == "src_port" {
			e.keySrcPt = true
		}
	}

	e.fanOn = cfg.Rules.Fanout.Enabled
	e.fanCfg = cfg.Rules.Fanout
	e.fans = map[netip.Addr]*fan{}

	e.dsOn = cfg.Rules.DropSummary.Enabled != nil && *cfg.Rules.DropSummary.Enabled
	e.dsInterval = cfg.Rules.DropSummary.Interval.D()
	e.dsCounts = map[string]*dropCount{}
	return e, nil
}

func ruleErr(group, name string, err error) error {
	return &RuleError{Group: group, Name: name, Err: err}
}

// RuleError identifies the offending rule.
type RuleError struct {
	Group, Name string
	Err         error
}

func (r *RuleError) Error() string { return "rules." + r.Group + " " + r.Name + ": " + r.Err.Error() }

// Normalize applies sampling scaling and direction classification. Inputs call
// it once per flow before Process.
func (e *Engine) Normalize(f *flow.Flow) {
	if !f.Scaled {
		for _, o := range e.samplingOv {
			if o.set.Contains(f.Exporter) {
				if o.force || f.SamplingRate <= 1 {
					f.SamplingRate = o.rate
				}
				break
			}
		}
	}
	if e.scale && f.SamplingRate > 1 && !f.Scaled {
		f.Bytes *= f.SamplingRate
		f.Packets *= f.SamplingRate
		f.Scaled = true
	}
	if f.Start.IsZero() {
		f.Start = f.Received
	}
	if f.End.IsZero() {
		f.End = f.Start
	}
	Classify(f, e.internal)
}

// Process runs one flow through the pipeline. now is processing time.
func (e *Engine) Process(f *flow.Flow, now time.Time) {
	if e.dedupOn && e.dedupFirst && e.isDup(f, now) {
		e.hooks.Decision(DecDedup, "")
		return
	}
	for _, b := range e.bypass {
		if b.m.Match(f) {
			e.hooks.Decision(DecBypass, b.name)
			e.observeFanout(f, now)
			e.out(ocsf.FromFlow(f, f.Start, f.End, f.Bytes, f.Packets, f.TCPFlags, e.red("bypass", b.name, 0)))
			return
		}
	}
	if e.dedupOn && !e.dedupFirst && e.isDup(f, now) {
		e.hooks.Decision(DecDedup, "")
		return
	}
	for _, d := range e.drop {
		if d.m.Match(f) {
			e.hooks.Decision(DecDrop, d.name)
			if e.dsOn {
				c := e.dsCounts[d.name]
				if c == nil {
					c = &dropCount{}
					e.dsCounts[d.name] = c
				}
				c.flows++
				c.bytes += f.Bytes
				c.packets += f.Packets
			}
			return
		}
	}
	e.observeFanout(f, now)
	if e.rollOn && e.rollupMatch.Match(f) {
		if e.addRollup(f, now) {
			e.hooks.Decision(DecRollup, "")
			return
		}
	}
	e.hooks.Decision(DecRaw, "")
	e.out(ocsf.FromFlow(f, f.Start, f.End, f.Bytes, f.Packets, f.TCPFlags, e.red("none", "", 0)))
}

func (e *Engine) red(kind, rule string, n uint64) ocsf.Reduction {
	return ocsf.Reduction{Kind: kind, Rule: rule, FlowCount: n, RuleVersion: e.cfg.RuleVersion, Shadow: false}
}

func (e *Engine) out(ev ocsf.Event) {
	if len(e.prune) > 0 {
		ocsf.Prune(ev.Body, e.prune)
	}
	e.emit(ev)
}

// ---- dedup ----

func (e *Engine) dedupHash(f *flow.Flow, bucket int64) uint64 {
	b := e.keyBuf[:0]
	for _, k := range e.dedupKey {
		b = appendField(b, f, k)
		if k == "start_time" {
			b = binary.BigEndian.AppendUint64(b, uint64(bucket))
		}
	}
	e.keyBuf = b
	return maphash.Bytes(e.seed, b)
}

func (e *Engine) isDup(f *flow.Flow, now time.Time) bool {
	bucket := f.Start.UnixNano() / e.dedupTol
	h := e.dedupHash(f, bucket)
	nowNs := now.UnixNano()
	if exp, ok := e.dedupSeen[h]; ok && exp > nowNs {
		return true
	}
	// a duplicate whose start time straddles a tolerance boundary
	for _, nb := range [2]int64{bucket - 1, bucket + 1} {
		if exp, ok := e.dedupSeen[e.dedupHash(f, nb)]; ok && exp > nowNs {
			return true
		}
	}
	if len(e.dedupSeen) >= e.dedupMax {
		e.hooks.Decision("dedup_capacity_exceeded", "")
		return false // fail open: never drop because we're full
	}
	exp := nowNs + int64(e.dedupWin)
	e.dedupSeen[h] = exp
	e.dedupFIFO = append(e.dedupFIFO, dedupEntry{h, exp})
	return false
}

func (e *Engine) sweepDedup(now time.Time) {
	nowNs := now.UnixNano()
	for e.dedupFIFOpos < len(e.dedupFIFO) {
		d := e.dedupFIFO[e.dedupFIFOpos]
		if d.exp > nowNs {
			break
		}
		if e.dedupSeen[d.h] == d.exp {
			delete(e.dedupSeen, d.h)
		}
		e.dedupFIFOpos++
	}
	if e.dedupFIFOpos > 4096 && e.dedupFIFOpos*2 > len(e.dedupFIFO) {
		e.dedupFIFO = append(e.dedupFIFO[:0], e.dedupFIFO[e.dedupFIFOpos:]...)
		e.dedupFIFOpos = 0
	}
}

// ---- rollup ----

func (e *Engine) rollupKey(f *flow.Flow) string {
	b := e.keyBuf[:0]
	for _, k := range e.rollKey {
		b = appendField(b, f, k)
	}
	e.keyBuf = b
	return string(b)
}

func (e *Engine) addRollup(f *flow.Flow, now time.Time) bool {
	k := e.rollupKey(f)
	a := e.aggs[k]
	if a == nil {
		if len(e.aggs) >= e.rollMax {
			e.hooks.Decision("rollup_capacity_exceeded", "")
			return false // pass raw rather than drop
		}
		a = &agg{tmpl: *f, opened: now, first: f.Start, last: f.End}
		if !e.keySrcPt {
			a.srcPorts = map[uint16]struct{}{}
		}
		e.aggs[k] = a
		e.aggFIFO = append(e.aggFIFO, k)
	}
	a.count++
	a.bytes += f.Bytes
	a.packets += f.Packets
	a.flags |= f.TCPFlags
	if f.Start.Before(a.first) {
		a.first = f.Start
	}
	if f.End.After(a.last) {
		a.last = f.End
	}
	if f.Exporter.IsValid() && len(a.exporters) < 8 && !containsAddr(a.exporters, f.Exporter) {
		a.exporters = append(a.exporters, f.Exporter)
	}
	if a.srcPorts != nil && len(a.srcPorts) < 4096 {
		a.srcPorts[f.SrcPort] = struct{}{}
	}
	if len(a.starts) < e.rollIAT {
		a.starts = append(a.starts, f.Start.UnixMilli())
	}
	return true
}

func containsAddr(s []netip.Addr, a netip.Addr) bool {
	for _, x := range s {
		if x == a {
			return true
		}
	}
	return false
}

func (e *Engine) flushAgg(k string, a *agg) {
	delete(e.aggs, k)
	t := a.tmpl
	if a.count == 1 {
		e.out(ocsf.FromFlow(&t, t.Start, t.End, t.Bytes, t.Packets, t.TCPFlags, e.red("none", "", 0)))
		return
	}
	red := e.red("rollup", "", a.count)
	for _, x := range a.exporters {
		red.Exporters = append(red.Exporters, x.String())
	}
	if a.srcPorts != nil {
		red.SrcPorts = len(a.srcPorts)
		if red.SrcPorts == 1 {
			for p := range a.srcPorts {
				t.SrcPort = p
			}
		}
	}
	red.IAT = iat(a.starts)
	e.out(ocsf.FromFlow(&t, a.first, a.last, a.bytes, a.packets, a.flags, red))
}

func iat(starts []int64) *ocsf.IATStats {
	if len(starts) < 3 {
		return nil
	}
	s := append([]int64(nil), starts...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s) - 1
	mn, mx, sum := math.MaxFloat64, 0.0, 0.0
	d := make([]float64, n)
	for i := 0; i < n; i++ {
		d[i] = float64(s[i+1] - s[i])
		sum += d[i]
		mn = math.Min(mn, d[i])
		mx = math.Max(mx, d[i])
	}
	mean := sum / float64(n)
	v := 0.0
	for _, x := range d {
		v += (x - mean) * (x - mean)
	}
	return &ocsf.IATStats{Samples: len(s), Min: mn, Max: mx, Mean: round2(mean), Stddev: round2(math.Sqrt(v / float64(n)))}
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func (e *Engine) sweepRollup(now time.Time, all bool) {
	for e.aggPos < len(e.aggFIFO) {
		k := e.aggFIFO[e.aggPos]
		a := e.aggs[k]
		if a != nil {
			if !all && now.Sub(a.opened) < e.rollWin {
				break
			}
			e.flushAgg(k, a)
		}
		e.aggPos++
	}
	if e.aggPos > 4096 && e.aggPos*2 > len(e.aggFIFO) {
		e.aggFIFO = append(e.aggFIFO[:0], e.aggFIFO[e.aggPos:]...)
		e.aggPos = 0
	}
}

// ---- fanout ----

func (e *Engine) observeFanout(f *flow.Flow, now time.Time) {
	if !e.fanOn || !f.Src.IsValid() {
		return
	}
	fn := e.fans[f.Src]
	if fn == nil {
		if len(e.fans) >= e.fanCfg.MaxSources {
			return
		}
		fn = &fan{opened: now, host: f.HostLabel(), dsts: map[netip.Addr]struct{}{}, ports: map[uint16]struct{}{}}
		e.fans[f.Src] = fn
		e.fanFIFO = append(e.fanFIFO, f.Src)
	}
	fn.flows++
	fn.bytes += f.Bytes
	if len(fn.dsts) < e.fanCfg.Cap {
		fn.dsts[f.Dst] = struct{}{}
	} else {
		fn.capped = true
	}
	if len(fn.ports) < e.fanCfg.Cap {
		fn.ports[f.DstPort] = struct{}{}
	} else {
		fn.capped = true
	}
}

func (e *Engine) sweepFanout(now time.Time, all bool) {
	win := e.fanCfg.Window.D()
	for e.fanPos < len(e.fanFIFO) {
		src := e.fanFIFO[e.fanPos]
		fn := e.fans[src]
		if fn != nil {
			if !all && now.Sub(fn.opened) < win {
				break
			}
			delete(e.fans, src)
			if len(fn.dsts) >= e.fanCfg.MinUniqueDstIPs || len(fn.ports) >= e.fanCfg.MinUniqueDstPorts {
				ev := ocsf.Summary("fanout_summary", now, fn.host, map[string]any{
					"src_ip":           src.String(),
					"flows":            fn.flows,
					"bytes":            fn.bytes,
					"unique_dst_ips":   len(fn.dsts),
					"unique_dst_ports": len(fn.ports),
					"capped":           fn.capped,
					"cap":              e.fanCfg.Cap,
					"window_s":         int(win.Seconds()),
				}, e.cfg.RuleVersion)
				ev.Body["src_endpoint"] = map[string]any{"ip": src.String()}
				e.out(ev)
			}
		}
		e.fanPos++
	}
	if e.fanPos > 4096 && e.fanPos*2 > len(e.fanFIFO) {
		e.fanFIFO = append(e.fanFIFO[:0], e.fanFIFO[e.fanPos:]...)
		e.fanPos = 0
	}
}

// ---- drop summary ----

func (e *Engine) flushDropSummary(now time.Time) {
	if !e.dsOn {
		return
	}
	names := make([]string, 0, len(e.dsCounts))
	for n := range e.dsCounts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := e.dsCounts[n]
		e.out(ocsf.Summary("drop_summary", now, "flowtrim", map[string]any{
			"rule":       n,
			"flows":      c.flows,
			"bytes":      c.bytes,
			"packets":    c.packets,
			"interval_s": int(e.dsInterval.Seconds()),
		}, e.cfg.RuleVersion))
	}
	e.dsCounts = map[string]*dropCount{}
}

// Tick flushes expired windows. Call about once per second.
func (e *Engine) Tick(now time.Time) {
	if e.dedupOn {
		e.sweepDedup(now)
	}
	if e.rollOn {
		e.sweepRollup(now, false)
	}
	if e.fanOn {
		e.sweepFanout(now, false)
	}
	if e.dsOn {
		if e.dsNext.IsZero() {
			e.dsNext = now.Add(e.dsInterval)
		} else if !now.Before(e.dsNext) {
			e.flushDropSummary(now)
			e.dsNext = now.Add(e.dsInterval)
		}
	}
	e.hooks.Gauge("dedup_entries", float64(len(e.dedupSeen)))
	e.hooks.Gauge("rollup_active_keys", float64(len(e.aggs)))
	e.hooks.Gauge("fanout_active_sources", float64(len(e.fans)))
}

// FlushAll emits all pending state (shutdown, rule reload).
func (e *Engine) FlushAll(now time.Time) {
	e.sweepRollup(now, true)
	e.sweepFanout(now, true)
	e.flushDropSummary(now)
}

// ---- keys ----

func appendAddr(b []byte, a netip.Addr) []byte {
	x := a.As16()
	return append(b, x[:]...)
}

func appendField(b []byte, f *flow.Flow, k string) []byte {
	switch k {
	case "src_ip":
		return appendAddr(b, f.Src)
	case "dst_ip":
		return appendAddr(b, f.Dst)
	case "src_port":
		return binary.BigEndian.AppendUint16(b, f.SrcPort)
	case "dst_port":
		return binary.BigEndian.AppendUint16(b, f.DstPort)
	case "proto":
		return append(b, f.Proto)
	case "action":
		return append(append(b, strings.ToUpper(f.Action)...), 0)
	case "exporter":
		return appendAddr(b, f.Exporter)
	case "in_if":
		return binary.BigEndian.AppendUint32(b, f.InIf)
	case "out_if":
		return binary.BigEndian.AppendUint32(b, f.OutIf)
	case "direction":
		return append(append(b, f.Direction...), 0)
	case "source":
		return append(append(b, f.Source...), 0)
	case "end_time":
		return binary.BigEndian.AppendUint64(b, uint64(f.End.UnixMilli()))
	case "bytes":
		return binary.BigEndian.AppendUint64(b, f.Bytes)
	case "packets":
		return binary.BigEndian.AppendUint64(b, f.Packets)
	case "tcp_flags":
		return append(b, f.TCPFlags)
	case "start_time":
		return b // bucket appended by caller
	}
	return b
}

// ConfigDir returns the directory of a config path (for relative list files).
func ConfigDir(path string) string { return filepath.Dir(path) }
