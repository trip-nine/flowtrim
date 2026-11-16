package rules

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tripnine/flowtrim/internal/config"
	"github.com/tripnine/flowtrim/internal/flow"
	"github.com/tripnine/flowtrim/internal/ocsf"
)

const baseYAML = `
mode: enforce
inputs: { netflow: { listen: ["127.0.0.1:0"] } }
output: { stdout: true }
rules:
  bypass:
    - name: intel
      match: { any_cidr: ["198.51.100.0/24"] }
    - name: denied
      match: { action: [REJECT] }
  drop:
    - name: dns
      match: { proto: [udp], dst_port: ["53"], dst_cidr: ["10.0.0.53/32"] }
  dedup: { enabled: true, window: 30s, start_tolerance: 1s }
  rollup: { enabled: true, window: 60s, key: [src_ip, dst_ip, dst_port, proto] }
  fanout: { enabled: true, window: 60s, min_unique_dst_ips: 5, min_unique_dst_ports: 1000 }
  drop_summary: { enabled: true, interval: 10s }
`

type rec struct{ evs []ocsf.Event }

func (r *rec) emit(e ocsf.Event) { r.evs = append(r.evs, e) }
func (r *rec) kinds() map[string]int {
	m := map[string]int{}
	for _, e := range r.evs {
		m[e.Kind]++
	}
	return m
}

func newEngine(t *testing.T, y string) (*Engine, *rec, map[string]int) {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	r := &rec{}
	dec := map[string]int{}
	e, err := New(cfg, ".", r.emit, Hooks{Decision: func(d, rule string) { dec[d+":"+rule]++ }}, false)
	if err != nil {
		t.Fatal(err)
	}
	return e, r, dec
}

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func mk(src, dst string, sp, dp uint16, proto uint8, exp string, start time.Time, bytes uint64) *flow.Flow {
	return &flow.Flow{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), SrcPort: sp, DstPort: dp, Proto: proto,
		Exporter: netip.MustParseAddr(exp), Start: start, End: start.Add(time.Second), Bytes: bytes, Packets: 3, Received: start, Source: "netflow"}
}

func run(e *Engine, f *flow.Flow, now time.Time) { e.Normalize(f); e.Process(f, now) }

func TestDedupAcrossExporters(t *testing.T) {
	e, r, dec := newEngine(t, baseYAML)
	a := mk("10.1.1.1", "93.184.216.34", 50000, 443, 6, "192.0.2.1", t0, 1000)
	b := mk("10.1.1.1", "93.184.216.34", 50000, 443, 6, "192.0.2.2", t0.Add(400*time.Millisecond), 1000) // same flow, other router, skewed clock
	run(e, a, t0)
	run(e, b, t0)
	if dec["dedup:"] != 1 {
		t.Fatalf("expected 1 dedup, got %v", dec)
	}
	e.FlushAll(t0.Add(time.Minute))
	if len(r.evs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(r.evs))
	}
	// different bytes => not a duplicate
	c := mk("10.1.1.1", "93.184.216.34", 50000, 443, 6, "192.0.2.2", t0, 999)
	run(e, c, t0)
	if dec["dedup:"] != 1 {
		t.Fatalf("different flow was deduped: %v", dec)
	}
}

func TestDedupExpires(t *testing.T) {
	e, _, dec := newEngine(t, baseYAML)
	run(e, mk("10.1.1.1", "8.8.8.8", 1, 2, 6, "192.0.2.1", t0, 10), t0)
	e.Tick(t0.Add(31 * time.Second))
	run(e, mk("10.1.1.1", "8.8.8.8", 1, 2, 6, "192.0.2.1", t0, 10), t0.Add(31*time.Second))
	if dec["dedup:"] != 0 {
		t.Fatalf("entry should have expired: %v", dec)
	}
}

func TestBypassBeatsDrop(t *testing.T) {
	e, r, dec := newEngine(t, baseYAML)
	f := mk("10.1.1.1", "10.0.0.53", 4000, 53, 17, "192.0.2.1", t0, 80)
	f.Action = "REJECT" // denied DNS must stay visible even though DNS is dropped
	run(e, f, t0)
	if dec["bypass:denied"] != 1 || len(r.evs) != 1 || r.evs[0].Kind != "bypass" {
		t.Fatalf("bypass should win: dec=%v kinds=%v", dec, r.kinds())
	}
}

func TestDropAndSummary(t *testing.T) {
	e, r, dec := newEngine(t, baseYAML)
	for i := 0; i < 10; i++ {
		run(e, mk("10.1.1.1", "10.0.0.53", uint16(4000+i), 53, 17, "192.0.2.1", t0, 80), t0)
	}
	if dec["drop:dns"] != 10 {
		t.Fatalf("drops: %v", dec)
	}
	e.Tick(t0)
	e.Tick(t0.Add(11 * time.Second))
	k := r.kinds()
	if k["drop_summary"] != 1 {
		t.Fatalf("expected a drop_summary, got %v", k)
	}
	ft := r.evs[0].Body["unmapped"].(map[string]any)["flowtrim"].(map[string]any)
	if ft["flows"].(uint64) != 10 || ft["bytes"].(uint64) != 800 || ft["rule"] != "dns" {
		t.Fatalf("bad summary %v", ft)
	}
}

func TestRollupKeepsSecuritySignal(t *testing.T) {
	e, r, _ := newEngine(t, baseYAML)
	// beacon: every 2s +-10ms, 30 times, distinct src ports
	for i := 0; i < 30; i++ {
		st := t0.Add(time.Duration(i)*2*time.Second + time.Duration(i%3)*5*time.Millisecond)
		f := mk("10.1.5.5", "203.0.113.66", uint16(40000+i), 443, 6, "192.0.2.1", st, 820)
		f.TCPFlags = 0x18
		if i == 0 {
			f.TCPFlags = 0x02
		}
		run(e, f, t0)
	}
	if len(r.evs) != 0 {
		t.Fatal("nothing should emit before window closes")
	}
	e.Tick(t0.Add(61 * time.Second))
	if len(r.evs) != 1 {
		t.Fatalf("want 1 rollup, got %d (%v)", len(r.evs), r.kinds())
	}
	b := r.evs[0].Body
	if b["count"].(uint64) != 30 {
		t.Fatalf("count %v", b["count"])
	}
	if b["traffic"].(map[string]any)["bytes"].(uint64) != 30*820 {
		t.Fatal("bytes not summed")
	}
	if b["connection_info"].(map[string]any)["tcp_flags"].(uint8) != 0x1a {
		t.Fatal("tcp flags not OR-ed")
	}
	ft := b["unmapped"].(map[string]any)["flowtrim"].(map[string]any)
	iat := ft["iat_ms"].(*ocsf.IATStats)
	if iat.Mean < 1990 || iat.Mean > 2010 || iat.Stddev > 10 {
		t.Fatalf("beacon periodicity lost: %+v", iat)
	}
	if ft["distinct_src_ports"].(int) != 30 {
		t.Fatalf("src ports %v", ft["distinct_src_ports"])
	}
	if b["start_time"].(int64) != t0.UnixMilli() {
		t.Fatal("first_seen wrong")
	}
	if _, has := b["src_endpoint"].(map[string]any)["port"]; has {
		t.Fatal("src port should be omitted when many were folded")
	}
}

func TestRollupSingleFlowStaysRaw(t *testing.T) {
	e, r, _ := newEngine(t, baseYAML)
	run(e, mk("10.1.1.1", "93.184.216.34", 5, 443, 6, "192.0.2.1", t0, 1), t0)
	e.FlushAll(t0)
	if r.evs[0].Kind != "raw" {
		t.Fatalf("single flow should not be labelled rollup: %s", r.evs[0].Kind)
	}
}

func TestRollupCapacityFailsOpen(t *testing.T) {
	y := baseYAML + "\n" // reuse but shrink max_keys
	cfg, _ := config.Parse([]byte(y))
	cfg.Rules.Rollup.MaxKeys = 2
	r := &rec{}
	e, _ := New(cfg, ".", r.emit, Hooks{}, false)
	for i := 0; i < 5; i++ {
		run(e, mk("10.1.1.1", "93.184.216.34", 5, uint16(1000+i), 6, "192.0.2.1", t0, 1), t0)
	}
	if len(r.evs) != 3 {
		t.Fatalf("over-capacity flows must pass raw, got %d", len(r.evs))
	}
}

func TestFanoutSummary(t *testing.T) {
	e, r, _ := newEngine(t, baseYAML)
	for i := 1; i <= 20; i++ {
		f := mk("10.1.9.9", netip.AddrFrom4([4]byte{10, 3, 0, byte(i)}).String(), 50000, 445, 6, "192.0.2.1", t0, 60)
		run(e, f, t0)
	}
	e.Tick(t0.Add(61 * time.Second))
	found := false
	for _, ev := range r.evs {
		if ev.Kind == "fanout_summary" {
			found = true
			ft := ev.Body["unmapped"].(map[string]any)["flowtrim"].(map[string]any)
			if ft["unique_dst_ips"].(int) != 20 {
				t.Fatalf("unique dsts %v", ft["unique_dst_ips"])
			}
		}
	}
	if !found {
		t.Fatalf("no fanout summary: %v", r.kinds())
	}
}

func TestSamplingScaledOnce(t *testing.T) {
	e, r, _ := newEngine(t, baseYAML)
	f := mk("10.1.1.1", "93.184.216.34", 5, 443, 6, "192.0.2.1", t0, 100)
	f.SamplingRate = 10
	e.Normalize(f)
	e.Normalize(f)
	e.Process(f, t0)
	e.FlushAll(t0)
	if got := r.evs[0].Body["traffic"].(map[string]any)["bytes"].(uint64); got != 1000 {
		t.Fatalf("want 1000 scaled bytes, got %d", got)
	}
}

func TestDirection(t *testing.T) {
	e, _, _ := newEngine(t, baseYAML)
	cases := map[[2]string]string{
		{"10.0.0.1", "10.0.0.2"}:   flow.DirInternal,
		{"10.0.0.1", "8.8.8.8"}:    flow.DirOutbound,
		{"8.8.8.8", "192.168.1.1"}: flow.DirInbound,
		{"8.8.8.8", "1.1.1.1"}:     flow.DirExternal,
		{"fd00::1", "2001:db8::1"}: flow.DirOutbound,
	}
	for k, want := range cases {
		f := mk(k[0], k[1], 1, 2, 6, "192.0.2.1", t0, 1)
		e.Normalize(f)
		if f.Direction != want {
			t.Errorf("%v: got %s want %s", k, f.Direction, want)
		}
	}
}

func TestMatcherPortsAndNot(t *testing.T) {
	m, err := Compile(config.Match{DstPort: []string{"5985-5986", "22"}, Not: &config.Match{SrcCIDR: []string{"10.9.0.0/16"}}}, &ListLoader{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(mk("10.1.1.1", "10.2.2.2", 1, 5986, 6, "192.0.2.1", t0, 1)) {
		t.Fatal("range should match")
	}
	if m.Match(mk("10.9.1.1", "10.2.2.2", 1, 22, 6, "192.0.2.1", t0, 1)) {
		t.Fatal("not: should exclude")
	}
	if m.Match(mk("10.1.1.1", "10.2.2.2", 1, 23, 6, "192.0.2.1", t0, 1)) {
		t.Fatal("port 23 should not match")
	}
}

func BenchmarkProcess(b *testing.B) {
	cfg, _ := config.Parse([]byte(baseYAML))
	e, _ := New(cfg, ".", func(ocsf.Event) {}, Hooks{}, false)
	fs := make([]*flow.Flow, 4096)
	for i := range fs {
		fs[i] = mk(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}).String(), "10.2.0.10", uint16(30000+i), 443, 6, "192.0.2.1", t0.Add(time.Duration(i)*time.Millisecond), uint64(i))
		e.Normalize(fs[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := fs[i&4095]
		e.Process(f, t0)
		if i&65535 == 0 {
			e.Tick(t0.Add(2 * time.Minute))
		}
	}
}
