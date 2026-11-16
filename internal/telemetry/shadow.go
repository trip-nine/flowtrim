package telemetry

import (
	"sync"
	"time"
)

// Shadow accumulates the side-by-side comparison of "what we sent" (raw)
// versus "what enforce mode would send" (reduced).
type Shadow struct {
	mu      sync.Mutex
	started time.Time
	total   ShadowCounts
	window  ShadowCounts
	winFrom time.Time
	byKind  map[string]uint64
	byRule  map[string]uint64
}

// ShadowCounts is one tally.
type ShadowCounts struct {
	RawEvents     uint64 `json:"raw_events"`
	RawBytes      uint64 `json:"raw_bytes"`
	ReducedEvents uint64 `json:"reduced_events"`
	ReducedBytes  uint64 `json:"reduced_bytes"`
}

// NewShadow starts a tally.
func NewShadow() *Shadow {
	now := time.Now()
	return &Shadow{started: now, winFrom: now, byKind: map[string]uint64{}, byRule: map[string]uint64{}}
}

// Raw records one unreduced record.
func (s *Shadow) Raw(bytes int) {
	s.mu.Lock()
	s.total.RawEvents++
	s.total.RawBytes += uint64(bytes)
	s.window.RawEvents++
	s.window.RawBytes += uint64(bytes)
	s.mu.Unlock()
	ShadowRawEvents.Inc()
	ShadowRawBytes.Add(float64(bytes))
}

// Reduced records one record enforce mode would send.
func (s *Shadow) Reduced(kind string, bytes int) {
	s.mu.Lock()
	s.total.ReducedEvents++
	s.total.ReducedBytes += uint64(bytes)
	s.window.ReducedEvents++
	s.window.ReducedBytes += uint64(bytes)
	s.byKind[kind]++
	s.mu.Unlock()
	ShadowReducedEvents.Inc()
	ShadowReducedBytes.Add(float64(bytes))
}

// Decision records flows handled per decision/rule (for the report).
func (s *Shadow) Decision(decision, rule string) {
	k := decision
	if rule != "" {
		k += ":" + rule
	}
	s.mu.Lock()
	s.byRule[k]++
	s.mu.Unlock()
}

// Report is the JSON served at /shadow and sent as a shadow_report event.
type Report struct {
	Since            time.Time         `json:"since"`
	Total            ShadowCounts      `json:"total"`
	TotalEventSaving float64           `json:"total_event_reduction_pct"`
	TotalByteSaving  float64           `json:"total_byte_reduction_pct"`
	WindowFrom       time.Time         `json:"window_from"`
	Window           ShadowCounts      `json:"window"`
	WindowByteSaving float64           `json:"window_byte_reduction_pct"`
	OutputKinds      map[string]uint64 `json:"reduced_output_by_kind"`
	FlowsByDecision  map[string]uint64 `json:"flows_by_decision"`
}

func pct(raw, red uint64) float64 {
	if raw == 0 {
		return 0
	}
	v := 100 * (1 - float64(red)/float64(raw))
	return float64(int(v*10)) / 10
}

// Snapshot returns the report; resetWindow starts a new interval.
func (s *Shadow) Snapshot(resetWindow bool) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Report{
		Since: s.started, Total: s.total, WindowFrom: s.winFrom, Window: s.window,
		TotalEventSaving: pct(s.total.RawEvents, s.total.ReducedEvents),
		TotalByteSaving:  pct(s.total.RawBytes, s.total.ReducedBytes),
		WindowByteSaving: pct(s.window.RawBytes, s.window.ReducedBytes),
		OutputKinds:      map[string]uint64{},
		FlowsByDecision:  map[string]uint64{},
	}
	for k, v := range s.byKind {
		r.OutputKinds[k] = v
	}
	for k, v := range s.byRule {
		r.FlowsByDecision[k] = v
	}
	if resetWindow {
		s.window = ShadowCounts{}
		s.winFrom = time.Now()
	}
	return r
}
