package telemetry

import (
	"encoding/json"
	"sync"
)

// Ring keeps the most recent N JSON documents for the console's record
// inspector. Capturing is cheap (a slice write under a mutex) and only
// every Nth item is kept, so it never shows up in throughput.
type Ring struct {
	mu    sync.Mutex
	buf   []json.RawMessage
	next  int
	full  bool
	every uint64
	seen  uint64
}

// NewRing keeps size items, sampling one in every `every` offers.
func NewRing(size int, every uint64) *Ring {
	if every == 0 {
		every = 1
	}
	return &Ring{buf: make([]json.RawMessage, size), every: every}
}

// Want reports whether the next Offer would be kept (lets callers skip
// rendering work for items that would be discarded).
func (r *Ring) Want() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen++
	return r.seen%r.every == 0
}

// Put stores one document (call after Want returned true).
func (r *Ring) Put(doc []byte) {
	cp := append(json.RawMessage(nil), doc...)
	r.mu.Lock()
	r.buf[r.next] = cp
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

// Last returns up to n most recent documents, newest first.
func (r *Ring) Last(n int) []json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	size := r.next
	if r.full {
		size = len(r.buf)
	}
	if n <= 0 || n > size {
		n = size
	}
	out := make([]json.RawMessage, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, r.buf[(r.next-i+len(r.buf))%len(r.buf)])
	}
	return out
}

// Record rings shared by the engine loop and the output encoders.
var (
	InputRecords  = NewRing(100, 7) // flows as received (normalized, before reduction)
	OutputRecords = NewRing(100, 3) // records as sent (after reduction + enrichment)
	ShadowPreview = NewRing(100, 3) // shadow mode: what enforce would send
)
