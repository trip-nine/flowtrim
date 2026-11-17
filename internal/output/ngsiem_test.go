package output

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trip-nine/flowtrim/internal/config"
	"github.com/trip-nine/flowtrim/internal/ocsf"
	"github.com/trip-nine/flowtrim/internal/telemetry"
)

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://abc.ingest.us-1.crowdstrike.com":                    "https://abc.ingest.us-1.crowdstrike.com/services/collector",
		"https://abc.ingest.us-1.crowdstrike.com/":                   "https://abc.ingest.us-1.crowdstrike.com/services/collector",
		"https://abc.ingest.us-1.crowdstrike.com/services/collector": "https://abc.ingest.us-1.crowdstrike.com/services/collector",
		"https://abc.ingest.eu-1.crowdstrike.com/api/v1/ingest/hec":  "https://abc.ingest.eu-1.crowdstrike.com/api/v1/ingest/hec",
	} {
		got, err := NormalizeURL(in)
		if err != nil || got != want {
			t.Errorf("%s => %s (%v), want %s", in, got, err, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := map[int]outcome{200: okSent, 204: okSent, 413: split, 401: authErr, 403: authErr, 429: retry, 503: retry, 500: retry, 408: retry, 400: noGzip, 404: dead}
	for c, want := range cases {
		if got := classify(c, true); got != want {
			t.Errorf("%d: got %v want %v", c, got, want)
		}
	}
	if classify(415, true) != noGzip || classify(415, false) != dead || classify(400, false) != dead {
		t.Error("415 handling")
	}
}

type fakeHEC struct {
	mu       sync.Mutex
	events   int
	gz       int
	fail     atomic.Int32 // number of 503s to return first
	maxBody  int
	auth     string
	noGzip   bool // answer 400 to gzip bodies, like a receiver that can't decompress
	statuses []int
}

func (f *fakeHEC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != f.auth {
		f.statuses = append(f.statuses, 401)
		w.WriteHeader(401)
		return
	}
	if f.fail.Load() > 0 {
		f.fail.Add(-1)
		f.statuses = append(f.statuses, 503)
		w.WriteHeader(503)
		return
	}
	body, _ := io.ReadAll(r.Body)
	if f.noGzip && r.Header.Get("Content-Encoding") == "gzip" {
		f.statuses = append(f.statuses, 400)
		w.WriteHeader(400)
		return
	}
	if r.Header.Get("Content-Encoding") == "gzip" {
		f.gz++
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		body, _ = io.ReadAll(zr)
	}
	if f.maxBody > 0 && len(body) > f.maxBody {
		f.statuses = append(f.statuses, 413)
		w.WriteHeader(413)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var env hecEnvelope
		if err := dec.Decode(&env); err != nil || env.Event == nil || env.Time == 0 {
			f.statuses = append(f.statuses, 400)
			w.WriteHeader(400)
			return
		}
		f.events++
	}
	f.statuses = append(f.statuses, 200)
	_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
}

func cfgFor(url, dir string) *config.HEC {
	y := `
mode: enforce
inputs: { netflow: { listen: ["127.0.0.1:0"] } }
output:
  hec:
    url: ` + url + `
    token: secret
    batch: { max_events: 50, max_wait: 50ms }
    retry: { initial: 10ms, max: 50ms }
    queue: { dir: "` + dir + `" }
`
	c, err := config.Parse([]byte(y))
	if err != nil {
		panic(err)
	}
	return c.Output.HEC
}

func ev(i int) ocsf.Event {
	return ocsf.Event{Time: time.Unix(1763251200, 0), Host: "192.0.2.1", Kind: "raw", Body: map[string]any{"class_uid": 4001, "i": i, "pad": string(bytes.Repeat([]byte("x"), 200))}}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout")
}

func TestDeliveryRetrySplitGzip(t *testing.T) {
	f := &fakeHEC{auth: "Bearer secret", maxBody: 4000}
	f.fail.Store(3)
	srv := httptest.NewServer(f)
	defer srv.Close()
	o, err := New(cfgFor(srv.URL, t.TempDir()), slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry.NewShadow(), nil)
	if err != nil {
		t.Fatal(err)
	}
	o.Start()
	for i := 0; i < 500; i++ {
		o.Send(ev(i))
	}
	waitFor(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.events == 500 })
	o.Close(time.Second)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gz == 0 {
		t.Error("expected gzip requests")
	}
	has := map[int]bool{}
	for _, s := range f.statuses {
		has[s] = true
	}
	if !has[503] || !has[413] || !has[200] {
		t.Errorf("expected retry and split paths, statuses=%v", has)
	}
}

func TestAuthErrorHoldsData(t *testing.T) {
	f := &fakeHEC{auth: "Bearer other"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	dir := t.TempDir()
	o, _ := New(cfgFor(srv.URL, dir), slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry.NewShadow(), nil)
	o.Start()
	for i := 0; i < 10; i++ {
		o.Send(ev(i))
	}
	time.Sleep(300 * time.Millisecond)
	o.Close(100 * time.Millisecond)
	if n, _ := o.q.Len(); n == 0 {
		t.Fatal("batches must be kept on 401, not discarded")
	}
	// fix the key and restart: the spooled batch is delivered
	f.mu.Lock()
	f.auth = "Bearer secret"
	f.mu.Unlock()
	o2, _ := New(cfgFor(srv.URL, dir), slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry.NewShadow(), nil)
	o2.Start()
	waitFor(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.events == 10 })
	o2.Close(time.Second)
}

func TestGzipProbeFallsBackOnly(t *testing.T) {
	f := &fakeHEC{auth: "Bearer secret", noGzip: true}
	srv := httptest.NewServer(f)
	defer srv.Close()
	o, _ := New(cfgFor(srv.URL, t.TempDir()), slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry.NewShadow(), nil)
	o.Start()
	for i := 0; i < 120; i++ {
		o.Send(ev(i))
	}
	waitFor(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.events == 120 })
	o.Close(time.Second)
	if o.gzipOn.Load() {
		t.Fatal("gzip should be disabled after a successful uncompressed probe")
	}
}

func TestBadBatchIsDeadLetteredNotGzipBlamed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(400) }))
	defer srv.Close()
	o, _ := New(cfgFor(srv.URL, t.TempDir()), slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry.NewShadow(), nil)
	o.Start()
	o.Send(ev(1))
	waitFor(t, func() bool { n, _ := o.q.Len(); return n == 0 })
	o.Close(100 * time.Millisecond)
	if !o.gzipOn.Load() {
		t.Fatal("a batch the receiver rejects either way must not switch gzip off")
	}
}
