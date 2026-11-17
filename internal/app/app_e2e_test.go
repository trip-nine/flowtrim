package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/trip-nine/flowtrim/internal/config"
)

// freeUDP returns an unused UDP port on loopback.
func freeUDP(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func freeTCP(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// v5 builds one NetFlow v5 packet.
func v5(recs [][4]any) []byte {
	now := time.Now()
	up := uint32(3600_000)
	b := make([]byte, 24+48*len(recs))
	be := binary.BigEndian
	be.PutUint16(b[0:], 5)
	be.PutUint16(b[2:], uint16(len(recs)))
	be.PutUint32(b[4:], up)
	be.PutUint32(b[8:], uint32(now.Unix()))
	for i, r := range recs {
		o := 24 + 48*i
		copy(b[o:], net.ParseIP(r[0].(string)).To4())
		copy(b[o+4:], net.ParseIP(r[1].(string)).To4())
		be.PutUint32(b[o+16:], 2)
		be.PutUint32(b[o+20:], 500)
		be.PutUint32(b[o+24:], up-1000)
		be.PutUint32(b[o+28:], up)
		be.PutUint16(b[o+32:], uint16(r[2].(int)))
		be.PutUint16(b[o+34:], uint16(r[3].(int)))
		b[o+38] = 6
	}
	return b
}

type hec struct {
	mu    sync.Mutex
	lines []map[string]any
}

func (h *hec) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rd io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, _ := gzip.NewReader(r.Body)
		rd = zr
	}
	body, _ := io.ReadAll(rd)
	dec := json.NewDecoder(bytes.NewReader(body))
	h.mu.Lock()
	for dec.More() {
		var m map[string]any
		if dec.Decode(&m) == nil {
			h.lines = append(h.lines, m)
		}
	}
	h.mu.Unlock()
	_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
}

func (h *hec) reductions() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]int{}
	for _, l := range h.lines {
		ft := l["event"].(map[string]any)["unmapped"].(map[string]any)["flowtrim"].(map[string]any)
		if rt, ok := ft["record_type"].(string); ok {
			out[rt]++
		} else {
			out[ft["reduction"].(string)]++
		}
	}
	return out
}

func TestEndToEndEnforce(t *testing.T) {
	sink := &hec{}
	srv := httptest.NewServer(sink)
	defer srv.Close()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "intel.txt"), []byte("198.51.100.7\n"), 0o644)
	port := freeUDP(t)
	y := fmt.Sprintf(`
mode: enforce
inputs: { netflow: { listen: ["127.0.0.1:%d"] } }
rules:
  bypass: [ { name: intel, match: { any_ip_in_list: intel.txt } } ]
  drop:   [ { name: dns, match: { dst_port: ["53"] } } ]
  dedup:  { enabled: true }
  rollup: { enabled: true, window: 1s }
output:
  ngsiem:
    url: %s
    token: t
    batch: { max_wait: 100ms }
    queue: { dir: %s/q }
telemetry: { listen: "127.0.0.1:%d" }
`, port, srv.URL, dir, freeTCP(t))
	cfgPath := filepath.Join(dir, "flowtrim.yaml")
	_ = os.WriteFile(cfgPath, []byte(y), 0o644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := New(cfgPath, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	select {
	case <-a.Ready:
	case err := <-done:
		t.Fatal(err)
	}

	conn, _ := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	recs := [][4]any{}
	for i := 0; i < 20; i++ { // 20 flows, same conversation -> 1 rollup
		recs = append(recs, [4]any{"10.1.1.1", "10.2.0.10", 40000 + i, 443})
	}
	recs = append(recs, [4]any{"10.1.1.1", "10.0.0.53", 5000, 53})     // dropped
	recs = append(recs, [4]any{"10.1.1.1", "198.51.100.7", 5001, 443}) // bypass
	pkt := v5(recs[:22])
	_, _ = conn.Write(pkt)
	_, _ = conn.Write(pkt) // exact re-export: all 22 deduped

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		r := sink.reductions()
		if r["rollup"] == 1 && r["bypass"] == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	r := sink.reductions()
	if r["rollup"] != 1 || r["bypass"] != 1 || r["none"] != 0 {
		t.Fatalf("unexpected output mix: %v", r)
	}
	if r["drop_summary"] != 1 {
		t.Fatalf("drop summary expected at shutdown flush: %v", r)
	}
	// verify the HEC envelope shape NG-SIEM expects
	sink.mu.Lock()
	defer sink.mu.Unlock()
	l := sink.lines[0]
	if _, ok := l["time"].(float64); !ok || l["source"] != "flowtrim" || l["host"] == "" {
		t.Fatalf("bad envelope: %v", l)
	}
	for _, l := range sink.lines {
		ev := l["event"].(map[string]any)
		ft := ev["unmapped"].(map[string]any)["flowtrim"].(map[string]any)
		if ft["reduction"] == "rollup" && ev["count"].(float64) != 20 {
			t.Fatalf("rollup count want 20 got %v", ev["count"])
		}
	}
}
