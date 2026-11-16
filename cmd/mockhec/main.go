// Command mockhec is a local stand-in for the Falcon NG-SIEM HEC endpoint.
// It checks the bearer token, accepts gzip, counts events and can inject
// failures (503, 413) so you can test FlowTrim's retry/split/queue behavior
// without a tenant. It is NOT a faithful reproduction of NG-SIEM limits.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
)

type stats struct {
	Requests  int64            `json:"requests"`
	Events    int64            `json:"events"`
	WireBytes int64            `json:"wire_bytes"`
	RawBytes  int64            `json:"raw_bytes"`
	Gzipped   int64            `json:"gzipped_requests"`
	Rejected  map[string]int64 `json:"rejected"`
	ByKind    map[string]int64 `json:"events_by_reduction"`
	ByRecord  map[string]int64 `json:"summaries_by_record_type"`
}

func main() {
	addr := flag.String("listen", "127.0.0.1:8088", "listen address")
	token := flag.String("token", "test-token", "expected API key")
	failRate := flag.Float64("fail-rate", 0, "fraction of requests answered 503")
	maxBody := flag.Int("max-body", 0, "answer 413 when uncompressed body exceeds this many bytes (0 = off)")
	out := flag.String("out", "", "append received events (NDJSON) to this file")
	flag.Parse()

	var mu sync.Mutex
	st := stats{Rejected: map[string]int64{}, ByKind: map[string]int64{}, ByRecord: map[string]int64{}}
	var reqs atomic.Int64
	var outF *os.File
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		outF = f
	}

	http.HandleFunc("/services/collector", func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		reject := func(code int, why string) {
			mu.Lock()
			st.Rejected[why]++
			mu.Unlock()
			http.Error(w, fmt.Sprintf(`{"text":%q,"code":%d}`, why, code), code)
		}
		if r.Header.Get("Authorization") != "Bearer "+*token {
			reject(401, "invalid token")
			return
		}
		if *failRate > 0 && rand.Float64() < *failRate {
			reject(503, "injected failure")
			return
		}
		wire, _ := io.ReadAll(r.Body)
		raw := wire
		gz := r.Header.Get("Content-Encoding") == "gzip"
		if gz {
			zr, err := gzip.NewReader(bytes.NewReader(wire))
			if err != nil {
				reject(400, "bad gzip")
				return
			}
			raw, err = io.ReadAll(zr)
			if err != nil {
				reject(400, "bad gzip")
				return
			}
		}
		if *maxBody > 0 && len(raw) > *maxBody {
			reject(413, "too large")
			return
		}
		n := int64(0)
		kinds := map[string]int64{}
		recs := map[string]int64{}
		dec := json.NewDecoder(bytes.NewReader(raw))
		for dec.More() {
			var env struct {
				Event struct {
					Unmapped struct {
						Flowtrim map[string]any `json:"flowtrim"`
					} `json:"unmapped"`
				} `json:"event"`
			}
			if err := dec.Decode(&env); err != nil {
				reject(400, "invalid json")
				return
			}
			n++
			ft := env.Event.Unmapped.Flowtrim
			if rt, ok := ft["record_type"].(string); ok {
				recs[rt]++
			} else if k, ok := ft["reduction"].(string); ok {
				kinds[k]++
			}
		}
		mu.Lock()
		st.Requests++
		st.Events += n
		st.WireBytes += int64(len(wire))
		st.RawBytes += int64(len(raw))
		if gz {
			st.Gzipped++
		}
		for k, v := range kinds {
			st.ByKind[k] += v
		}
		for k, v := range recs {
			st.ByRecord[k] += v
		}
		if outF != nil {
			bw := bufio.NewWriter(outF)
			bw.Write(raw)
			bw.Flush()
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	})
	http.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
	})
	log.Printf("mockhec listening on http://%s/services/collector (token=%q)", *addr, *token)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
