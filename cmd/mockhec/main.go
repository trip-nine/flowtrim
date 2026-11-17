// Command mockhec is a local stand-in for an HEC receiver so the whole chain
// can be demonstrated without a tenant:
//
//	flowgen ──UDP──► flowtrim ──HEC──► mockhec -role onum ──HEC──► mockhec -role ngsiem
//
// role ngsiem: the last hop (Falcon NG-SIEM HEC/HTTP Event Data Connector).
// role onum:   a pass-through hop (Falcon Onum HEC Listener → pipeline → NG-SIEM
//
//	Data Sink with "Raw" event format): forwards each batch unchanged,
//	and answers 503 when the next hop is down, so backpressure works.
//
// It checks the token (Bearer or Splunk scheme), accepts gzip, counts events,
// keeps the most recent ones for inspection (/events), and can inject
// failures (503, 413). It is NOT a faithful reproduction of NG-SIEM or Onum.
package main

import (
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
	"strconv"
	"sync"
	"time"
)

type stats struct {
	Name        string           `json:"name"`
	Role        string           `json:"role"`
	Started     time.Time        `json:"started"`
	Requests    int64            `json:"requests"`
	Events      int64            `json:"events"`
	WireBytes   int64            `json:"wire_bytes"`
	RawBytes    int64            `json:"raw_bytes"`
	Gzipped     int64            `json:"gzipped_requests"`
	Forwarded   int64            `json:"forwarded_events,omitempty"`
	ForwardErrs int64            `json:"forward_errors,omitempty"`
	Rejected    map[string]int64 `json:"rejected"`
	ByKind      map[string]int64 `json:"events_by_reduction"`
	ByRecord    map[string]int64 `json:"summaries_by_record_type"`
	LastEventAt time.Time        `json:"last_event_at"`
}

func main() {
	addr := flag.String("listen", "127.0.0.1:8088", "listen address")
	token := flag.String("token", "test-token", "expected token")
	role := flag.String("role", "ngsiem", "ngsiem (final hop) | onum (forwarding hop)")
	name := flag.String("name", "", "display name (default from role)")
	forward := flag.String("forward", "", "role onum: next hop URL, e.g. http://127.0.0.1:8088/services/collector")
	fwdToken := flag.String("forward-token", "test-token", "role onum: bearer token for the next hop")
	failRate := flag.Float64("fail-rate", 0, "fraction of requests answered 503")
	maxBody := flag.Int("max-body", 0, "answer 413 when uncompressed body exceeds this many bytes (0 = off)")
	out := flag.String("out", "", "append received events (NDJSON) to this file")
	keep := flag.Int("keep", 200, "recent events kept for /events")
	flag.Parse()
	if *name == "" {
		*name = map[string]string{"ngsiem": "Falcon NG-SIEM (mock)", "onum": "Falcon Onum (mock)"}[*role]
	}
	if *role == "onum" && *forward == "" {
		log.Fatal("-role onum requires -forward")
	}

	var mu sync.Mutex
	st := stats{Name: *name, Role: *role, Started: time.Now(), Rejected: map[string]int64{}, ByKind: map[string]int64{}, ByRecord: map[string]int64{}}
	recent := make([]json.RawMessage, 0, *keep)
	var outF *os.File
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		outF = f
	}
	client := &http.Client{Timeout: 15 * time.Second}

	handler := func(w http.ResponseWriter, r *http.Request) {
		reject := func(code int, why string) {
			mu.Lock()
			st.Rejected[why]++
			mu.Unlock()
			http.Error(w, fmt.Sprintf(`{"text":%q,"code":%d}`, why, code), code)
		}
		if a := r.Header.Get("Authorization"); a != "Bearer "+*token && a != "Splunk "+*token {
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
			if raw, err = io.ReadAll(zr); err != nil {
				reject(400, "bad gzip")
				return
			}
		}
		if *maxBody > 0 && len(raw) > *maxBody {
			reject(413, "too large")
			return
		}
		var lines []json.RawMessage
		kinds, recs := map[string]int64{}, map[string]int64{}
		dec := json.NewDecoder(bytes.NewReader(raw))
		for dec.More() {
			var m json.RawMessage
			if err := dec.Decode(&m); err != nil {
				reject(400, "invalid json")
				return
			}
			lines = append(lines, m)
			var env struct {
				Event struct {
					Unmapped struct {
						Flowtrim map[string]any `json:"flowtrim"`
					} `json:"unmapped"`
				} `json:"event"`
			}
			_ = json.Unmarshal(m, &env)
			ft := env.Event.Unmapped.Flowtrim
			if rt, ok := ft["record_type"].(string); ok {
				recs[rt]++
			} else if k, ok := ft["reduction"].(string); ok {
				kinds[k]++
			}
		}
		if *role == "onum" {
			// pass the batch on unchanged ("Raw" event format), same encoding
			req, _ := http.NewRequest(http.MethodPost, *forward, bytes.NewReader(wire))
			req.Header.Set("Authorization", "Bearer "+*fwdToken)
			req.Header.Set("Content-Type", "application/json")
			if gz {
				req.Header.Set("Content-Encoding", "gzip")
			}
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode >= 300 {
				code := 0
				if resp != nil {
					code = resp.StatusCode
					resp.Body.Close()
				}
				mu.Lock()
				st.ForwardErrs++
				mu.Unlock()
				reject(503, "next hop unavailable ("+strconv.Itoa(code)+")")
				return
			}
			resp.Body.Close()
		}
		mu.Lock()
		st.Requests++
		st.Events += int64(len(lines))
		st.WireBytes += int64(len(wire))
		st.RawBytes += int64(len(raw))
		st.LastEventAt = time.Now()
		if gz {
			st.Gzipped++
		}
		if *role == "onum" {
			st.Forwarded += int64(len(lines))
		}
		for k, v := range kinds {
			st.ByKind[k] += v
		}
		for k, v := range recs {
			st.ByRecord[k] += v
		}
		for _, l := range lines {
			if len(recent) == *keep {
				recent = recent[1:]
			}
			recent = append(recent, l)
		}
		if outF != nil {
			_, _ = outF.Write(raw)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}
	http.HandleFunc("/services/collector", handler)
	http.HandleFunc("/services/collector/event", handler)
	http.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = json.NewEncoder(w).Encode(st)
	})
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		mu.Lock()
		defer mu.Unlock()
		if n <= 0 || n > len(recent) {
			n = len(recent)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = json.NewEncoder(w).Encode(recent[len(recent)-n:])
	})
	log.Printf("mockhec %q (role=%s) listening on http://%s/services/collector[/event]", *name, *role, *addr)
	if *role == "onum" {
		log.Printf("forwarding to %s", *forward)
	}
	log.Fatal(http.ListenAndServe(*addr, nil))
}
