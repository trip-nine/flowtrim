package app

import (
	"context"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/trip-nine/flowtrim/internal/config"
	"github.com/trip-nine/flowtrim/internal/flow"
	"github.com/trip-nine/flowtrim/internal/ocsf"
	"github.com/trip-nine/flowtrim/internal/output"
	"github.com/trip-nine/flowtrim/internal/telemetry"
)

//go:embed ui
var uiFS embed.FS

var started = time.Now()

// counters flattens the Prometheus registry into the shapes the console uses.
type counters struct {
	Received   map[string]float64            `json:"received"`
	Rejected   map[string]float64            `json:"rejected"`
	Decisions  map[string]map[string]float64 `json:"decisions"`
	Emitted    map[string]float64            `json:"emitted"`
	HTTP       map[string]float64            `json:"http_status"`
	Batches    map[string]float64            `json:"batches"`
	Lost       map[string]float64            `json:"lost"`
	Enrich     map[string]map[string]float64 `json:"enrich"`
	Engine     map[string]float64            `json:"engine"`
	OutEvents  float64                       `json:"out_events"`
	OutWire    float64                       `json:"out_wire_bytes"`
	OutRaw     float64                       `json:"out_raw_bytes"`
	QueueBatch float64                       `json:"queue_batches"`
	QueueBytes float64                       `json:"queue_bytes"`
	EngineQ    float64                       `json:"engine_queue"`
	LatencySum float64                       `json:"latency_sum_s"`
	LatencyN   float64                       `json:"latency_count"`
	Templates  float64                       `json:"templates_known"`
}

func label(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func val(m *dto.Metric) float64 {
	switch {
	case m.Counter != nil:
		return m.Counter.GetValue()
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	}
	return 0
}

func gather() counters {
	c := counters{Received: map[string]float64{}, Rejected: map[string]float64{}, Decisions: map[string]map[string]float64{},
		Emitted: map[string]float64{}, HTTP: map[string]float64{}, Batches: map[string]float64{}, Lost: map[string]float64{},
		Enrich: map[string]map[string]float64{}, Engine: map[string]float64{}}
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return c
	}
	nested := func(m map[string]map[string]float64, a, b string, v float64) {
		if m[a] == nil {
			m[a] = map[string]float64{}
		}
		m[a][b] += v
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			v := val(m)
			switch mf.GetName() {
			case "flowtrim_flows_received_total":
				c.Received[label(m, "input")] += v
			case "flowtrim_flows_rejected_total":
				c.Rejected[label(m, "reason")] += v
			case "flowtrim_decisions_total":
				nested(c.Decisions, label(m, "decision"), label(m, "rule"), v)
			case "flowtrim_events_emitted_total":
				c.Emitted[label(m, "kind")] += v
			case "flowtrim_output_http_status_total":
				c.HTTP[label(m, "code")] += v
			case "flowtrim_output_batches_total":
				c.Batches[label(m, "result")] += v
			case "flowtrim_output_events_lost_total":
				c.Lost[label(m, "reason")] += v
			case "flowtrim_enrich_lookups_total":
				nested(c.Enrich, label(m, "kind"), label(m, "result"), v)
			case "flowtrim_engine_state":
				c.Engine[label(m, "name")] = v
			case "flowtrim_output_events_sent_total":
				c.OutEvents = v
			case "flowtrim_output_wire_bytes_total":
				c.OutWire = v
			case "flowtrim_output_uncompressed_bytes_total":
				c.OutRaw = v
			case "flowtrim_queue_batches":
				c.QueueBatch = v
			case "flowtrim_queue_bytes":
				c.QueueBytes = v
			case "flowtrim_engine_input_queue":
				c.EngineQ = v
			case "flowtrim_output_request_seconds":
				if h := m.GetHistogram(); h != nil {
					c.LatencySum, c.LatencyN = h.GetSampleSum(), float64(h.GetSampleCount())
				}
			case "flowtrim_netflow_templates_total", "goflow2_flow_process_nf_templates_total":
				c.Templates += v
			}
		}
	}
	return c
}

type status struct {
	Product     string              `json:"product"`
	Version     string              `json:"version"`
	Mode        string              `json:"mode"`
	RuleVersion string              `json:"rule_version"`
	Started     time.Time           `json:"started"`
	Now         time.Time           `json:"now"`
	Inputs      []map[string]any    `json:"inputs"`
	Output      map[string]any      `json:"output"`
	Rules       map[string]any      `json:"rules"`
	Enrichment  map[string]bool     `json:"enrichment"`
	Counters    counters            `json:"counters"`
	Shadow      *telemetry.Report   `json:"shadow,omitempty"`
	Downstream  []config.Downstream `json:"downstream"`
}

func (a *App) status() status {
	c := a.cfg
	st := status{Product: "FlowTrim", Version: Version, Mode: c.Mode, RuleVersion: c.RuleVersion, Started: started, Now: time.Now(),
		Counters: gather(), Downstream: c.Telemetry.Downstream}
	if in := c.Inputs.NetFlow; in != nil {
		st.Inputs = append(st.Inputs, map[string]any{"name": "NetFlow v5/v9 · IPFIX", "listen": in.Listen})
	}
	if in := c.Inputs.SFlow; in != nil {
		st.Inputs = append(st.Inputs, map[string]any{"name": "sFlow v5", "listen": in.Listen})
	}
	if in := c.Inputs.AWSFirehose; in != nil {
		st.Inputs = append(st.Inputs, map[string]any{"name": "AWS VPC Flow Logs (Firehose)", "listen": []string{in.Listen}})
	}
	if o := c.Output.HEC; o != nil {
		u, _ := output.NormalizeURLPath(o.URL, o.Path)
		st.Output = map[string]any{"target": o.Target, "url": redactURL(u), "auth": o.AuthScheme, "gzip": *o.Gzip, "queue": o.Queue.Dir != ""}
	}
	var bypass, drop []string
	for _, r := range c.Rules.Bypass {
		bypass = append(bypass, r.Name)
	}
	for _, r := range c.Rules.Drop {
		drop = append(drop, r.Name)
	}
	st.Rules = map[string]any{"bypass": bypass, "drop": drop, "dedup": c.Rules.Dedup.Enabled, "rollup": c.Rules.Rollup.Enabled,
		"rollup_window_s": c.Rules.Rollup.Window.D().Seconds(), "fanout": c.Rules.Fanout.Enabled}
	e := c.Enrich
	st.Enrichment = map[string]bool{
		"geoip": e.GeoIP.CityDB != "" || e.GeoIP.ASNDB != "", "reverse_dns": e.DNS.Enabled, "hostnames": e.HostnamesFile != "",
		"metadata": e.MetadataFile != "", "interfaces_file": e.Interfaces.File != "", "snmp": e.Interfaces.SNMP.Enabled,
		"services": *e.Apps.Services || e.Apps.ServicesFile != "", "apps": e.Apps.AppsFile != "", "threat_lists": len(e.Threat) > 0,
		"community_id": *e.CommunityID.Enabled, "client_server": *e.ClientServer, "pseudonymize": len(c.Privacy.Pseudonymize) > 0,
	}
	if c.Mode == config.ModeShadow {
		r := a.shadow.Snapshot(false)
		st.Shadow = &r
	}
	return st
}

func redactURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, ".:/"); j > 6 {
			return u[:i+3] + rest[:4] + "…" + rest[j:]
		}
	}
	return u
}

// recordInput samples an input flow for the console (engine goroutine).
func recordInput(f *flow.Flow, rv string) {
	if !telemetry.InputRecords.Want() {
		return
	}
	ev := ocsf.FromFlow(f, f.Start, f.End, f.Bytes, f.Packets, f.TCPFlags, ocsf.Reduction{Kind: "none", RuleVersion: rv})
	doc := map[string]any{"time": float64(ev.Time.UnixMilli()) / 1000, "host": ev.Host, "event": ev.Body,
		"input": map[string]any{"source": f.Source, "type": f.Type, "exporter": f.Exporter.String()}}
	if b, err := json.Marshal(doc); err == nil {
		telemetry.InputRecords.Put(b)
	}
}

var dsClient = &http.Client{Timeout: 1500 * time.Millisecond}

func fetchDownstream(ds []config.Downstream) []map[string]any {
	out := make([]map[string]any, len(ds))
	var wg sync.WaitGroup
	for i, d := range ds {
		wg.Add(1)
		go func(i int, d config.Downstream) {
			defer wg.Done()
			res := map[string]any{"name": d.Name, "role": d.Role, "ok": false}
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.StatsURL, nil)
			if resp, err := dsClient.Do(req); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				var m map[string]any
				if json.Unmarshal(b, &m) == nil {
					res["ok"], res["stats"] = true, m
				}
			} else {
				res["error"] = err.Error()
			}
			out[i] = res
		}(i, d)
	}
	wg.Wait()
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) mountAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, a.status()) })
	mux.HandleFunc("/api/records", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 {
			n = 25
		}
		writeJSON(w, map[string]any{
			"input":   telemetry.InputRecords.Last(n),
			"output":  telemetry.OutputRecords.Last(n),
			"preview": telemetry.ShadowPreview.Last(n),
		})
	})
	mux.HandleFunc("/api/downstream", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, fetchDownstream(a.cfg.Telemetry.Downstream))
	})
	if a.cfg.Telemetry.UI != nil && *a.cfg.Telemetry.UI {
		sub, _ := fs.Sub(uiFS, "ui")
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}
}
