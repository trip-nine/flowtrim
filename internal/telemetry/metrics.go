// Package telemetry exposes Prometheus metrics, health endpoints and the
// shadow-mode reduction report.
package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	FlowsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_flows_received_total", Help: "Flow records received, by input.",
	}, []string{"input"})
	FlowsRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_flows_rejected_total", Help: "Flow records rejected before the engine (exporter not allowed, parse error).",
	}, []string{"input", "reason"})
	Decisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_decisions_total", Help: "Engine decisions per flow (bypass, drop, dedup, rollup, raw, *_capacity_exceeded), by rule.",
	}, []string{"decision", "rule"})
	EventsEmitted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_events_emitted_total", Help: "Records emitted toward the output, by kind.",
	}, []string{"kind"})
	EngineGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "flowtrim_engine_state", Help: "Engine state sizes (dedup_entries, rollup_active_keys, fanout_active_sources).",
	}, []string{"name"})
	EngineQueue = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "flowtrim_engine_input_queue", Help: "Flows waiting for the engine.",
	})

	OutBatches = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_output_batches_total", Help: "HEC batches by result (ok, retry, split, dead_letter, dropped_overflow, auth_error).",
	}, []string{"result"})
	OutEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "flowtrim_output_events_sent_total", Help: "Events accepted by NG-SIEM (HTTP 2xx).",
	})
	OutWireBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "flowtrim_output_wire_bytes_total", Help: "Request body bytes sent (compressed if gzip on) for accepted batches.",
	})
	OutRawBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "flowtrim_output_uncompressed_bytes_total", Help: "Uncompressed NDJSON bytes for accepted batches (what NG-SIEM ingests).",
	})
	OutStatus = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_output_http_status_total", Help: "HTTP status codes from NG-SIEM.",
	}, []string{"code"})
	OutLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "flowtrim_output_request_seconds", Help: "HEC request latency.", Buckets: prometheus.DefBuckets,
	})
	QueueBatches = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "flowtrim_queue_batches", Help: "Batches buffered (pending + in flight).",
	})
	QueueBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "flowtrim_queue_bytes", Help: "Bytes buffered.",
	})
	EventsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_output_events_lost_total", Help: "Events lost (queue overflow, dead letter, oversize).",
	}, []string{"reason"})

	ShadowRawEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "flowtrim_shadow_raw_events_total", Help: "Shadow mode: records forwarded unreduced.",
	})
	ShadowRawBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "flowtrim_shadow_raw_bytes_total", Help: "Shadow mode: uncompressed bytes of unreduced records.",
	})
	ShadowReducedEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "flowtrim_shadow_reduced_events_total", Help: "Shadow mode: records enforce mode would have sent.",
	})
	ShadowReducedBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "flowtrim_shadow_reduced_bytes_total", Help: "Shadow mode: uncompressed bytes enforce mode would have sent.",
	})
	EnrichLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_enrich_lookups_total", Help: "Enrichment lookups by kind (geoip, dns, snmp, threat) and result.",
	}, []string{"kind", "result"})
	ConfigReloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flowtrim_config_reloads_total", Help: "Rule reloads via SIGHUP.",
	}, []string{"result"})
	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "flowtrim_build_info", Help: "Build and rule version.",
	}, []string{"version", "rule_version", "mode"})
)
