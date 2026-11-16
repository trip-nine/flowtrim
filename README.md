# FlowTrim

**Collect flow logs, keep the signal, cut the volume, and ship the rest over HTTPS to Falcon Onum or straight to Falcon Next-Gen SIEM.**

FlowTrim is a single Go binary with one YAML file. It receives NetFlow v5/v9, IPFIX, sFlow v5 and AWS VPC Flow Logs (via Amazon Data Firehose). It then deduplicates, drops known-boring traffic and rolls up chatty conversations, while keeping the statistics that detections need. The result goes to the **Falcon Next-Gen SIEM HEC/HTTP Event Data Connector** as OCSF-shaped JSON.

> Think of FlowTrim as a strainer on the tap: it keeps the gravel out of the pipe and lets the water through. It does not replace the treatment plant (your SIEM).

```
 Routers / switches / probes ──UDP 2055/4739/6343──┐
                                                    ├─► FlowTrim ──HTTPS (gzip, batched)──► Falcon NG-SIEM
 AWS VPC Flow Logs ─► Data Firehose ─HTTPS 8443────┘   dedup → bypass → drop → rollup       HEC/HTTP Event Data Connector
                                                         fanout + drop summaries
                                                         disk queue, retries, /metrics
```

## Why another flow collector?

| | ElastiFlow (Community / Basic) | **FlowTrim** |
|---|---|---|
| License | Proprietary freeware EULA | **Apache-2.0** |
| Rate cap | 500 / 4,000 records/s, single instance | **None.** Measured with zero loss at 200k flows/s on 2 vCPUs ([benchmarks](docs/BENCHMARKS.md)) |
| Config | Dozens of `EF_*` env vars | **One YAML file**, strict validation, `flowtrim check` |
| Purpose | Enrich and store in Elastic/OpenSearch/Splunk | **Reduce before the SIEM**, then forward to NG-SIEM over HTTPS |
| Safety net | n/a | **Shadow mode** measures savings before anything is dropped |
| Audit trail | n/a | Every drop rule emits a **`drop_summary`** record into the SIEM |

FlowTrim does **not** try to match ElastiFlow on dashboards, 6,900 vendor information elements, or ML.

## How reduction works (and what it never touches)

Every flow goes through the stages in a fixed order:

| # | Stage | What it does | Detection safeguard |
|---|---|---|---|
| 1 | **Dedup** | Drops exact duplicates: the same flow exported by several routers on the path, with ±1 s clock-skew tolerance | Fails open when full: never drops because it is out of memory |
| 2 | **Bypass** | Forwards raw and **never reduces**: threat-intel hits, denied traffic, lateral-movement ports | Bypass always beats drop |
| 3 | **Drop** | Discards known-boring traffic you list (multicast, DNS/NTP to *your* servers, AWS `NODATA`) | Per-rule `drop_summary` counts flows/bytes/packets every interval |
| 4 | **Rollup** | Folds one conversation per window into one record | Keeps first/last seen, flow count, byte/packet sums, TCP-flag union, **inter-arrival min/max/mean/stddev** (beaconing), distinct src ports |
| — | **Fanout** | Per-source summary when a host touches ≥ N distinct IPs/ports | Scan and sweep visibility that survives rollup |

The **golden rule**: reduction only applies to traffic you have *named* as boring. Unknown, denied, rare or intel-matched traffic passes through raw.

## Quick start (local demo, no tenant needed)

The block below builds everything, starts a mock NG-SIEM endpoint, runs FlowTrim in shadow mode, sends 15 seconds of synthetic traffic, and prints the projected savings. Copy the whole box, from the first line to the last, into a terminal:

```bash
bash <<'FLOWTRIM_DEMO'
set -euo pipefail
REPO="$HOME/src/flowtrim"          # where you cloned/unzipped FlowTrim
cd "$REPO"
go build -o bin/ ./cmd/...
mkdir -p /tmp/flowtrim-demo && cp examples/intel.txt /tmp/flowtrim-demo/
sed -e 's#/var/lib/flowtrim/queue#/tmp/flowtrim-demo/queue#' \
    -e 's#\["0.0.0.0:2055", "0.0.0.0:4739"\]#["127.0.0.1:2055"]#' \
    -e 's#"0.0.0.0:9109"#"127.0.0.1:9109"#' \
    -e 's#window: 60s#window: 5s#g' -e 's#shadow_report_interval: 5m#shadow_report_interval: 10s#' \
    examples/flowtrim.yaml > /tmp/flowtrim-demo/flowtrim.yaml
export HEC_URL=http://127.0.0.1:8088 HEC_TOKEN=test-token
./bin/mockhec >/tmp/flowtrim-demo/mock.log 2>&1 & MOCK=$!
./bin/flowtrim -config /tmp/flowtrim-demo/flowtrim.yaml 2>/tmp/flowtrim-demo/flowtrim.log & FT=$!
trap 'kill $FT $MOCK 2>/dev/null || true' EXIT
sleep 1
./bin/flowgen -rate 3000 -duration 15s
sleep 7
echo "=== Projected reduction (shadow mode) ==="
curl -s 127.0.0.1:9109/shadow
FLOWTRIM_DEMO
```

## Where FlowTrim fits

FlowTrim is **not** a one-box ElastiFlow clone. With the CrowdStrike stack, **FlowTrim + Falcon Onum + Falcon NG-SIEM** together cover what ElastiFlow does:

| Job | Owner |
|---|---|
| Get flows off the wire without loss; normalize; **flow-aware reduction** | **FlowTrim** |
| Enrichment, routing, masking, other destinations | **Falcon Onum** (optional) |
| Storage, search, dashboards, detections | **Falcon NG-SIEM** |

| Layout | Flow | Profile |
|---|---|---|
| **A** (recommended with Onum) | exporters → FlowTrim → Onum HEC Listener → NG-SIEM | `examples/profiles/onum-onprem.yaml`, `onum-cloud.yaml` |
| **C** (no Onum) | exporters → FlowTrim → NG-SIEM HEC connector | `examples/profiles/ngsiem-direct.yaml` |
| Collector-only | exporters → FlowTrim (no reduction) → Onum does all reduction | `examples/profiles/collector-only.yaml` |

Diagrams and the reasoning behind them are in [docs/01-overview.md](docs/01-overview.md).

## Production setup (summary)

1. Prepare the receiver: an NG-SIEM HEC/HTTP Event Data Connector (API URL and key), **or** an Onum HEC Listener wired to an NG-SIEM Data Sink.
2. Install FlowTrim (binary + systemd, or Docker), copy the profile for your layout, and put `HEC_URL` and `HEC_TOKEN` in the environment.
3. Run `flowtrim check`, then start in `mode: shadow` and leave it for a week.
4. Tune using `/shadow` and the `drop_summary` records, then switch to `mode: enforce`.

Full walkthrough: [docs/02-setup.md](docs/02-setup.md).

## Output format

Each record is an HEC envelope (the example below is illustrative). `time` is the flow end in epoch seconds. The `event` is shaped as OCSF Network Activity (`class_uid` 4001):

```json
{"time":1763251259.877,"host":"192.0.2.1","source":"flowtrim","event":{
  "class_uid":4001,"activity_id":6,"type_uid":400106,"count":30,
  "start_time":1763251200123,"end_time":1763251259877,
  "src_endpoint":{"ip":"10.1.5.5"},"dst_endpoint":{"ip":"203.0.113.66","port":443},
  "connection_info":{"protocol_num":6,"protocol_name":"tcp","direction":"Outbound","tcp_flags":27},
  "traffic":{"bytes":24600,"packets":180},"device":{"ip":"192.0.2.1"},
  "unmapped":{"flowtrim":{"reduction":"rollup","flow_count":30,"distinct_src_ports":30,
    "iat_ms":{"samples":30,"min":1995,"max":2010,"mean":2000.2,"stddev":4.1},
    "flow_type":"NETFLOW_V9","direction":"outbound","rule_version":"e3594e602653"}}}}
```

`unmapped.flowtrim.reduction` is one of `none`, `bypass` or `rollup`. Summary records carry `unmapped.flowtrim.record_type`, which is one of `drop_summary`, `fanout_summary` or `shadow_report`.

## Observability

| Endpoint | Purpose |
|---|---|
| `/metrics` | Prometheus: `flowtrim_flows_received_total`, `flowtrim_decisions_total{decision,rule}`, `flowtrim_output_*`, `flowtrim_queue_*`, `flowtrim_shadow_*`, plus goflow2 template/decoder metrics |
| `/shadow` | JSON projected-savings report (shadow mode) |
| `/healthz`, `/readyz` | Liveness and readiness |

The most useful alerts: `rate(flowtrim_flows_rejected_total[5m]) > 0`, `flowtrim_queue_bytes` growing, `flowtrim_output_batches_total{result="auth_error"}`, and `flowtrim_output_events_lost_total`.

## Documentation

| Doc | For |
|---|---|
| [01 Overview](docs/01-overview.md) | What FlowTrim is, the ElastiFlow capability map, layouts, diagrams |
| [02 Setup](docs/02-setup.md) | Install, receiver setup (NG-SIEM / Onum), exporter configs, verification, go-live |
| [03 User guide](docs/03-user-guide.md) | Modes, reading records, NG-SIEM searches, operations, alerts, troubleshooting |
| [04 Configuration](docs/04-configuration.md) | Every key, type and default |
| [Rules playbook](docs/RULES.md) | Match syntax and tuning |
| [Plan and unknowns](docs/PLAN.md) | Roadmap and the risks and unknowns register |
| [Benchmarks](docs/BENCHMARKS.md) | What was measured and how |

## Status

`v0.1.0` (MVP). Tested against a local HEC mock. **Not yet validated against a live NG-SIEM tenant.** See the first items of the unknowns register in [docs/PLAN.md](docs/PLAN.md).

## License and trademarks

Apache-2.0. Third-party notices are in [NOTICE](NOTICE). FlowTrim is an independent open-source project. "CrowdStrike", "Falcon" and "Falcon Next-Gen SIEM" are trademarks of CrowdStrike, Inc., used here only to describe compatibility. FlowTrim is not affiliated with, or endorsed by, ElastiFlow.
