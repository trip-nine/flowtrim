# FlowTrim

**Collect flow logs, keep the signal, cut the volume, and ship the rest to Falcon Next-Gen SIEM over HTTPS.**

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
export NGSIEM_URL=http://127.0.0.1:8088 NGSIEM_TOKEN=test-token
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

## Production setup with Falcon Next-Gen SIEM

1. **Create the connector.** In the Falcon console, go to *Next-Gen SIEM → Data onboarding → Add data connector → HEC / HTTP Event Data Connector*. Assign a parser (start from [`deploy/ngsiem/flowtrim-parser.logscale`](deploy/ngsiem/flowtrim-parser.logscale)), save, then **Generate API key**. Copy the API key, which is shown only once, and the API URL.
2. **Configure FlowTrim.** Copy [`examples/flowtrim.yaml`](examples/flowtrim.yaml) to `/etc/flowtrim/flowtrim.yaml`. Put the URL and key in the environment (`NGSIEM_URL`, `NGSIEM_TOKEN`), never in the file. The URL works with or without the `/services/collector` suffix.
3. **Validate.** Run `flowtrim check -config /etc/flowtrim/flowtrim.yaml`.
4. **Run in `mode: shadow` for at least a week.** Everything is forwarded unreduced. `GET :9109/shadow` and a `shadow_report` event in NG-SIEM show what enforce mode *would* send, per rule.
5. **Review, tune, and switch to `mode: enforce`.** Mode changes need a restart. Rule edits reload live with `kill -HUP`.

Deployment files: [`deploy/systemd`](deploy/systemd), [`deploy/docker`](deploy/docker) (with a docker-compose demo), [`deploy/sysctl`](deploy/sysctl/99-flowtrim.conf).

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

- [docs/PLAN.md](docs/PLAN.md): architecture, roadmap, and the **risks and unknowns register**
- [docs/RULES.md](docs/RULES.md): rule reference and a tuning playbook
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md): what was measured and how

## Status

`v0.1.0` (MVP). Tested against a local HEC mock. **Not yet validated against a live NG-SIEM tenant.** See the first items of the unknowns register in [docs/PLAN.md](docs/PLAN.md).

## License and trademarks

Apache-2.0. Third-party notices are in [NOTICE](NOTICE). FlowTrim is an independent open-source project. "CrowdStrike", "Falcon" and "Falcon Next-Gen SIEM" are trademarks of CrowdStrike, Inc., used here only to describe compatibility. FlowTrim is not affiliated with, or endorsed by, ElastiFlow.
