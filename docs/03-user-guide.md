# 3. User Guide

For operators and SOC analysts who run FlowTrim day to day, or read its output in the SIEM.

## 3.1 Key concepts

| Term | Meaning |
|---|---|
| **Flow** | One record from an exporter: who talked to whom, on which ports, how much, and when |
| **Exporter** | The device that sent the flow (router, firewall, probe) |
| **Mode** | `shadow` forwards everything and measures what enforce would save. `enforce` actually reduces. |
| **Bypass** | Rules whose matches are **never reduced** |
| **Drop** | Rules whose matches are discarded and counted in a `drop_summary` |
| **Rollup** | Many flows of one conversation, folded into one record per window |
| **Fanout summary** | A record that flags a source touching many destinations (possible scan or sweep) |
| **Rule version** | A 12-character hash of the `rules:` section, stamped on every record |

## 3.2 The two modes

| | `shadow` (default) | `enforce` |
|---|---|---|
| What's forwarded | Every flow, unreduced, tagged `shadow: true` | Reduced output only |
| What's measured | The output enforce mode *would* produce | Actual output |
| Extra records | `shadow_report` every 5 min | `drop_summary`, `fanout_summary` |
| Risk | None. It only measures. | Drops data. Needs SOC sign-off. |
| How to switch | Edit `mode:` and **restart**. A reload can't change the mode, on purpose. | |

## 3.3 Reading FlowTrim records

Every record is OCSF Network Activity (`class_uid: 4001`). What FlowTrim adds is under `unmapped.flowtrim`.

| `unmapped.flowtrim.reduction` | What the record is | Key fields |
|---|---|---|
| `none` | One original flow, untouched | `start_time`, `end_time`, `traffic.bytes` |
| `bypass` | One original flow that matched a protected rule | `rule` tells you which |
| `rollup` | Many flows of one conversation in one window | `count`/`flow_count`, `start_time` = first seen, `end_time` = last seen, `traffic` = sums, `tcp_flags` = union, `iat_ms` = gap statistics, `distinct_src_ports` |

| `unmapped.flowtrim.record_type` | What it is |
|---|---|
| `drop_summary` | Per drop rule per interval: flows, bytes and packets discarded |
| `fanout_summary` | Per source per window: `unique_dst_ips`, `unique_dst_ports`, `capped` |
| `shadow_report` | Projected savings per decision and rule |

### How to read `iat_ms` (beaconing)

`iat_ms` describes the **gaps between connection start times** inside a rollup.

| Pattern | `mean` | `stddev` | Likely meaning |
|---|---|---|---|
| Machine-regular | 2000 | < 50 | Timer-driven: a heartbeat, a health check, **or a C2 beacon** |
| Human / bursty | 4000 | > 2000 | Interactive or on-demand traffic |
| Few samples | — | — | Fewer than 3 flows, so no statistics are computed |

## 3.4 Starter searches in NG-SIEM

These assume the starter parser (`deploy/ngsiem/flowtrim-parser.logscale`). Adjust the field names if your parser differs.

**Top talkers by bytes (tuning)**

```
#Vendor="flowtrim"
| groupBy([destination.ip, destination.port], function=sum(network.bytes, as=bytes))
| sort(bytes, limit=20)
```

**Beacon candidates**

```
#Vendor="flowtrim" Vendor.unmapped.flowtrim.reduction="rollup"
| Vendor.unmapped.flowtrim.flow_count > 20
| Vendor.unmapped.flowtrim.iat_ms.stddev < 50
| table([source.ip, destination.ip, destination.port, Vendor.unmapped.flowtrim.iat_ms.mean, Vendor.unmapped.flowtrim.flow_count])
```

**Scans and sweeps**

```
#Vendor="flowtrim" Vendor.unmapped.flowtrim.record_type="fanout_summary"
| sort(Vendor.unmapped.flowtrim.unique_dst_ips, limit=50)
```

**What did we drop? (audit)**

```
#Vendor="flowtrim" Vendor.unmapped.flowtrim.record_type="drop_summary"
| groupBy(Vendor.unmapped.flowtrim.rule, function=[sum(Vendor.unmapped.flowtrim.flows, as=flows), sum(Vendor.unmapped.flowtrim.bytes, as=bytes)])
```

**Which rule set produced this data?**

```
#Vendor="flowtrim" | groupBy(Vendor.unmapped.flowtrim.rule_version)
```

## 3.5 Day-to-day operations

| Task | How |
|---|---|
| Reload rules or intel lists | `sudo systemctl reload flowtrim` (SIGHUP). Open rollups are flushed first, so nothing is lost. |
| Check config before a reload | `flowtrim check -config /etc/flowtrim/flowtrim.yaml` |
| See projected savings | `curl -s localhost:9109/shadow` |
| Update the intel list | Edit the file, then reload |
| Rotate the token | Update `/etc/flowtrim/flowtrim.env`, then `sudo systemctl restart flowtrim`. Queued data is kept. |
| Safe restart | `systemctl restart`. FlowTrim drains for up to 30 s, and anything left stays on disk. |
| Inspect undeliverable batches | `/var/lib/flowtrim/queue/dead/`. Each `.g.batch` file is gzip NDJSON (`zcat`). |

### Recommended alerts

| Alert | PromQL | Why |
|---|---|---|
| Flows stopped | `rate(flowtrim_flows_received_total[5m]) == 0` | Exporter or network issue |
| Flows rejected | `rate(flowtrim_flows_rejected_total[5m]) > 0` | Unknown exporter, decode errors, saturation |
| Backlog growing | `deriv(flowtrim_queue_bytes[15m]) > 0` | Receiver slow or down |
| Auth failing | `increase(flowtrim_output_batches_total{result="auth_error"}[5m]) > 0` | Token revoked or expired |
| Data lost | `increase(flowtrim_output_events_lost_total[1h]) > 0` | Queue overflow or dead letters |
| Capacity | `increase(flowtrim_decisions_total{decision=~".*capacity_exceeded"}[15m]) > 0` | Raise `max_keys`/`max_entries`. FlowTrim fails open (passes flows raw) meanwhile. |

## 3.6 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `flowtrim_flows_received_total` stays at 0 | Firewall, wrong port, exporter blocked by `allowed_exporters` | `tcpdump -ni any udp port 2055`; check the `flows_rejected{reason="exporter_not_allowed"}` metric |
| Many `template_not_found_packets` | v9/IPFIX template not received yet | Normal for about 60 s after a start. Lower `template data timeout` on the exporter. |
| Log warns "UDP receive buffer smaller than requested" | `net.core.rmem_max` too low and no `CAP_NET_ADMIN` | Apply `deploy/sysctl/99-flowtrim.conf` |
| `RcvbufErrors` rising | Kernel dropping packets | Bigger buffer, more `sockets`/`workers`, or more vCPU |
| `auth_error` batches | Wrong token or wrong `auth_scheme` | NG-SIEM: `Bearer`. Onum: check the Listener. Set `auth_scheme` explicitly. |
| Log says "receiver cannot read gzip bodies" | Receiver doesn't accept gzip | Set `gzip: false` to stop the probe each start |
| Records in NG-SIEM but fields missing | Parser not assigned, or field names differ | Assign or adjust the parser. Test it with a sample record. |
| `@timestamp` equals arrival time | Onum pipeline re-wrapped the event | Forward the body unchanged (Setup §2.3) |
| Savings lower than expected | Most traffic is unique egress | Expected. Look at the top talkers; rollup helps chatty *internal* traffic most. |

## 3.7 FAQ

**Does FlowTrim ever drop something I didn't tell it to?**
Only exact duplicates, which you can turn off with `dedup.enabled: false`. Records that hit capacity limits are passed raw, never dropped.

**Can a rollup hide an attack?**
Rollups keep first/last seen, totals, the TCP-flag union and gap statistics. Port scans and sweeps show up in `fanout_summary`. Denied traffic, intel hits and lateral-movement ports bypass rollup entirely. What you lose is per-flow source ports and per-flow timing inside the window. Keep any class where that matters in `bypass`.

**Is it at-least-once or exactly-once?**
At-least-once. In rare timeout cases a batch can arrive twice.

**Do I need Onum?**
No. Layout C sends directly to NG-SIEM. With Onum, FlowTrim slots in front of it ([Overview](01-overview.md)).
