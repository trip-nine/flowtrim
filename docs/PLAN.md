# FlowTrim: Plan, Architecture, and the Unknowns Register

## 1. Goal

| Item | Definition |
|---|---|
| Problem | New flow sources (NetFlow/IPFIX from core and edge devices, cloud VPC flow logs) produce volumes that are expensive to ingest and mostly low-value |
| Outcome | Forward to **Falcon Next-Gen SIEM over HTTPS** a stream that is materially smaller and still supports detection and investigation |
| Non-goals | Dashboards, long-term storage, ML, a full replacement for SIEM-side processing |
| Success metric | ≥ 50% fewer uncompressed bytes reaching NG-SIEM in shadow measurements on real traffic, with **zero** reduction applied to bypass classes |

## 2. Architecture

```
inputs ──► normalize ──► engine (single goroutine) ──► encoders (4) ──► batcher ──► queue (disk|mem) ──► senders (N) ──► NG-SIEM HEC
 netflow    sampling       dedup → bypass → drop          OCSF→HEC JSON     size/time     fsync, FIFO,        retry, 413 split,
 sflow      scaling,       → fanout observe → rollup                       gzip          drop_oldest|block   415 gzip fallback,
 firehose   direction      tick: flush windows/summaries                                                    401 hold, 4xx dead-letter
```

| Component | Choice | Rationale |
|---|---|---|
| Language | Go 1.24, static binary | One artifact, no runtime, FIPS build path (`GOFIPS140`) |
| Decoding | goflow2 v2 (BSD-3) as a library | Mature NetFlow v5/v9/IPFIX/sFlow decoding, template cache, sampling-rate handling |
| UDP receive | FlowTrim's own (`SO_REUSEPORT` + `SO_RCVBUF`/`SO_RCVBUFFORCE`) | goflow2's receiver leaves the kernel default (≈208 KB) in place. That was the main source of loss in testing. |
| Engine | Single-threaded, FIFO expiry queues, `maphash` keys | Deterministic and easy to reason about. ≈2.4M flows/s per core in the rollup path |
| Schema | OCSF Network Activity (4001) shape, FlowTrim extras under `unmapped.flowtrim` | Vendor-neutral, predictable for NG-SIEM parsers |
| Transport | HEC envelope, NDJSON-style body, `Authorization: Bearer`, gzip | Matches the NG-SIEM HEC/HTTP Event Data Connector contract used by other shippers |
| Durability | Disk queue: one fsynced file per batch, recovered on start | Survives NG-SIEM outages and restarts. At-least-once delivery. |

## 3. Roadmap

| Phase | Scope | Status |
|---|---|---|
| **v0.1 MVP** | NetFlow v5/v9/IPFIX, sFlow, AWS VPC via Firehose. Dedup/bypass/drop/rollup/fanout/drop-summary. Shadow mode. NG-SIEM HEC output with gzip, batching, retry, 413 split, disk queue. Prometheus. SIGHUP rule reload. Docker, systemd. | **Built and tested locally** |
| v0.2 | Live-tenant validation (register items U1–U6). Helm chart (StatefulSet + PVC). Signed releases + SBOM (goreleaser, cosign). CI license scan. | Next |
| v0.3 | Azure VNet flow logs (Blob + Event Grid), GCP VPC (Pub/Sub). S3+SQS pull for AWS. | Planned |
| v0.2.x | `output.hec` with `ngsiem`/`onum`/`generic` presets, gzip probe, deployment profiles, user/setup/config docs | **Done** |
| v0.3.0 | **Enrichment parity** (GeoIP/ASN, DNS, hostnames, metadata, SNMP and file interface names, services, SaaS apps, threat lists, Community ID, client/server, pseudonymization, sampling overrides). **FlowTrim Console** UI. **Demo package** (IPFIX/v9/v5 captures + manifests, replay with retime, mock Onum → mock NG-SIEM). MIT license. | **Done** |
| v0.4 | "First-seen destination" bypass. Interface names from v9/IPFIX option templates. Vendor IE mapping. Helm chart. Signed releases + SBOM. | Planned |
| v1.0 | Multi-replica guidance with exporter affinity. CEL expressions in matchers. Per-rule rate limits. Zeek `conn.log` input. Hardening review. | Planned |

## 4. Risks and Unknowns Register

Status: **Open** = needs evidence; **Mitigated** = the design handles it, but it should still be verified; **Accepted** = documented limitation.

### 4a. NG-SIEM / HEC contract (verify first in a lab tenant)

| ID | Unknown | Why it matters | Current handling | Status |
|---|---|---|---|---|
| U1 | **Does the NG-SIEM HEC endpoint accept `Content-Encoding: gzip`?** | Gzip is a large wire saving, roughly 10–20× on this JSON | Defaults to on. A `415` response automatically switches gzip off and resends the batch uncompressed. Override with `gzip: false`. | Open |
| U2 | **Maximum request body and per-event size** | Wrong batch sizing causes rejects | Batch defaults to 2 MiB uncompressed and 1,000 events. `413` splits the batch in half recursively. A single oversize event is dead-lettered. LogScale documents a 1 MiB raw-event cap. | Mitigated |
| U3 | **Rate limits and `429` behavior** | Throttling during bursts | Exponential backoff with jitter, honors `Retry-After`, disk queue absorbs the backlog | Mitigated |
| U4 | **How NG-SIEM meters ingest (uncompressed vs wire bytes; per connector)** | Determines the real cost saving | Exposes both `flowtrim_output_uncompressed_bytes_total` and `..._wire_bytes_total`. Assume uncompressed is what gets metered. | Open |
| U5 | **Parser behavior for HEC JSON events** (auto-parse of `event`, field names, CPS normalization) | Searchability and detections | Starter parser in `deploy/ngsiem/`. Validate field names in the tenant. | Open |
| U6 | **Do `activity_id: 99` summary records trigger any built-in correlation rules or dashboards?** | Noise or false positives | Summaries are clearly typed under `unmapped.flowtrim.record_type`. Filter them in the parser if needed. | Open |
| U7 | Regions and GovCloud URLs (`us-1`, `us-2`, `eu-1`, `us-gov-1`, `us-gov-2`) | Correct endpoint | The URL comes verbatim from the connector page | Mitigated |
| U8 | **Duplicates after a timeout** (request accepted but the response was lost) | HEC has no idempotency key, so a retry can duplicate a batch | Accepted as at-least-once. Duplicates are rare and limited to whole batches. | Accepted |
| U9 | API key rotation | Outage if the key expires or is revoked | `401`/`403` keeps data queued (never drops) and logs loudly. Rotate by updating the environment and restarting. | Mitigated |

### 4a-2. Onum in the path (Layout A)

| ID | Unknown | Why it matters | Current handling | Status |
|---|---|---|---|---|
| O1 | Which Onum Listener fits (Splunk HEC, HTTP, HTTP Standard Inbound), and its auth header and path | Output correctness | `target: onum` preset = `Splunk` auth on `/services/collector/event`. Override with `auth_scheme`/`path`. | Open |
| O2 | Does the Onum Listener accept gzip and batched HEC bodies? What is its size limit? | Throughput | The gzip probe falls back safely. 413 splits. | Open |
| O3 | Does the Onum pipeline re-wrap FlowTrim's event before the NG-SIEM Data Sink? | Double-nested JSON, wrong parser fields | Onum's CrowdStrike integration guide requires the NG-SIEM Data Sink's event format to be **Raw**. Set that, and verify in the lab. | Partly resolved |
| O4 | Is the flow-end timestamp kept end to end? | `@timestamp` accuracy | HEC `time` = flow end. Check that the Onum sink passes it through. | Open |
| O5 | Does Onum bill by volume? | Savings case | Reducing before Onum saves at both hops if it does | Open |
| O6 | Where FlowTrim runs relative to Onum Distributors | Latency, failure domains | One per site, next to the Distributor, with exporter affinity | Mitigated |

### 4b. Flow semantics

| ID | Unknown | Handling | Status |
|---|---|---|---|
| F1 | Timestamp semantics: v5/v9 times are relative to sysUptime, and exporter clocks skew | goflow2 converts them to absolute UTC. HEC `time` is the flow **end**. Dedup has ±1 s tolerance plus neighbor buckets. **TODO:** a metric for exporter skew greater than N seconds. | Partially mitigated |
| F2 | v9/IPFIX templates are lost when an exporter restarts | Flows arriving before the template are counted (`template_not_found_packets`) and dropped by necessity | Accepted |
| F3 | Sampling-rate normalization | Bytes and packets are multiplied by the sampling rate exactly once. The rate is kept in `sampling_rate`, and `sampling_scaled` records that scaling happened. | Mitigated |
| F4 | NAT and duplicate visibility across hops | Dedup keys exclude the exporter, so the same 5-tuple seen pre- and post-NAT is *not* a duplicate, which is correct | Mitigated |
| F5 | Synthetic-looking identical flows (the same host/ports/bytes within 1 s) are treated as duplicates | This matches how exporters aggregate flows. Narrow `dedup.key` or `start_tolerance` if needed. | Accepted |
| F6 | Cloud sources are already aggregated (AWS uses 1- or 10-minute windows) | Exclude them from rollup with `match: { source: [netflow, sflow] }`, or accept the coarse rollup | Documented |
| F7 | Firehose at-least-once: FlowTrim acknowledges with `200` once flows are in memory | A crash between the acknowledgement and the disk queue loses that window (seconds). Use a disk queue and a short `batch.max_wait`. | Accepted |

### 4c. Scale and operations

| ID | Unknown | Handling | Status |
|---|---|---|---|
| S1 | UDP loss at the kernel | 32 MiB `SO_RCVBUF` by default, `SO_RCVBUFFORCE` fallback, a warning when the buffer is capped. Ships `deploy/sysctl/99-flowtrim.conf`. | Mitigated |
| S2 | Stateful windows across replicas | Rollup/dedup state is per instance. Use source-IP affinity (one exporter → one replica). Duplicate exports from *different* routers only dedup when they hit the same instance. | Documented |
| S3 | Memory ceilings | `dedup.max_entries`, `rollup.max_keys`, `fanout.max_sources`. **Fails open** when exceeded (passes raw and counts it). | Mitigated |
| S4 | Backpressure policy during long NG-SIEM outages | Disk queue up to `max_bytes`, then `drop_oldest` (counted) or `block` (pushes loss to the UDP socket) | Mitigated |
| S5 | Engine CPU ceiling (single goroutine) | ≈2.4M flows/s per core for the engine alone. JSON encoding is parallel. Shard engines by src/dst hash if ever needed. | Accepted for v0.x |

### 4d. Security, privacy, compliance

| ID | Unknown | Handling | Status |
|---|---|---|---|
| P1 | Over-aggressive drop rules hide attacks | Shadow mode is the default, empty drop matches are refused, bypass beats drop, `drop_summary` keeps an audit trail, `rule_version` is stamped on every record | Mitigated |
| P2 | Rule drift and unreviewed changes | Keep rules in Git. The `rule_version` hash is on every record and in `flowtrim_build_info`. | Mitigated |
| P3 | IP addresses are personal data under GDPR; data residency | Choose the NG-SIEM region. **TODO:** optional IP truncation or hashing for selected CIDRs. | Open |
| P4 | Collector attack surface (open UDP, Firehose HTTPS) | `allowed_exporters`, constant-time Firehose key check, body limits, non-root container, read-only rootfs. Telemetry binds to localhost by default. | Mitigated |
| P5 | FedRAMP / GovCloud customers | No phone-home. Static binary. **TODO:** document a `GOFIPS140=v1.0.0` build and test against `us-gov-1`. | Open |

### 4e. Legal and project hygiene

| ID | Unknown | Handling | Status |
|---|---|---|---|
| L1 | **Project ownership.** FlowTrim works with CrowdStrike products but is not CrowdStrike software. | It is an independent, community open-source project under the personal `trip-nine` GitHub account, built for the CrowdStrike user community. It uses only public, documented APIs and endpoints (HEC, NG-SIEM HTTP Event Collector, Onum HTTP listener). The README states it is not affiliated with or endorsed by CrowdStrike. | **Resolved.** The repo has been public since 2026-11-16. |
| L2 | License contamination | Every linked dependency is MIT, BSD, ISC or Apache-2.0, all compatible with the MIT project license (see NOTICE). No ElastiFlow code, schema or field names. No GPL/AGPL (for example Akvorado). `go-licenses` runs in CI. | Mitigated |
| L3 | Trademarks in the project name | The name avoids "Elasti-", "Falcon", "CrowdStrike" and "Onum". Those marks are used only nominatively, with a trademark notice in the README. A GitHub and USPTO search for "FlowTrim" is still worth doing. | Mitigated |
| L4 | Support expectations now that the repo is public | `SECURITY.md`, bug and feature issue templates, and a "best effort, no SLA" Support section in the README | Mitigated |

### 4f. The "unknown unknowns" probe list

These are questions to ask in the first lab week. They usually surface the issues nobody thought to list.

1. What share of exporters send **v9/IPFIX options templates** that change the sampling rate during the day?
2. Do any exporters send **egress *and* ingress** records for the same flow on the same device? Those are not duplicates under the default key, but they double the volume.
3. Are there **asymmetric paths**, where dedup across routers only works on one direction?
4. Which **existing NG-SIEM detections and dashboards** query raw flow fields that rollup removes (for example per-flow `src_port`)?
5. Does the SOC run **retro-hunts** that need per-flow granularity for drop classes? If so, keep a short raw archive elsewhere.
6. What is the **true daily peak and burst ratio** (p99 per second, not the daily average)?
7. Will other teams want this data with **different reduction policies**? That calls for multiple outputs in v0.3+.
