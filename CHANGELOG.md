# Changelog

All notable changes to FlowTrim. Versions follow [Semantic Versioning](https://semver.org/). Pre-1.0 minor versions may change configuration.

## [0.3.0] — 2026-11-16

### Added
- **Enrichment, at parity with ElastiFlow's enrichment features:** GeoIP/ASN from any MMDB (MaxMind, DB-IP, IPinfo; both schemas), async reverse DNS with caching and include/exclude scope, user-defined hostnames and CIDR metadata, interface names from a file or SNMP (IF-MIB, v2c/v3), port → service names, SaaS/app identification by CIDR, threat-list tagging with severity, Community ID v1 (checked against the reference implementation), client/server inference, IP pseudonymization (HMAC or truncate), per-exporter sampling-rate overrides.
- **FlowTrim Console**, embedded at the telemetry port: live animated pipeline (NetFlow → FlowTrim → Onum → NG-SIEM), KPIs, reduction funnel, rule hits, enrichment status and parity, delivery health, record inspector (input next to output), end-to-end walkthrough, sizing calculator. Falls back to a built-in simulation when no backend is reachable.
- Console API: `/api/status`, `/api/records`, `/api/downstream`.
- **Demo package:** IPFIX, NetFlow v9 and NetFlow v5 sample captures with ground-truth manifests; `flowgen gen` (v5/v9/IPFIX, IPv6, pcap output) and `flowgen replay` (any classic pcap, timestamp retiming); `mockhec -role onum|ngsiem` for a full mock chain; `demo/run-demo.sh`; Docker Compose full-chain demo.
- Docs: quick start with diagrams and sizing, enrichment and parity, demo package.

### Changed
- **License changed from Apache-2.0 to MIT.**
- Go module path is now `github.com/trip-nine/flowtrim`.

## [0.2.0] — 2026-11-16

### Added
- `output.hec` with `target: ngsiem | onum | generic` presets. `output.ngsiem` is kept as an alias.
- Gzip probe: a 400/415 on a gzip body is retried uncompressed before the batch is dead-lettered.
- Deployment profiles: `onum-onprem`, `onum-cloud`, `ngsiem-direct`, `collector-only`.
- Docs: overview, setup, user guide, configuration reference, Mermaid diagrams, rendered docs-site builder.

## [0.1.0] — 2026-11-16

### Added
- NetFlow v5/v9, IPFIX, sFlow v5 (goflow2) and AWS VPC Flow Logs (Firehose HTTP endpoint) inputs.
- Reduction engine: dedup, bypass, drop, rollup (with inter-arrival statistics), fanout summaries, drop summaries.
- Shadow mode with a projected-savings report.
- NG-SIEM HEC output: batching, gzip, retry with backoff, 413 split, 401 hold, dead letters, disk queue.
- Custom UDP receiver with large socket buffers (zero loss at 200k flows/s on 2 vCPUs in the lab).
- Prometheus metrics, SIGHUP rule reload, systemd unit, Dockerfile.

[0.3.0]: https://github.com/trip-nine/flowtrim/releases/tag/v0.3.0
[0.2.0]: https://github.com/trip-nine/flowtrim/releases/tag/v0.2.0
[0.1.0]: https://github.com/trip-nine/flowtrim/releases/tag/v0.1.0
