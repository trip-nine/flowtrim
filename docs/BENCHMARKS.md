# Benchmarks (v0.1.0, local)

**Environment:** a 2 vCPU Linux container. FlowTrim, the traffic generator (`flowgen`) and the HEC mock (`mockhec`) all shared the same 2 vCPUs, so these numbers are a floor. Synthetic NetFlow v5, 30 records per packet. The mock does not reproduce NG-SIEM latency or limits.

## Throughput and loss

| Offered rate | Mode | Flows offered / received | Kernel `RcvbufErrors` | Decode-queue drops |
|---|---|---|---|---|
| 60,000 flows/s × 10 s | enforce | 600,005 / 600,005 | 0 | 0 |
| 60,000 flows/s × 10 s | shadow (double encode) | 600,005 / 600,005 | 0 | 0 |
| 120,000 flows/s × 8 s | enforce | 960,004 / 960,004 | 0 | 0 |
| 200,000 flows/s × 8 s | enforce | 1,600,004 / 1,600,004 | 0 | 0 |

Before FlowTrim replaced goflow2's UDP receiver with one that sets `SO_RCVBUF`, the same 60k flows/s test **lost 27–44%** of flows in the kernel. The default 208 KB socket buffer was overflowing.

Engine micro-benchmark (`go test -bench . ./internal/rules`): **≈412 ns/flow, 3 allocs** in the rollup path, which is about 2.4M flows/s on one core.

## Reduction on the synthetic mix (enforce, 5 s windows)

| Stage | Flows |
|---|---|
| Received (incl. 30% duplicate re-exports from a 2nd router) | 47,348 |
| Dedup | 14,648 |
| Dropped (DNS/NTP to corp servers, multicast) | 7,474 |
| Bypassed raw (intel, lateral ports) | 1,236 |
| Folded into 236 rollups | 23,990 |
| **Records sent** | **10,916 (−77% events)** |
| Uncompressed bytes sent | 9.9 MB (vs ≈42.9 MB unreduced) |
| Wire bytes with gzip | 0.46 MB |

**Caveat:** synthetic traffic is far more repetitive than real networks, and the generator was built to contain reducible patterns. Treat these ratios as a demonstration that the mechanism works, not as a forecast. Measure your own traffic in shadow mode.

## Reproduce

```bash
bash <<'FLOWTRIM_BENCH'
set -euo pipefail
cd "$HOME/src/flowtrim"
go test -run xxx -bench . -benchmem ./internal/rules/
FLOWTRIM_BENCH
```
