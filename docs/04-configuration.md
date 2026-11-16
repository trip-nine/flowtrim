# 4. Configuration Reference

One file: `flowtrim.yaml`. Parsing is **strict**: an unknown key is an error, which catches typos. Validate with `flowtrim check -config <file>`.

- **Secrets:** use `${VAR}` or `${VAR:-default}` anywhere. Values are read from the environment at load time.
- **Durations:** `500ms`, `30s`, `5m`, `1h`.
- **Sizes:** `512KiB`, `2MiB`, `10GiB`, or plain bytes.
- **Relative paths** (intel lists) resolve from the config file's folder.
- **Reload:** `rules`, `networks` and `normalize` reload on SIGHUP. Everything else needs a restart.

## 4.1 Top level

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | `shadow` \| `enforce` | `shadow` | See [User Guide §3.2](03-user-guide.md#32-the-two-modes) |
| `log_level` | `debug` \| `info` \| `warn` \| `error` | `info` | JSON logs to stderr |
| `networks.internal` | list of CIDR | RFC 1918, `100.64/10`, `fc00::/7`, `fe80::/10` | Your address space. Drives `direction`. |

`direction` is computed per flow:

| Source in `internal`? | Destination in `internal`? | `direction` |
|---|---|---|
| yes | yes | `internal` |
| yes | no | `outbound` |
| no | yes | `inbound` |
| no | no | `external` |

## 4.2 `inputs.netflow` and `inputs.sflow`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | list of `host:port` | required | NetFlow v5/v9 and IPFIX are detected per packet |
| `sockets` | int | `1` | `SO_REUSEPORT` sockets per address (Linux) |
| `workers` | int | `2` | Decode goroutines per address |
| `queue_size` | int | `100000` | Packets buffered between socket and decoders. Overflow is counted as `decode_queue_full_packets`. |
| `rcvbuf_bytes` | size | `32MiB` | Kernel receive buffer per socket. Needs `net.core.rmem_max` or `CAP_NET_ADMIN`. |
| `allowed_exporters` | list of CIDR | all | Accept flows only from these exporters |

## 4.3 `inputs.aws_firehose`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | `host:port` | required | HTTPS listener |
| `tls_cert`, `tls_key` | path | — | Required unless TLS is terminated in front |
| `access_key` | string | required | Must match the Firehose stream's access key (`X-Amz-Firehose-Access-Key`) |
| `fields` | list | AWS v2 default (14 fields) | The VPC flow log format, in order |
| `max_body` | size | `64MiB` | Request size limit |

Accepted record shapes: plain flow-log lines, gzip-compressed records, CloudWatch Logs subscription envelopes, and JSON objects with a `message` field.

## 4.4 `normalize`

| Key | Type | Default | Description |
|---|---|---|---|
| `scale_by_sampling_rate` | bool | `true` | Multiply bytes and packets by the exporter's sampling rate once. The rate is kept in `sampling_rate`. |

## 4.5 `rules`

Order: `dedup` (when `apply_to_bypass`) → `bypass` → `dedup` → `drop` → `fanout` → `rollup` → raw. The match syntax is in [RULES.md](RULES.md).

### `rules.bypass[]`, `rules.drop[]`

| Key | Type | Description |
|---|---|---|
| `name` | string, unique | Appears in metrics, records and `drop_summary` |
| `match` | match object | An empty `match` is **refused** in `drop`, because it would drop everything |

### `rules.dedup`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `key` | list | `src_ip, dst_ip, src_port, dst_port, proto, start_time, bytes, packets` | Allowed: `src_ip dst_ip src_port dst_port proto action exporter in_if out_if start_time end_time bytes packets tcp_flags`. Leave `exporter` out to catch cross-router duplicates. |
| `start_tolerance` | duration | `1s` | Clock-skew tolerance between exporters |
| `window` | duration | `30s` | How long a flow is remembered |
| `max_entries` | int | `2000000` | Memory cap. When full, flows pass (fail open). |
| `apply_to_bypass` | bool | `true` | Also dedup flows that bypass |

### `rules.rollup`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `key` | list | `src_ip, dst_ip, dst_port, proto, action` | Allowed: `src_ip dst_ip src_port dst_port proto action exporter in_if out_if direction source` |
| `match` | match object | all | Only matching flows are rolled up |
| `window` | duration | `60s` | Window per conversation, starting at its first flow |
| `max_keys` | int | `500000` | Memory cap. When full, flows pass raw (fail open). |
| `iat_samples` | int | `64` | Start times kept for the gap statistics |

### `rules.fanout`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `window` | duration | `60s` | |
| `min_unique_dst_ips` | int | `50` | Emit a summary at or above this… |
| `min_unique_dst_ports` | int | `50` | …or this |
| `cap` | int | `1024` | Exact counting up to the cap, then `capped: true` |
| `max_sources` | int | `200000` | Memory cap |

### `rules.drop_summary`, `rules.prune_fields`

| Key | Type | Default | Description |
|---|---|---|---|
| `drop_summary.enabled` | bool | `true` | One audit record per drop rule per interval |
| `drop_summary.interval` | duration | `60s` | |
| `prune_fields` | list of dotted paths | `[]` | Removed from reduced output, e.g. `unmapped.flowtrim.icmp`, `device` |

## 4.6 `output.hec`

`output.ngsiem` (the v0.1.0 name) is still accepted as an alias for `output.hec` with `target: ngsiem`.

| Key | Type | Default | Description |
|---|---|---|---|
| `target` | `ngsiem` \| `onum` \| `generic` | `ngsiem` | Picks the defaults below |
| `url` | URL | required | The target's default path is appended when the URL has none |
| `token` | string | required | Use `${HEC_TOKEN}` |
| `auth_scheme` | string | per target | Sent as `Authorization: <scheme> <token>` |
| `path` | string | per target | Overrides the default path |
| `gzip` | bool | `true` | If the receiver rejects gzip (400/415), FlowTrim probes uncompressed and switches gzip off for this run only if that probe succeeds |
| `concurrency` | int | `4` | Parallel senders |
| `timeout` | duration | `15s` | Per request |
| `source` / `sourcetype` | string | `flowtrim` / empty | HEC envelope fields |
| `batch.max_events` | int | `1000` | Max `100000` |
| `batch.max_bytes` | size | `2MiB` | Uncompressed size |
| `batch.max_wait` | duration | `2s` | Latency ceiling |
| `retry.initial` / `retry.max` | duration | `500ms` / `60s` | Exponential backoff with jitter. `Retry-After` is honored. |
| `tls.ca_file` | path | system CAs | Extra CA (Onum On-Prem with a private CA) |
| `tls.client_cert` / `tls.client_key` | path | — | mTLS |
| `tls.insecure_skip_verify` | bool | `false` | Labs only |
| `proxy` | URL \| `none` | `HTTPS_PROXY` env | |
| `queue.dir` | path | memory only | **Set this in production.** Batches survive restarts and outages. |
| `queue.max_bytes` | size | `10GiB` (disk) / `256MiB` (memory) | |
| `queue.overflow` | `drop_oldest` \| `block` | `drop_oldest` | `block` pushes loss back to the UDP socket instead |

**Target presets**

| `target` | `auth_scheme` | Default path | Use with |
|---|---|---|---|
| `ngsiem` | `Bearer` | `/services/collector` | Falcon NG-SIEM HEC/HTTP Event Data Connector |
| `onum` | `Splunk` | `/services/collector/event` | Onum Splunk-HEC Listener (**lab-verify**) |
| `generic` | `Bearer` | none (put the path in `url`) | Any HEC-compatible receiver |

**Response handling**

| Receiver says | FlowTrim does |
|---|---|
| 2xx | Deletes the batch |
| 408, 429, 5xx, network error | Retries the same batch with backoff, forever (the queue absorbs it) |
| 413 | Splits the batch in half and resends. A single oversized event is dead-lettered. |
| 400/415 to a gzip body | Probes uncompressed: success turns gzip off, a repeat 400 dead-letters the batch |
| 401/403 | Keeps the batch, logs an error, retries slowly |
| Other 4xx | Dead-letters to `queue.dir/dead/` |

`output.stdout: true` also prints every record as NDJSON (debugging).

## 4.7 `telemetry`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | `host:port` | `127.0.0.1:9109` | `/metrics`, `/healthz`, `/readyz`, `/shadow` |
| `shadow_report_interval` | duration | `5m` | How often a `shadow_report` is logged and sent |

## 4.8 Minimal configs

**Smallest useful config (Layout C):**

```yaml
inputs:
  netflow: { listen: ["0.0.0.0:2055"] }
output:
  hec: { url: "${HEC_URL}", token: "${HEC_TOKEN}", queue: { dir: /var/lib/flowtrim/queue } }
```

This starts in shadow mode with no reduction rules. It's a pure collector until you add rules.

**Same, as JSON** (YAML is a superset of JSON, so this also works):

```json
{
  "mode": "shadow",
  "inputs": { "netflow": { "listen": ["0.0.0.0:2055"] } },
  "rules": {
    "bypass": [{ "name": "denied", "match": { "action": ["REJECT", "DENY"] } }],
    "dedup": { "enabled": true },
    "rollup": { "enabled": true, "window": "60s" }
  },
  "output": { "hec": { "target": "onum", "url": "${HEC_URL}", "token": "${HEC_TOKEN}" } }
}
```
