# Rule Reference and Tuning Playbook

## Evaluation order

```
dedup (if apply_to_bypass) → bypass → dedup → drop → fanout observe → rollup (if rollup.match) → raw
```

- Rules in `bypass` and `drop` are checked **in order**. The **first match wins**.
- Conditions inside one `match` are **ANDed**. A list inside one condition is **ORed**.

## Match conditions

| Key | Type | Example | Notes |
|---|---|---|---|
| `src_cidr`, `dst_cidr`, `any_cidr` | list of IP/CIDR | `["10.0.0.0/8", "2001:db8::/32"]` | `any_` = src OR dst |
| `src_ip_in_list`, `dst_ip_in_list`, `any_ip_in_list` | file path | `intel.txt` | One IP/CIDR per line. `#` comments. Reloaded on SIGHUP. |
| `src_port`, `dst_port` | list of ports/ranges | `["22", "5985-5986"]` | |
| `proto` | list | `[tcp, udp, "47"]` | Names or IANA numbers |
| `exporter` | list of IP/CIDR | `["192.0.2.1"]` | The device that exported the flow |
| `action` | list | `[REJECT, DENY]` | Cloud and firewall exports |
| `log_status` | list | `[NODATA, SKIPDATA]` | AWS VPC |
| `direction` | list | `[internal, outbound, inbound, external]` | Computed from `networks.internal` |
| `source` | list | `[netflow, sflow, aws_firehose]` | Which input received the flow |
| `bytes_lt`, `bytes_gt`, `packets_lt`, `packets_gt` | number | `bytes_lt: 100` | Evaluated after sampling scaling |
| `tcp_flags_any`, `tcp_flags_none` | bitmask | `tcp_flags_any: 2` (SYN) | |
| `not` | nested match | `not: { src_cidr: ["10.9.0.0/16"] }` | Excludes |

## Tuning playbook

1. **Start in shadow mode** with only bypass rules and `multicast_broadcast`.
2. **Find the top talkers.** In NG-SIEM, group the raw shadow records by `dst_endpoint.ip`, `dst_endpoint.port` and `connection_info.protocol_num`, and sort by count. The top 20 usually account for most of the volume.
3. For each top talker, ask two questions. *Would any detection or investigation miss this record?* *Is the destination one we own and trust?* Only "no" plus "yes" earns a **drop** rule. Otherwise it is a **rollup** candidate.
4. **Re-read `/shadow`** after every change (`kill -HUP <pid>`). Look at `flows_by_decision`.
5. **Switch to enforce** once the projected `total_byte_reduction_pct` is stable and the SOC has signed off.

## Rules of thumb

| Do | Don't |
|---|---|
| Drop DNS/NTP **to your own resolvers and servers** | Drop all DNS. Tunneling detections need DNS to unknown resolvers. |
| Keep `REJECT`/`DENY` in bypass | Sample. Low-and-slow C2 and single-packet scans disappear. |
| Roll up internal and outbound chatter | Roll up inbound from the internet, unless you have measured it |
| Keep lateral-movement ports in bypass | Remove `fanout`. It is what keeps sweep visibility after rollup. |
| Exclude already-aggregated cloud logs from rollup if timing matters | Edit rules in production without Git. `rule_version` will show it. |
