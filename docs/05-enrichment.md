# 5. Enrichment and ElastiFlow Parity

Enrichment runs **after** reduction, in the output's parallel encoder workers. It only touches records that will actually be sent, so a 70% reduction also means about 70% fewer lookups.

```mermaid
flowchart LR
  R["Reduced record"] --> H["Hostnames<br/>(file, then async DNS)"] --> M["Metadata<br/>CIDR → tags"] --> G["GeoIP / ASN<br/>MMDB"] --> IF["Interface names<br/>file, then SNMP"] --> S["Service + client/server"] --> A["SaaS app by CIDR"] --> T["Threat-list tags"] --> C["Community ID"] --> P["Pseudonymize<br/>(last)"] --> OUT["HEC JSON"]
```

## 5.1 Parity matrix

| ElastiFlow capability | FlowTrim | How |
|---|---|---|
| GeoIP enrichment | ✅ | Any MMDB: MaxMind GeoLite2/GeoIP2, DB-IP Lite, IPinfo Lite (both schemas handled) |
| Autonomous System enrichment | ✅ | ASN MMDB. The exporter's own AS numbers are kept, and the org name is added. |
| Reverse DNS (IPs to hostnames) | ✅ | Async, cached, never blocks the pipeline. Include/exclude CIDRs. Custom nameserver. |
| User-defined IP → hostname | ✅ | `enrich.hostnames_file`. Wins over DNS. |
| User-defined metadata for IPs | ✅ | `enrich.metadata_file`: CIDR → tags, longest prefix wins |
| AS/CIDR include/exclude for lookups | ✅ (CIDR) | `enrich.dns.include_cidrs` / `exclude_cidrs`, `enrich.scope.exclude_cidrs` |
| Interface names via SNMP | ✅ | IF-MIB `ifName`, `ifDescr`, `ifAlias`, `ifHighSpeed`. v2c and v3 (auth/priv). Tested against an SNMP agent simulator. |
| Interface names, user-defined | ✅ | `enrich.interfaces.file` |
| Interface names from v9/IPFIX option templates | ⏳ Roadmap | The goflow2 producer doesn't expose option records yet |
| Application ID (port → service) | ✅ | ~80 built-in services, extended with `apps.services_file` |
| SaaS identification (Microsoft 365, Salesforce, …) | ✅ (bring your ranges) | `apps.apps_file`: app → CIDRs. Feed it the providers' published ranges. |
| Threat intelligence | ✅ (bring your feed) | `enrich.threat_lists`: any IP/CIDR feed. Raises `severity_id`. ElastiFlow NetIntel is a commercial feed, so FlowTrim doesn't ship one. |
| Community ID | ✅ | v1, checked against the reference implementation, including the spec's published vectors |
| Infer client and server sides | ✅ | `unmapped.flowtrim.server: src\|dst` |
| Obscure IP addresses | ✅ | `privacy.pseudonymize`: HMAC (stable pseudonyms in 240/4 or fd00::/8) or prefix truncation |
| Sample-rate adjustment | ✅ | Automatic, plus `normalize.sampling_overrides` per exporter |
| Translate IE values / 6,900 vendor IEs | ➖ Partial | goflow2's core IE set. Vendor IE mapping is roadmap. |
| Dashboards | → NG-SIEM | By design |
| Rate cap on the free tier | **None** | ElastiFlow: 500 (no key) or 4,000 records/s (Basic) |

## 5.2 Does Onum do enrichment too?

Yes, according to Falcon Onum's own materials. The product page lists "Enrichment (GeoIP, asset data, threat intelligence, tags)", and Onum describes uploading your own data tables to enrich event streams. Two caveats:

- Onum's public docs don't show the specific GeoIP action configuration, or whether Cloud and On-Prem behave identically. **Verify in your tenant.**
- Onum can't do the flow-specific pieces: Community ID, client/server inference, SNMP interface names from the exporter, or cross-router dedup.

**Recommended split.** Do flow-specific enrichment in FlowTrim. Use Onum for organization-wide context such as CMDB, identity and business tags that other data sources share. Don't geo-enrich in both places. Pick one, and disable the other with `enrich.geoip` left empty.

## 5.3 Configuration

```yaml
enrich:
  geoip:
    city_db: /etc/flowtrim/GeoLite2-City.mmdb     # or dbip-city-lite.mmdb / ipinfo_lite.mmdb
    asn_db:  /etc/flowtrim/GeoLite2-ASN.mmdb      # optional when city_db already has ASN fields (IPinfo Lite)
    skip_internal: true
  dns:
    enabled: true
    nameserver: "10.0.0.53:53"     # empty = system resolver
    include_cidrs: [internal]      # "internal" = networks.internal
    exclude_cidrs: []
    cache_ttl: 1h
    negative_ttl: 5m
  hostnames_file: hostnames.yaml   # 10.1.5.5: wks-0417.corp.example
  metadata_file: metadata.yaml     # - cidr: 10.1.0.0/16  tags: {site: dallas, zone: prod}
  interfaces:
    file: interfaces.yaml          # 192.0.2.1: {3: {name: Gi0/0/3, description: uplink, speed_mbps: 10000}}
    snmp:
      enabled: true
      version: "3"                 # or "2c" with community: ${SNMP_COMMUNITY}
      v3: { user: flowtrim, level: authPriv, auth_proto: SHA256, auth_pass: "${SNMP_AUTH}", priv_proto: AES, priv_pass: "${SNMP_PRIV}" }
      interval: 15m
      exporters: []                # empty = poll every exporter seen
  apps:
    services: true                 # built-in port → service names
    services_file: services.yaml   # "tcp/8443": corp-portal
    apps_file: apps.yaml           # "Microsoft 365": [13.107.6.152/31, 52.112.0.0/14, …]
  threat_lists:
    - { name: feodo, file: /var/lib/flowtrim/feodo.txt, severity: high }
  community_id: { enabled: true, seed: 0 }
  client_server: true

privacy:
  key: "${FLOWTRIM_PSEUDO_KEY}"    # ≥ 16 chars
  pseudonymize:
    - { cidr: 10.50.0.0/16, mode: hash }          # HR network → stable pseudonyms
    - { cidr: 10.60.0.0/16, mode: truncate, bits: 24 }

normalize:
  sampling_overrides:
    - { exporter: 192.0.2.9, rate: 1000 }         # exporter samples 1:1000 but doesn't say so
```

## 5.4 Output fields

| Field | Example | Source |
|---|---|---|
| `src_endpoint.hostname` / `dst_endpoint.hostname` | `wks-0417.corp.example` | hostnames file, then DNS |
| `*.location.{country,city,region,continent,lat,long}` | `NL`, `Amsterdam` | GeoIP |
| `*.autonomous_system.{number,name}` | `64501`, `Example Hosting B.V.` | ASN DB / exporter |
| `src_endpoint.interface_name` / `dst_endpoint.interface_name` | `Gi0/0/3` / `Te0/1/0` | file / SNMP (input / output ifIndex) |
| `unmapped.flowtrim.{in,out}_if_description`, `*_speed_mbps` | `uplink-isp-a`, `10000` | file / SNMP |
| `dst_endpoint.svc_name` (or `src_endpoint` when the source is the server) | `https` | services |
| `app_name` | `Microsoft 365` | apps file |
| `unmapped.flowtrim.threat[]` + raised `severity_id` | `[{list: feodo, severity: high, side: dst}]` | threat lists |
| `connection_info.community_uid` | `1:LQU9qZlK+B5F3KDmev6m5PMibrg=` | Community ID |
| `unmapped.flowtrim.server` | `dst` | client/server inference |
| `unmapped.flowtrim.{src,dst}_meta` | `{site: dallas, zone: prod}` | metadata file |

## 5.5 Getting free data files

| Data | Free source | License note |
|---|---|---|
| Geo + ASN | DB-IP "IP to City Lite" / "IP to ASN Lite" (MMDB) | CC BY 4.0: attribution required |
| Geo + ASN in one file | IPinfo Lite (MMDB) | Check IPinfo's current terms |
| Geo + ASN | MaxMind GeoLite2 City / ASN | Free account and license key; EULA applies |
| Threat IPs | abuse.ch Feodo Tracker IP blocklist, FireHOL level 1 | Check each feed's terms |

FlowTrim ships **no** third-party databases. The demo uses tiny generated MMDBs that cover only documentation IP ranges (`tools/mkdemodb`).

## 5.6 Cost

The microbenchmark for the default modules (services, client/server, Community ID) is ≈ 2 µs per record. MMDB lookups add ≈ 1–2 µs per public IP. DNS and SNMP run in the background. With a 70% reduction at 100k flows/s, that's about 30k records/s, which fits comfortably in the parallel encoders.
