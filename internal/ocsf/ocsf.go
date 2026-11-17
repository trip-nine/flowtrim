// Package ocsf renders flows and reduction summaries as OCSF Network
// Activity (class_uid 4001) shaped JSON objects. FlowTrim-specific data lives
// under unmapped.flowtrim so standard OCSF consumers ignore it safely.
package ocsf

import (
	"net/netip"
	"strings"
	"time"

	"github.com/trip-nine/flowtrim/internal/flow"
)

// Version is the OCSF schema version the records are shaped after.
const Version = "1.3.0"

// Event is one record ready for the output.
type Event struct {
	Time time.Time
	Host string
	Kind string // raw | bypass | rollup | drop_summary | fanout_summary | shadow_report
	Body map[string]any
	// Shadow marks shadow-mode accounting: ShadowRaw = forwarded and counted
	// as raw; ShadowReduced = counted as "enforce would send", never forwarded.
	Shadow string
	// Flow carries the typed flow keys the enrichment stage needs (nil for
	// summary records).
	Flow *FlowMeta
}

// FlowMeta is the typed identity of a (possibly rolled-up) flow record.
type FlowMeta struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	SrcPortValid     bool // false when a rollup folded several source ports
	Proto            uint8
	ICMPType         uint8
	ICMPCode         uint8
	Exporter         netip.Addr
	InIf, OutIf      uint32
	SrcAS, DstAS     uint32
}

// Shadow accounting markers.
const (
	ShadowRaw     = "raw"
	ShadowReduced = "reduced"
)

// Reduction describes what FlowTrim did to produce a record.
type Reduction struct {
	Kind        string // none | bypass | rollup
	Rule        string
	FlowCount   uint64
	Exporters   []string
	SrcPorts    int // distinct src ports folded into a rollup (when src_port not in key)
	IAT         *IATStats
	RuleVersion string
	Shadow      bool
}

// IATStats are inter-arrival statistics (milliseconds) of flow start times
// inside a rollup; they preserve beaconing signal.
type IATStats struct {
	Samples int     `json:"samples"`
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
	Mean    float64 `json:"mean"`
	Stddev  float64 `json:"stddev"`
}

var product = map[string]any{"name": "FlowTrim", "vendor_name": "FlowTrim (open source)"}

func dirID(d string) (int, string) {
	switch d {
	case flow.DirInbound:
		return 1, "Inbound"
	case flow.DirOutbound:
		return 2, "Outbound"
	case flow.DirInternal:
		return 3, "Lateral"
	}
	return 0, "Unknown"
}

// FromFlow renders a single (possibly rolled-up) flow.
func FromFlow(f *flow.Flow, start, end time.Time, bytes, packets uint64, tcpFlags uint8, red Reduction) Event {
	if start.IsZero() {
		start = f.Received
	}
	if end.IsZero() {
		end = start
	}
	did, dname := dirID(f.Direction)
	conn := map[string]any{"protocol_num": f.Proto, "direction_id": did, "direction": dname}
	if n := flow.ProtoName(f.Proto); n != "" {
		conn["protocol_name"] = n
	}
	if f.Proto == 6 {
		conn["tcp_flags"] = tcpFlags
	}
	if f.Src.Is6() || f.Dst.Is6() {
		conn["protocol_ver_id"] = 6
	} else {
		conn["protocol_ver_id"] = 4
	}

	src := map[string]any{"ip": f.Src.String()}
	dst := map[string]any{"ip": f.Dst.String()}
	if f.Proto == 6 || f.Proto == 17 || f.Proto == 132 {
		dst["port"] = f.DstPort
		if red.Kind != "rollup" || red.SrcPorts <= 1 {
			src["port"] = f.SrcPort
		}
	}
	if f.SrcAS != 0 {
		src["autonomous_system"] = map[string]any{"number": f.SrcAS}
	}
	if f.DstAS != 0 {
		dst["autonomous_system"] = map[string]any{"number": f.DstAS}
	}
	if f.InIf != 0 {
		src["interface_uid"] = itoa(uint64(f.InIf))
	}
	if f.OutIf != 0 {
		dst["interface_uid"] = itoa(uint64(f.OutIf))
	}

	body := map[string]any{
		"class_uid":       4001,
		"class_name":      "Network Activity",
		"category_uid":    4,
		"category_name":   "Network Activity",
		"activity_id":     6,
		"activity_name":   "Traffic",
		"type_uid":        400106,
		"severity_id":     1,
		"time":            end.UnixMilli(),
		"start_time":      start.UnixMilli(),
		"end_time":        end.UnixMilli(),
		"src_endpoint":    src,
		"dst_endpoint":    dst,
		"connection_info": conn,
		"traffic":         map[string]any{"bytes": bytes, "packets": packets},
		"metadata": map[string]any{
			"version":  Version,
			"product":  product,
			"log_name": f.Source,
		},
	}
	if f.Exporter.IsValid() {
		body["device"] = map[string]any{"ip": f.Exporter.String()}
	}
	switch strings.ToUpper(f.Action) {
	case "ACCEPT", "ALLOW", "ALLOWED", "PERMIT":
		body["action_id"], body["action"] = 1, "Allowed"
		body["disposition_id"], body["disposition"] = 1, "Allowed"
	case "REJECT", "DENY", "DENIED", "DROP", "BLOCK", "BLOCKED":
		body["action_id"], body["action"] = 2, "Denied"
		body["disposition_id"], body["disposition"] = 2, "Blocked"
	}
	if red.FlowCount > 1 {
		body["count"] = red.FlowCount
	}
	if len(f.Cloud) > 0 {
		cloud := map[string]any{"provider": "AWS"}
		if v := f.Cloud["account_id"]; v != "" {
			cloud["account"] = map[string]any{"uid": v}
		}
		if v := f.Cloud["region"]; v != "" {
			cloud["region"] = v
		}
		body["cloud"] = cloud
	}

	ft := map[string]any{
		"reduction":    red.Kind,
		"flow_type":    f.Type,
		"rule_version": red.RuleVersion,
	}
	if red.Rule != "" {
		ft["rule"] = red.Rule
	}
	if f.SamplingRate > 1 {
		ft["sampling_rate"] = f.SamplingRate
		ft["sampling_scaled"] = f.Scaled
	}
	if red.FlowCount > 0 {
		ft["flow_count"] = red.FlowCount
	}
	if len(red.Exporters) > 1 {
		ft["exporters"] = red.Exporters
	}
	if red.SrcPorts > 1 {
		ft["distinct_src_ports"] = red.SrcPorts
	}
	if red.IAT != nil {
		ft["iat_ms"] = red.IAT
	}
	if f.Direction != "" {
		ft["direction"] = f.Direction
	}
	if f.LogStatus != "" {
		ft["log_status"] = f.LogStatus
	}
	if f.ICMPType != 0 || f.ICMPCode != 0 {
		ft["icmp"] = map[string]any{"type": f.ICMPType, "code": f.ICMPCode}
	}
	if f.VLAN != 0 {
		ft["vlan"] = f.VLAN
	}
	for k, v := range f.Cloud {
		if k == "account_id" || k == "region" {
			continue
		}
		ft[k] = v
	}
	if red.Shadow {
		ft["shadow"] = true
	}
	body["unmapped"] = map[string]any{"flowtrim": ft}

	kind := red.Kind
	if kind == "none" || kind == "" {
		kind = "raw"
	}
	meta := &FlowMeta{Src: f.Src, Dst: f.Dst, SrcPort: f.SrcPort, DstPort: f.DstPort,
		SrcPortValid: red.Kind != "rollup" || red.SrcPorts <= 1, Proto: f.Proto,
		ICMPType: f.ICMPType, ICMPCode: f.ICMPCode, Exporter: f.Exporter,
		InIf: f.InIf, OutIf: f.OutIf, SrcAS: f.SrcAS, DstAS: f.DstAS}
	return Event{Time: end, Host: f.HostLabel(), Kind: kind, Body: body, Flow: meta}
}

// Summary builds a FlowTrim summary record (drop_summary, fanout_summary,
// shadow_report). It is still class 4001 with activity "Other" so it lands
// next to the traffic it describes.
func Summary(kind string, now time.Time, host string, fields map[string]any, ruleVersion string) Event {
	fields["record_type"] = kind
	fields["rule_version"] = ruleVersion
	body := map[string]any{
		"class_uid":     4001,
		"class_name":    "Network Activity",
		"category_uid":  4,
		"category_name": "Network Activity",
		"activity_id":   99,
		"activity_name": kind,
		"type_uid":      400199,
		"severity_id":   1,
		"time":          now.UnixMilli(),
		"metadata":      map[string]any{"version": Version, "product": product, "log_name": "flowtrim"},
		"unmapped":      map[string]any{"flowtrim": fields},
	}
	if c, ok := fields["flows"].(uint64); ok && c > 0 {
		body["count"] = c
	}
	return Event{Time: now, Host: host, Kind: kind, Body: body}
}

// Prune removes dotted paths (e.g. "unmapped.flowtrim.icmp", "device") from a body.
func Prune(body map[string]any, paths [][]string) {
	for _, p := range paths {
		m := body
		for i, k := range p {
			if i == len(p)-1 {
				delete(m, k)
				break
			}
			next, ok := m[k].(map[string]any)
			if !ok {
				break
			}
			m = next
		}
	}
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
