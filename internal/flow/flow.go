// Package flow defines the normalized flow record every input produces and
// every reduction stage consumes. Inputs (NetFlow/IPFIX/sFlow via goflow2,
// AWS VPC Flow Logs via Firehose) all convert into this one shape, so rules
// are written once and apply to every source.
package flow

import (
	"net/netip"
	"time"
)

// Flow is one normalized flow record.
type Flow struct {
	Received time.Time // when FlowTrim received the export packet / request
	Start    time.Time // flow start as reported by the exporter (UTC)
	End      time.Time // flow end as reported by the exporter (UTC)

	Exporter netip.Addr // router/switch/probe that exported the flow (invalid for cloud sources)
	Source   string     // input name: netflow, sflow, aws_firehose

	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8

	Bytes, Packets uint64 // already scaled by SamplingRate when normalize.scale_by_sampling_rate is on
	SamplingRate   uint64 // 0/1 = unsampled
	Scaled         bool   // true when Bytes/Packets were multiplied by SamplingRate

	TCPFlags    uint8
	InIf, OutIf uint32
	SrcAS       uint32
	DstAS       uint32
	VLAN        uint16
	ICMPType    uint8
	ICMPCode    uint8
	Type        string // NETFLOW_V5, NETFLOW_V9, IPFIX, SFLOW_5, AWS_VPC

	Action    string // ACCEPT / REJECT (cloud flow logs, firewall exports)
	LogStatus string // OK / NODATA / SKIPDATA (AWS)

	Direction string // computed: internal | outbound | inbound | external

	// Cloud carries source-specific identifiers (account_id, interface_id,
	// vpc_id, subnet_id, instance_id, region, flow_direction, pkt_srcaddr, ...).
	Cloud map[string]string
}

// Direction values.
const (
	DirInternal = "internal"
	DirOutbound = "outbound"
	DirInbound  = "inbound"
	DirExternal = "external"
)

// HostLabel is the value placed in the HEC "host" field: the exporter IP for
// network devices, the interface/account for cloud sources.
func (f *Flow) HostLabel() string {
	if f.Exporter.IsValid() {
		return f.Exporter.String()
	}
	if f.Cloud != nil {
		if v := f.Cloud["interface_id"]; v != "" {
			return v
		}
		if v := f.Cloud["account_id"]; v != "" {
			return v
		}
	}
	return f.Source
}

// ProtoName returns a short protocol name for common IANA numbers.
func ProtoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 58:
		return "ipv6-icmp"
	case 132:
		return "sctp"
	}
	return ""
}

// ProtoNumber parses a protocol name; ok=false if unknown.
func ProtoNumber(name string) (uint8, bool) {
	switch name {
	case "icmp":
		return 1, true
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "gre":
		return 47, true
	case "esp":
		return 50, true
	case "ipv6-icmp", "icmpv6":
		return 58, true
	case "sctp":
		return 132, true
	}
	return 0, false
}
