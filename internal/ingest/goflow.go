// Package ingest turns wire formats into flow.Flow records.
package ingest

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"time"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/metrics"
	flowpb "github.com/netsampler/goflow2/v2/pb"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/utils"
	"github.com/netsampler/goflow2/v2/utils/debug"

	"github.com/tripnine/flowtrim/internal/config"
	"github.com/tripnine/flowtrim/internal/flow"
	"github.com/tripnine/flowtrim/internal/netset"
	"github.com/tripnine/flowtrim/internal/telemetry"
)

// Sink receives normalized flows (blocking send = backpressure).
type Sink func(*flow.Flow)

// UDP runs goflow2 receivers for NetFlow v5/v9/IPFIX or sFlow v5.
type UDP struct {
	name    string // netflow | sflow
	cfg     *config.UDPInput
	sink    Sink
	log     *slog.Logger
	allowed *netset.Set
	servers []*udpServer
	pipes   []utils.FlowPipe
}

// NewUDP builds a listener group.
func NewUDP(name string, cfg *config.UDPInput, sink Sink, log *slog.Logger) (*UDP, error) {
	u := &UDP{name: name, cfg: cfg, sink: sink, log: log.With("input", name)}
	if len(cfg.AllowedExporters) > 0 {
		s, err := netset.Parse(cfg.AllowedExporters)
		if err != nil {
			return nil, fmt.Errorf("inputs.%s.allowed_exporters: %w", name, err)
		}
		u.allowed = s
	}
	return u, nil
}

// formatter adapts goflow2's producer output to our Sink. goflow2 calls
// Format for each decoded record; we copy what we need (the message is
// pooled and reused after Commit) and return no bytes.
type formatter struct{ u *UDP }

func addr(b []byte) netip.Addr {
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}

func nsTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns)).UTC()
}

func (f formatter) Format(data interface{}) ([]byte, []byte, error) {
	m, ok := data.(*protoproducer.ProtoProducerMessage)
	if !ok {
		return nil, nil, errors.New("unexpected producer message")
	}
	fm := &m.FlowMessage
	fl := &flow.Flow{
		Received:     nsTime(fm.TimeReceivedNs),
		Start:        nsTime(fm.TimeFlowStartNs),
		End:          nsTime(fm.TimeFlowEndNs),
		Exporter:     addr(fm.SamplerAddress),
		Source:       f.u.name,
		Src:          addr(fm.SrcAddr),
		Dst:          addr(fm.DstAddr),
		SrcPort:      uint16(fm.SrcPort),
		DstPort:      uint16(fm.DstPort),
		Proto:        uint8(fm.Proto),
		Bytes:        fm.Bytes,
		Packets:      fm.Packets,
		SamplingRate: fm.SamplingRate,
		TCPFlags:     uint8(fm.TcpFlags),
		InIf:         fm.InIf,
		OutIf:        fm.OutIf,
		SrcAS:        fm.SrcAs,
		DstAS:        fm.DstAs,
		VLAN:         uint16(fm.VlanId),
		ICMPType:     uint8(fm.IcmpType),
		ICMPCode:     uint8(fm.IcmpCode),
		Type:         flowType(fm.Type),
	}
	if fl.Received.IsZero() {
		fl.Received = time.Now().UTC()
	}
	if f.u.allowed != nil && !f.u.allowed.Contains(fl.Exporter) {
		telemetry.FlowsRejected.WithLabelValues(f.u.name, "exporter_not_allowed").Inc()
		return nil, nil, nil
	}
	if !fl.Src.IsValid() || !fl.Dst.IsValid() {
		// non-IP samples (e.g. sFlow counter-only / L2) are not useful here
		telemetry.FlowsRejected.WithLabelValues(f.u.name, "no_ip").Inc()
		return nil, nil, nil
	}
	telemetry.FlowsReceived.WithLabelValues(f.u.name).Inc()
	f.u.sink(fl)
	return nil, nil, nil
}

func flowType(t flowpb.FlowMessage_FlowType) string {
	switch t {
	case flowpb.FlowMessage_NETFLOW_V5:
		return "NETFLOW_V5"
	case flowpb.FlowMessage_NETFLOW_V9:
		return "NETFLOW_V9"
	case flowpb.FlowMessage_IPFIX:
		return "IPFIX"
	case flowpb.FlowMessage_SFLOW_5:
		return "SFLOW_5"
	}
	return t.String()
}

// Start opens sockets and decode workers.
func (u *UDP) Start() error {
	pc := &protoproducer.ProducerConfig{}
	cfgm, err := pc.Compile()
	if err != nil {
		return err
	}
	prod, err := protoproducer.CreateProtoProducer(cfgm, protoproducer.CreateSamplingSystem)
	if err != nil {
		return err
	}
	sockets := u.cfg.Sockets
	if runtime.GOOS != "linux" {
		sockets = 1
	}
	for _, l := range u.cfg.Listen {
		pipeCfg := &utils.PipeConfig{Format: formatter{u}, Producer: prod, NetFlowTemplater: metrics.NewDefaultPromTemplateSystem}
		var p utils.FlowPipe
		if u.name == "sflow" {
			p = utils.NewSFlowPipe(pipeCfg)
		} else {
			p = utils.NewNetFlowPipe(pipeCfg)
		}
		dec := metrics.PromDecoderWrapper(debug.PanicDecoderWrapper(p.DecodeFlow), u.name)
		srv, err := listenUDP(u.name, l, sockets, u.cfg.Workers, u.cfg.QueueSize, int(u.cfg.RcvBuf),
			func(m *utils.Message) error { return dec(m) }, u.log)
		if err != nil {
			return fmt.Errorf("listen %s: %w", l, err)
		}
		u.servers = append(u.servers, srv)
		u.pipes = append(u.pipes, p)
		u.log.Info("listening", "addr", l, "sockets", sockets, "workers", u.cfg.Workers)
	}
	return nil
}

func isTemplateNotFound(err error) bool { return errors.Is(err, netflow.ErrorTemplateNotFound) }

// Stop closes sockets and drains decoders.
func (u *UDP) Stop() {
	for _, s := range u.servers {
		s.close()
	}
	for _, p := range u.pipes {
		p.Close()
	}
}
