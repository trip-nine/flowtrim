package enrich

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/trip-nine/flowtrim/internal/config"
)

// IF-MIB columns.
const (
	oidIfDescr     = ".1.3.6.1.2.1.2.2.1.2"
	oidIfName      = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfAlias     = ".1.3.6.1.2.1.31.1.1.1.18"
	oidIfHighSpeed = ".1.3.6.1.2.1.31.1.1.1.15"
)

// Iface describes one interface on one exporter.
type Iface struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	SpeedMbps   uint64 `yaml:"speed_mbps"`
}

type ifTable map[netip.Addr]map[uint32]Iface

// snmpPoller walks IF-MIB on exporters and publishes an immutable snapshot.
type snmpPoller struct {
	cfg      config.SNMP
	log      *slog.Logger
	snap     atomic.Pointer[ifTable]
	mu       sync.Mutex
	seen     map[netip.Addr]time.Time // exporter -> last poll
	fixed    []netip.Addr
	auto     bool
	done     chan struct{}
	wg       sync.WaitGroup
	onResult func(result string)
}

func newSNMP(c config.SNMP, log *slog.Logger, onResult func(string)) (*snmpPoller, error) {
	p := &snmpPoller{cfg: c, log: log.With("component", "snmp"), seen: map[netip.Addr]time.Time{}, done: make(chan struct{}), onResult: onResult}
	for _, e := range c.Exporters {
		a, err := netip.ParseAddr(strings.TrimSpace(e))
		if err != nil {
			return nil, fmt.Errorf("enrich.interfaces.snmp.exporters: %w", err)
		}
		p.fixed = append(p.fixed, a)
	}
	p.auto = len(p.fixed) == 0
	empty := ifTable{}
	p.snap.Store(&empty)
	p.wg.Add(1)
	go p.loop()
	return p, nil
}

// observe registers an exporter for polling (auto mode).
func (p *snmpPoller) observe(a netip.Addr) {
	if !p.auto || !a.IsValid() {
		return
	}
	p.mu.Lock()
	if _, ok := p.seen[a]; !ok {
		p.seen[a] = time.Time{} // poll on next tick
	}
	p.mu.Unlock()
}

func (p *snmpPoller) get(exp netip.Addr, idx uint32) (Iface, bool) {
	t := *p.snap.Load()
	m, ok := t[exp]
	if !ok {
		return Iface{}, false
	}
	i, ok := m[idx]
	return i, ok
}

func (p *snmpPoller) loop() {
	defer p.wg.Done()
	for _, a := range p.fixed {
		p.seen[a] = time.Time{}
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case now := <-t.C:
			p.mu.Lock()
			var due []netip.Addr
			for a, last := range p.seen {
				if now.Sub(last) >= p.cfg.Interval.D() {
					due = append(due, a)
					p.seen[a] = now
				}
			}
			p.mu.Unlock()
			for _, a := range due {
				m, err := p.poll(a)
				if err != nil {
					p.log.Warn("SNMP poll failed", "exporter", a, "err", err)
					if p.onResult != nil {
						p.onResult("error")
					}
					continue
				}
				if p.onResult != nil {
					p.onResult("ok")
				}
				old := *p.snap.Load()
				next := make(ifTable, len(old)+1)
				for k, v := range old {
					next[k] = v
				}
				next[a] = m
				p.snap.Store(&next)
				p.log.Info("SNMP interfaces learned", "exporter", a, "interfaces", len(m))
			}
		}
	}
}

func (p *snmpPoller) client(a netip.Addr) *gosnmp.GoSNMP {
	g := &gosnmp.GoSNMP{
		Target: a.String(), Port: uint16(p.cfg.Port), Timeout: p.cfg.Timeout.D(),
		Retries: p.cfg.Retries, MaxOids: gosnmp.MaxOids, MaxRepetitions: 25,
	}
	if p.cfg.Version == "3" {
		v3 := p.cfg.V3
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		switch strings.ToLower(v3.Level) {
		case "noauthnopriv":
			g.MsgFlags = gosnmp.NoAuthNoPriv
		case "authnopriv":
			g.MsgFlags = gosnmp.AuthNoPriv
		}
		usm := &gosnmp.UsmSecurityParameters{UserName: v3.User, AuthenticationPassphrase: v3.AuthPass, PrivacyPassphrase: v3.PrivPass}
		switch strings.ToUpper(v3.AuthProto) {
		case "MD5":
			usm.AuthenticationProtocol = gosnmp.MD5
		case "SHA256":
			usm.AuthenticationProtocol = gosnmp.SHA256
		case "SHA512":
			usm.AuthenticationProtocol = gosnmp.SHA512
		default:
			usm.AuthenticationProtocol = gosnmp.SHA
		}
		switch strings.ToUpper(v3.PrivProto) {
		case "DES":
			usm.PrivacyProtocol = gosnmp.DES
		case "AES256":
			usm.PrivacyProtocol = gosnmp.AES256
		default:
			usm.PrivacyProtocol = gosnmp.AES
		}
		g.SecurityParameters = usm
	} else {
		g.Version = gosnmp.Version2c
		g.Community = p.cfg.Community
	}
	return g
}

func (p *snmpPoller) poll(a netip.Addr) (map[uint32]Iface, error) {
	g := p.client(a)
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	out := map[uint32]Iface{}
	set := func(oid string, f func(*Iface, gosnmp.SnmpPDU)) error {
		return g.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
			i := strings.LastIndexByte(pdu.Name, '.')
			idx, err := strconv.ParseUint(pdu.Name[i+1:], 10, 32)
			if err != nil {
				return nil
			}
			x := out[uint32(idx)]
			f(&x, pdu)
			out[uint32(idx)] = x
			return nil
		})
	}
	str := func(pdu gosnmp.SnmpPDU) string {
		if b, ok := pdu.Value.([]byte); ok {
			return strings.TrimSpace(string(b))
		}
		return ""
	}
	if err := set(oidIfName, func(x *Iface, pdu gosnmp.SnmpPDU) { x.Name = str(pdu) }); err != nil {
		return nil, err
	}
	_ = set(oidIfDescr, func(x *Iface, pdu gosnmp.SnmpPDU) {
		if x.Name == "" {
			x.Name = str(pdu)
		}
	})
	_ = set(oidIfAlias, func(x *Iface, pdu gosnmp.SnmpPDU) { x.Description = str(pdu) })
	_ = set(oidIfHighSpeed, func(x *Iface, pdu gosnmp.SnmpPDU) {
		x.SpeedMbps = gosnmp.ToBigInt(pdu.Value).Uint64()
	})
	if len(out) == 0 {
		return nil, fmt.Errorf("no IF-MIB data returned")
	}
	return out, nil
}

func (p *snmpPoller) close() {
	close(p.done)
	p.wg.Wait()
}
