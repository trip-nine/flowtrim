// Package enrich adds context to records after reduction: GeoIP/ASN,
// reverse DNS, user-defined hostnames and metadata, interface names
// (file or SNMP), service and SaaS application names, threat-list tags,
// Community ID, client/server roles, and IP pseudonymization.
//
// It runs in the output's encoder workers (in parallel) and only on the
// reduced stream, so enrichment cost scales with what is sent, not with
// what is received.
package enrich

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/trip-nine/flowtrim/internal/config"
	"github.com/trip-nine/flowtrim/internal/netset"
	"github.com/trip-nine/flowtrim/internal/ocsf"
)

// Hooks report enrichment results to metrics without a Prometheus dependency.
type Hooks struct {
	Lookup func(kind, result string) // e.g. ("geoip","hit"), ("dns","miss"), ("snmp","ok")
}

// Enricher is safe for concurrent use.
type Enricher struct {
	internal   *netset.Set
	scopeExcl  *netset.Set
	geo        *geoDB
	geoSkipInt bool
	dns        *dnsCache
	hostnames  map[netip.Addr]string
	meta       *prefixTable[map[string]string]
	ifFile     ifTable
	snmp       *snmpPoller
	services   map[string]string
	svcOn      bool
	apps       *prefixTable[string]
	threats    []threatList
	cidOn      bool
	cidSeed    uint16
	csOn       bool
	priv       []privRule
	privKey    []byte
	hooks      Hooks
	active     bool
}

type privRule struct {
	set  *netset.Set
	hash bool
	bits int
}

// New builds an Enricher. baseDir resolves relative file paths.
func New(cfg *config.Config, baseDir string, log *slog.Logger, hooks Hooks) (*Enricher, error) {
	if hooks.Lookup == nil {
		hooks.Lookup = func(string, string) {}
	}
	ec := cfg.Enrich
	e := &Enricher{hooks: hooks, svcOn: *ec.Apps.Services, cidOn: *ec.CommunityID.Enabled, cidSeed: ec.CommunityID.Seed, csOn: *ec.ClientServer}
	var err error
	if e.internal, err = netset.Parse(cfg.Networks.Internal); err != nil {
		return nil, err
	}
	if e.scopeExcl, err = netset.Parse(ec.Scope.ExcludeCIDRs); err != nil {
		return nil, fmt.Errorf("enrich.scope.exclude_cidrs: %w", err)
	}
	if ec.GeoIP.CityDB != "" || ec.GeoIP.ASNDB != "" {
		if e.geo, err = openGeo(resolve(baseDir, ec.GeoIP.CityDB), resolve(baseDir, ec.GeoIP.ASNDB)); err != nil {
			return nil, err
		}
		e.geoSkipInt = *ec.GeoIP.SkipInternal
	}
	if ec.DNS.Enabled {
		if e.dns, err = newDNS(ec.DNS, e.internal, func(r string) { hooks.Lookup("dns", r) }); err != nil {
			return nil, fmt.Errorf("enrich.dns: %w", err)
		}
	}
	if ec.HostnamesFile != "" {
		if e.hostnames, err = loadHostnames(resolve(baseDir, ec.HostnamesFile)); err != nil {
			return nil, fmt.Errorf("enrich.hostnames_file: %w", err)
		}
	}
	if ec.MetadataFile != "" {
		if e.meta, err = loadMetadata(resolve(baseDir, ec.MetadataFile)); err != nil {
			return nil, fmt.Errorf("enrich.metadata_file: %w", err)
		}
	}
	if ec.Interfaces.File != "" {
		if e.ifFile, err = loadInterfaces(resolve(baseDir, ec.Interfaces.File)); err != nil {
			return nil, fmt.Errorf("enrich.interfaces.file: %w", err)
		}
	}
	if ec.Interfaces.SNMP.Enabled {
		if e.snmp, err = newSNMP(ec.Interfaces.SNMP, log, func(r string) { hooks.Lookup("snmp", r) }); err != nil {
			return nil, err
		}
	}
	e.services = map[string]string{}
	if e.svcOn {
		for k, v := range builtinServices {
			e.services[k] = v
		}
	}
	if ec.Apps.ServicesFile != "" {
		user, err := loadServices(resolve(baseDir, ec.Apps.ServicesFile))
		if err != nil {
			return nil, fmt.Errorf("enrich.apps.services_file: %w", err)
		}
		for k, v := range user {
			e.services[k] = v
		}
		e.svcOn = true
	}
	if ec.Apps.AppsFile != "" {
		if e.apps, err = loadApps(resolve(baseDir, ec.Apps.AppsFile)); err != nil {
			return nil, fmt.Errorf("enrich.apps.apps_file: %w", err)
		}
	}
	for _, t := range ec.Threat {
		s, err := netset.LoadFile(resolve(baseDir, t.File))
		if err != nil {
			return nil, fmt.Errorf("enrich.threat_lists %s: %w", t.Name, err)
		}
		sev := t.Severity
		if sev == "" {
			sev = "medium"
		}
		e.threats = append(e.threats, threatList{name: t.Name, severity: sev, set: s})
	}
	e.privKey = []byte(cfg.Privacy.Key)
	for _, p := range cfg.Privacy.Pseudonymize {
		s, err := netset.Parse([]string{p.CIDR})
		if err != nil {
			return nil, fmt.Errorf("privacy.pseudonymize: %w", err)
		}
		e.priv = append(e.priv, privRule{set: s, hash: p.Mode == "hash", bits: p.Bits})
	}
	e.active = e.geo != nil || e.dns != nil || e.hostnames != nil || e.meta != nil || e.ifFile != nil || e.snmp != nil ||
		e.svcOn || e.apps != nil || len(e.threats) > 0 || e.cidOn || e.csOn || len(e.priv) > 0
	return e, nil
}

// Active reports whether any enrichment is configured.
func (e *Enricher) Active() bool { return e != nil && e.active }

// Close stops background workers.
func (e *Enricher) Close() {
	if e == nil {
		return
	}
	if e.dns != nil {
		e.dns.close()
	}
	if e.snmp != nil {
		e.snmp.close()
	}
	if e.geo != nil {
		e.geo.close()
	}
}

var severityID = map[string]int{"low": 2, "medium": 3, "high": 4, "critical": 5}

func sub(m map[string]any, k string) map[string]any {
	v, ok := m[k].(map[string]any)
	if !ok {
		v = map[string]any{}
		m[k] = v
	}
	return v
}

func flowtrimMap(body map[string]any) map[string]any {
	return sub(sub(body, "unmapped"), "flowtrim")
}

// Apply enriches one record in place.
func (e *Enricher) Apply(ev *ocsf.Event) {
	if !e.Active() {
		return
	}
	if ev.Flow == nil {
		// summary records: only pseudonymize the source they describe
		if len(e.priv) > 0 {
			if src, ok := ev.Body["src_endpoint"].(map[string]any); ok {
				if s, ok := src["ip"].(string); ok {
					if a, err := netip.ParseAddr(s); err == nil {
						src["ip"] = e.pseudo(a)
					}
				}
			}
			if ft := flowtrimMap(ev.Body); ft["src_ip"] != nil {
				if a, err := netip.ParseAddr(fmt.Sprint(ft["src_ip"])); err == nil {
					ft["src_ip"] = e.pseudo(a)
				}
			}
		}
		return
	}
	f := ev.Flow
	src, dst := sub(ev.Body, "src_endpoint"), sub(ev.Body, "dst_endpoint")
	ft := flowtrimMap(ev.Body)

	if e.snmp != nil {
		e.snmp.observe(f.Exporter)
	}
	e.endpoint(src, f.Src, ft, "src")
	e.endpoint(dst, f.Dst, ft, "dst")

	// interfaces: input on src side, output on dst side
	if n, ok := e.iface(f.Exporter, f.InIf); ok {
		src["interface_name"] = n.Name
		if n.Description != "" {
			ft["in_if_description"] = n.Description
		}
		if n.SpeedMbps > 0 {
			ft["in_if_speed_mbps"] = n.SpeedMbps
		}
	}
	if n, ok := e.iface(f.Exporter, f.OutIf); ok {
		dst["interface_name"] = n.Name
		if n.Description != "" {
			ft["out_if_description"] = n.Description
		}
		if n.SpeedMbps > 0 {
			ft["out_if_speed_mbps"] = n.SpeedMbps
		}
	}

	// services and client/server roles
	if e.svcOn || e.csOn {
		side := serverSide(e.services, f.Proto, f.SrcPort, f.DstPort, f.SrcPortValid)
		if e.csOn && side != "" {
			ft["server"] = side
		}
		if e.svcOn {
			if side == "src" {
				if s, ok := e.services[protoKey(f.Proto, f.SrcPort)]; ok {
					src["svc_name"] = s
				}
			} else if s, ok := e.services[protoKey(f.Proto, f.DstPort)]; ok {
				dst["svc_name"] = s
			}
		}
	}
	// SaaS / business applications by destination (then source) CIDR
	if e.apps != nil {
		if n, ok := e.apps.lookup(f.Dst); ok {
			ev.Body["app_name"] = n
		} else if n, ok := e.apps.lookup(f.Src); ok {
			ev.Body["app_name"] = n
		}
	}
	// threat lists: tag, raise severity
	if len(e.threats) > 0 {
		var hits []map[string]any
		maxSev := 0
		for _, t := range e.threats {
			for side, a := range map[string]netip.Addr{"src": f.Src, "dst": f.Dst} {
				if t.set.Contains(a) {
					hits = append(hits, map[string]any{"list": t.name, "severity": t.severity, "side": side, "ip": a.String()})
					if s := severityID[t.severity]; s > maxSev {
						maxSev = s
					}
				}
			}
		}
		if len(hits) > 0 {
			ft["threat"] = hits
			e.hooks.Lookup("threat", "hit")
			if cur, _ := ev.Body["severity_id"].(int); maxSev > cur {
				ev.Body["severity_id"] = maxSev
			}
		}
	}
	if e.cidOn && f.SrcPortValid {
		if id, ok := CommunityID(e.cidSeed, f.Src, f.Dst, f.SrcPort, f.DstPort, f.Proto, f.ICMPType, f.ICMPCode); ok {
			sub(ev.Body, "connection_info")["community_uid"] = id
		}
	}
	// privacy last, so every lookup above used the real address
	if len(e.priv) > 0 {
		for _, ep := range []struct {
			m map[string]any
			a netip.Addr
		}{{src, f.Src}, {dst, f.Dst}} {
			if p := e.pseudo(ep.a); p != ep.a.String() {
				ep.m["ip"] = p
				delete(ep.m, "hostname")
			}
		}
	}
}

func (e *Enricher) endpoint(ep map[string]any, a netip.Addr, ft map[string]any, side string) {
	if !a.IsValid() || a.IsUnspecified() {
		return
	}
	internal := e.internal.Contains(a)
	if h, ok := e.hostnames[a]; ok {
		ep["hostname"] = h
	} else if e.dns != nil {
		if h := e.dns.Get(a); h != "" {
			ep["hostname"] = h
		}
	}
	if e.scopeExcl.Contains(a) {
		return
	}
	if e.meta != nil {
		if tags, ok := e.meta.lookup(a); ok && len(tags) > 0 {
			ft[side+"_meta"] = tags
		}
	}
	if e.geo != nil && !(e.geoSkipInt && internal) && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
		if g, ok := e.geo.lookup(a); ok {
			e.hooks.Lookup("geoip", "hit")
			if g.Country != "" {
				loc := map[string]any{"country": g.Country}
				if g.City != "" {
					loc["city"] = g.City
				}
				if g.Region != "" {
					loc["region"] = g.Region
				}
				if g.Continent != "" {
					loc["continent"] = g.Continent
				}
				if g.HasCoords {
					loc["lat"], loc["long"] = g.Lat, g.Lon
				}
				ep["location"] = loc
			}
			if g.ASN != 0 {
				as := sub(ep, "autonomous_system")
				if _, has := as["number"]; !has {
					as["number"] = g.ASN
				}
				if g.ASOrg != "" {
					as["name"] = g.ASOrg
				}
			}
		} else {
			e.hooks.Lookup("geoip", "miss")
		}
	}
}

func (e *Enricher) iface(exp netip.Addr, idx uint32) (Iface, bool) {
	if idx == 0 || !exp.IsValid() {
		return Iface{}, false
	}
	if m, ok := e.ifFile[exp]; ok { // user-defined wins
		if i, ok := m[idx]; ok && i.Name != "" {
			return i, true
		}
	}
	if e.snmp != nil {
		if i, ok := e.snmp.get(exp, idx); ok && i.Name != "" {
			return i, true
		}
	}
	return Iface{}, false
}

// pseudo returns the address to publish for a.
func (e *Enricher) pseudo(a netip.Addr) string {
	for _, r := range e.priv {
		if !r.set.Contains(a) {
			continue
		}
		if !r.hash {
			bits := r.bits
			if bits == 0 {
				bits = 24
				if a.Is6() {
					bits = 48
				}
			}
			p, err := a.Prefix(bits)
			if err == nil {
				return p.Addr().String()
			}
			return a.String()
		}
		// keyed hash into the same family, stable per key: same IP -> same pseudonym
		m := hmac.New(sha256.New, e.privKey)
		m.Write(a.AsSlice())
		sum := m.Sum(nil)
		if a.Is4() {
			// 240.0.0.0/4 (reserved) so pseudonyms can never collide with real hosts
			v := binary.BigEndian.Uint32(sum[:4])&0x0fffffff | 0xf0000000
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], v)
			return netip.AddrFrom4(b).String()
		}
		var b [16]byte
		copy(b[:], sum[:16])
		b[0], b[1] = 0xfd, 0x00 // fd00::/8 unique-local range, flagged as pseudonymous
		return netip.AddrFrom16(b).String()
	}
	return a.String()
}
