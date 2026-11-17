package enrich

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/trip-nine/flowtrim/internal/config"
	"github.com/trip-nine/flowtrim/internal/ocsf"
)

// Reference values computed with the Python `communityid` package (the
// spec's reference implementation); the first two are the spec's own
// published baseline vectors.
func TestCommunityIDMatchesReference(t *testing.T) {
	ip := netip.MustParseAddr
	cases := []struct {
		src, dst     string
		sport, dport uint16
		proto        uint8
		it, ic       uint8
		seed         uint16
		want         string
	}{
		{"128.232.110.120", "66.35.250.204", 34855, 80, 6, 0, 0, 0, "1:LQU9qZlK+B5F3KDmev6m5PMibrg="},
		{"192.168.1.52", "8.8.8.8", 54585, 53, 17, 0, 0, 0, "1:d/FP5EW3wiY1vCndhwleRRKHowQ="},
		{"10.0.0.9", "10.0.0.1", 443, 50000, 6, 0, 0, 0, "1:80r1huzxqss6ulKNNxRgmxK6DQk="},
		{"2001:db8::1", "2001:db8::2", 1234, 443, 6, 0, 0, 0, "1:2h29Psz1danTKrAdwKC8Zw31l2Y="},
		{"192.168.170.8", "192.168.170.56", 7, 80, 132, 0, 0, 0, "1:jQgCxbku+pNGw8WPbEc/TS/uTpQ="},
		{"192.168.0.89", "192.168.0.1", 0, 0, 1, 8, 0, 0, "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="},
		{"192.168.0.89", "192.168.0.1", 0, 0, 1, 0, 0, 0, "1:Xd3I0IiB3MnC0cDe3fbqH8+dDGI="},
		{"192.168.0.89", "192.168.0.1", 0, 0, 1, 3, 1, 0, "1:LXCfhMUFbYXe+CEMrQuZCbiLY3o="},
		{"fe80::1", "fe80::2", 0, 0, 58, 128, 0, 0, "1:3H+V/JVcqh/phPel5utt4dOKqOU="},
		{"10.0.0.1", "10.0.0.2", 0, 0, 47, 0, 0, 0, "1:+KlEHDT0vJgzs/eNmzHq0aSpRYw="},
		{"128.232.110.120", "66.35.250.204", 34855, 80, 6, 0, 0, 5, "1:1L+GyryBoud+u40VsoW7gojkTJI="},
	}
	for _, c := range cases {
		got, ok := CommunityID(c.seed, ip(c.src), ip(c.dst), c.sport, c.dport, c.proto, c.it, c.ic)
		if !ok || got != c.want {
			t.Errorf("%s->%s p%d: got %s want %s", c.src, c.dst, c.proto, got, c.want)
		}
		// direction-independent for two-way protocols
		if c.proto == 6 || c.proto == 17 {
			rev, _ := CommunityID(c.seed, ip(c.dst), ip(c.src), c.dport, c.sport, c.proto, 0, 0)
			if rev != got {
				t.Errorf("reverse direction differs: %s vs %s", rev, got)
			}
		}
	}
}

func TestServerSide(t *testing.T) {
	svc := builtinServices
	for _, c := range []struct {
		sport, dport uint16
		valid        bool
		want         string
	}{
		{51000, 443, true, "dst"}, {443, 51000, true, "src"}, {51000, 52000, true, ""},
		{51000, 3389, true, "dst"}, {0, 8443, false, "dst"}, {1023, 60000, true, "src"},
	} {
		if got := serverSide(svc, 6, c.sport, c.dport, c.valid); got != c.want {
			t.Errorf("%d->%d: got %q want %q", c.sport, c.dport, got, c.want)
		}
	}
}

// writeMMDB builds a tiny MMDB in either MaxMind or IPinfo-Lite shape.
func writeMMDB(t *testing.T, path, dbType string, nets map[string]mmdbtype.Map) {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 28, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, rec := range nets {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
}

func cfgFor(t *testing.T, dir, y string) *config.Config {
	t.Helper()
	full := "inputs: {netflow: {listen: ['127.0.0.1:0']}}\noutput: {stdout: true}\n" + y
	c, err := config.Parse([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func flowEv(src, dst string, sport, dport uint16, proto uint8) ocsf.Event {
	body := map[string]any{"src_endpoint": map[string]any{"ip": src}, "dst_endpoint": map[string]any{"ip": dst}, "severity_id": 1,
		"connection_info": map[string]any{}, "unmapped": map[string]any{"flowtrim": map[string]any{}}}
	return ocsf.Event{Body: body, Flow: &ocsf.FlowMeta{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), SrcPort: sport, DstPort: dport,
		SrcPortValid: true, Proto: proto, Exporter: netip.MustParseAddr("192.0.2.1"), InIf: 3, OutIf: 7}}
}

func ep(ev ocsf.Event, side string) map[string]any { return ev.Body[side+"_endpoint"].(map[string]any) }
func ft(ev ocsf.Event) map[string]any {
	return ev.Body["unmapped"].(map[string]any)["flowtrim"].(map[string]any)
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestGeoIPBothSchemasAndFiles(t *testing.T) {
	dir := t.TempDir()
	writeMMDB(t, filepath.Join(dir, "city.mmdb"), "GeoLite2-City", map[string]mmdbtype.Map{
		"93.184.216.0/24": {
			"country":   mmdbtype.Map{"iso_code": mmdbtype.String("US"), "names": mmdbtype.Map{"en": mmdbtype.String("United States")}},
			"city":      mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Norwell")}},
			"continent": mmdbtype.Map{"code": mmdbtype.String("NA")},
			"location":  mmdbtype.Map{"latitude": mmdbtype.Float64(42.15), "longitude": mmdbtype.Float64(-70.82)},
		},
	})
	writeMMDB(t, filepath.Join(dir, "asn.mmdb"), "GeoLite2-ASN", map[string]mmdbtype.Map{
		"93.184.216.0/24": {"autonomous_system_number": mmdbtype.Uint32(15133), "autonomous_system_organization": mmdbtype.String("EDGECAST")},
	})
	writeMMDB(t, filepath.Join(dir, "ipinfo.mmdb"), "ipinfo lite", map[string]mmdbtype.Map{
		"203.0.113.0/24": {"country_code": mmdbtype.String("DE"), "continent_code": mmdbtype.String("EU"), "asn": mmdbtype.String("AS64500"), "as_name": mmdbtype.String("Example GmbH")},
	})
	_ = os.WriteFile(filepath.Join(dir, "hosts.yaml"), []byte("10.1.1.1: build-01.corp\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "meta.yaml"), []byte("- cidr: 10.1.0.0/16\n  tags: {site: dallas, zone: prod}\n- cidr: 10.1.1.0/24\n  tags: {site: dallas, zone: build}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "ifaces.yaml"), []byte("192.0.2.1:\n  3: {name: Gi0/0/3, description: uplink-isp-a, speed_mbps: 10000}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "apps.yaml"), []byte("Example CDN: [93.184.216.0/24]\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "bad.txt"), []byte("203.0.113.9\n"), 0o644)

	c := cfgFor(t, dir, `
enrich:
  geoip: { city_db: city.mmdb, asn_db: asn.mmdb }
  hostnames_file: hosts.yaml
  metadata_file: meta.yaml
  interfaces: { file: ifaces.yaml }
  apps: { apps_file: apps.yaml }
  threat_lists: [ { name: test-feed, file: bad.txt, severity: high } ]
`)
	e, err := New(c, dir, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ev := flowEv("10.1.1.1", "93.184.216.34", 51000, 443, 6)
	e.Apply(&ev)
	src, dst := ep(ev, "src"), ep(ev, "dst")
	if src["hostname"] != "build-01.corp" {
		t.Errorf("hostname: %v", src["hostname"])
	}
	loc := dst["location"].(map[string]any)
	if loc["country"] != "US" || loc["city"] != "Norwell" || loc["continent"] != "NA" || loc["lat"] != 42.15 {
		t.Errorf("geo: %v", loc)
	}
	as := dst["autonomous_system"].(map[string]any)
	if as["number"] != uint32(15133) || as["name"] != "EDGECAST" {
		t.Errorf("asn: %v", as)
	}
	if _, has := src["location"]; has {
		t.Error("internal IPs must not be geo-located")
	}
	if m := ft(ev)["src_meta"].(map[string]string); m["zone"] != "build" {
		t.Errorf("longest-prefix metadata: %v", m)
	}
	if src["interface_name"] != "Gi0/0/3" || ft(ev)["in_if_description"] != "uplink-isp-a" {
		t.Errorf("interface: %v %v", src["interface_name"], ft(ev)["in_if_description"])
	}
	if dst["svc_name"] != "https" || ft(ev)["server"] != "dst" {
		t.Errorf("service: %v server=%v", dst["svc_name"], ft(ev)["server"])
	}
	if ev.Body["app_name"] != "Example CDN" {
		t.Errorf("app: %v", ev.Body["app_name"])
	}
	if !strings.HasPrefix(ev.Body["connection_info"].(map[string]any)["community_uid"].(string), "1:") {
		t.Error("community id missing")
	}

	// IPinfo Lite flat schema in a single file + threat tag
	c2 := cfgFor(t, dir, "enrich:\n  geoip: { city_db: ipinfo.mmdb }\n  threat_lists: [ { name: test-feed, file: bad.txt, severity: high } ]\n")
	e2, err := New(c2, dir, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	ev2 := flowEv("10.1.1.1", "203.0.113.9", 51000, 8443, 6)
	e2.Apply(&ev2)
	d2 := ep(ev2, "dst")
	if d2["location"].(map[string]any)["country"] != "DE" || d2["autonomous_system"].(map[string]any)["number"] != uint32(64500) ||
		d2["autonomous_system"].(map[string]any)["name"] != "Example GmbH" {
		t.Errorf("ipinfo schema: %v", d2)
	}
	if ev2.Body["severity_id"] != 4 || len(ft(ev2)["threat"].([]map[string]any)) != 1 {
		t.Errorf("threat tagging: sev=%v %v", ev2.Body["severity_id"], ft(ev2)["threat"])
	}
}

func TestPseudonymize(t *testing.T) {
	c := cfgFor(t, "", `
enrich: { community_id: { enabled: false } }
privacy:
  key: "0123456789abcdef-test-key"
  pseudonymize:
    - { cidr: 10.20.0.0/16, mode: hash }
    - { cidr: 10.30.0.0/16, mode: truncate, bits: 24 }
`)
	e, err := New(c, "", quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	a := flowEv("10.20.5.5", "10.30.7.9", 1, 2, 6)
	b := flowEv("10.20.5.5", "8.8.8.8", 1, 2, 6)
	e.Apply(&a)
	e.Apply(&b)
	pa, pb := ep(a, "src")["ip"].(string), ep(b, "src")["ip"].(string)
	if pa == "10.20.5.5" || pa != pb || !strings.HasPrefix(pa, "24") && !strings.HasPrefix(pa, "25") {
		t.Errorf("hash pseudonym must be stable, in 240/4: %s %s", pa, pb)
	}
	if ep(a, "dst")["ip"] != "10.30.7.0" {
		t.Errorf("truncate: %v", ep(a, "dst")["ip"])
	}
	if ep(b, "dst")["ip"] != "8.8.8.8" {
		t.Error("out-of-scope IPs must be untouched")
	}
}

// fakeDNS answers every PTR query with name.
func fakeDNS(t *testing.T, name string, delay time.Duration) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			time.Sleep(delay)
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
			b.EnableCompression()
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			_ = b.PTRResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(name + ".")})
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestReverseDNSIsAsync(t *testing.T) {
	ns := fakeDNS(t, "fileserver.corp", 200*time.Millisecond)
	c := cfgFor(t, "", "enrich:\n  dns: { enabled: true, nameserver: \""+ns+"\", timeout: 2s }\n")
	hits := make(chan string, 4)
	e, err := New(c, "", quiet, Hooks{Lookup: func(k, r string) {
		if k == "dns" {
			hits <- r
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	start := time.Now()
	ev := flowEv("10.1.1.50", "93.184.216.34", 51000, 443, 6)
	e.Apply(&ev)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("a cache miss must not block the pipeline")
	}
	if _, has := ep(ev, "src")["hostname"]; has {
		t.Fatal("first sighting should not have a name yet")
	}
	select {
	case r := <-hits:
		if r != "hit" {
			t.Fatalf("lookup result %s", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lookup never completed")
	}
	ev2 := flowEv("10.1.1.50", "93.184.216.34", 51001, 443, 6)
	e.Apply(&ev2)
	if ep(ev2, "src")["hostname"] != "fileserver.corp" {
		t.Fatalf("cached name: %v", ep(ev2, "src")["hostname"])
	}
	// public dst is out of scope by default (include = internal)
	if _, has := ep(ev2, "dst")["hostname"]; has {
		t.Fatal("external IPs are not resolved unless included")
	}
}

func BenchmarkApplyTypical(b *testing.B) {
	c, _ := config.Parse([]byte("inputs: {netflow: {listen: ['127.0.0.1:0']}}\noutput: {stdout: true}\n"))
	e, _ := New(c, "", quiet, Hooks{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := flowEv("10.1.1.1", "93.184.216.34", 51000, 443, 6)
		e.Apply(&ev)
	}
}
