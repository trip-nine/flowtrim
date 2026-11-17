package enrich

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// geoDB reads MMDB files. It understands the MaxMind GeoIP2/GeoLite2 and
// DB-IP schemas (nested country/city/location objects) and the IPinfo Lite
// flat schema (country_code, continent_code, asn, as_name).
type geoDB struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// Geo is one lookup result.
type Geo struct {
	Country   string
	CountryNm string
	Continent string
	Region    string
	City      string
	Lat, Lon  float64
	HasCoords bool
	ASN       uint32
	ASOrg     string
}

func openGeo(cityPath, asnPath string) (*geoDB, error) {
	g := &geoDB{}
	var err error
	if cityPath != "" {
		if g.city, err = maxminddb.Open(cityPath); err != nil {
			return nil, fmt.Errorf("enrich.geoip.city_db: %w", err)
		}
	}
	if asnPath != "" {
		if g.asn, err = maxminddb.Open(asnPath); err != nil {
			return nil, fmt.Errorf("enrich.geoip.asn_db: %w", err)
		}
	}
	return g, nil
}

func parseASN(s string) uint32 {
	s = strings.TrimPrefix(strings.ToUpper(s), "AS")
	n, _ := strconv.ParseUint(s, 10, 32)
	return uint32(n)
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	if v, ok := cur.(string); ok {
		return v
	}
	return ""
}

func num(m map[string]any, path ...string) (float64, bool) {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur = mm[k]
	}
	switch v := cur.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint16:
		return float64(v), true
	case int:
		return float64(v), true
	}
	return 0, false
}

// lookup decodes generically so both the MaxMind/DB-IP nested schema and
// the IPinfo Lite flat schema (where "country" is a string) work.
func (g *geoDB) lookup(a netip.Addr) (Geo, bool) {
	var out Geo
	found := false
	ip := a.AsSlice()
	for _, db := range []*maxminddb.Reader{g.city, g.asn} {
		if db == nil {
			continue
		}
		var r map[string]any
		if err := db.Lookup(ip, &r); err != nil || r == nil {
			continue
		}
		if out.Country == "" {
			if cc := first(str(r, "country", "iso_code"), str(r, "country_code")); cc != "" {
				found = true
				out.Country = cc
				out.CountryNm = first(str(r, "country", "names", "en"), str(r, "country"))
				out.Continent = first(str(r, "continent", "code"), str(r, "continent_code"))
				out.City = first(str(r, "city", "names", "en"), str(r, "city"))
				if subs, ok := r["subdivisions"].([]any); ok && len(subs) > 0 {
					if s0, ok := subs[0].(map[string]any); ok {
						out.Region = first(str(s0, "names", "en"), str(s0, "iso_code"))
					}
				}
				lat, ok1 := num(r, "location", "latitude")
				lon, ok2 := num(r, "location", "longitude")
				if ok1 && ok2 {
					out.Lat, out.Lon, out.HasCoords = lat, lon, true
				}
			}
		}
		if out.ASN == 0 {
			if n, ok := num(r, "autonomous_system_number"); ok && n > 0 {
				out.ASN, out.ASOrg, found = uint32(n), str(r, "autonomous_system_organization"), true
			} else if n := parseASN(str(r, "asn")); n != 0 {
				out.ASN, out.ASOrg, found = n, str(r, "as_name"), true
			}
		}
	}
	return out, found
}

func (g *geoDB) close() {
	if g.city != nil {
		_ = g.city.Close()
	}
	if g.asn != nil {
		_ = g.asn.Close()
	}
}

func first(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
