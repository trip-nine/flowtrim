// Command mkdemodb writes the tiny demo GeoIP/ASN MMDB files used by
// demo/flowtrim-demo.yaml. They cover only documentation and demo ranges;
// for real deployments use MaxMind GeoLite2, DB-IP Lite or IPinfo Lite.
package main

import (
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type place struct {
	cidr, country, countryName, city, continent string
	lat, lon                                    float64
	asn                                         uint32
	org                                         string
}

var places = []place{
	{"93.184.0.0/16", "US", "United States", "Los Angeles", "NA", 34.05, -118.24, 64496, "Example CDN Inc. (demo)"},
	{"203.0.113.0/24", "NL", "Netherlands", "Amsterdam", "EU", 52.37, 4.90, 64501, "Example Hosting B.V. (demo)"},
	{"198.51.100.0/24", "SC", "Seychelles", "Victoria", "AF", -4.62, 55.45, 64502, "Example Offshore VPS Ltd (demo)"},
	{"45.33.0.0/16", "US", "United States", "Fremont", "NA", 37.55, -121.98, 64503, "Example Cloud LLC (demo)"},
	{"2001:db8::/32", "DE", "Germany", "Frankfurt", "EU", 50.11, 8.68, 64504, "Example IPv6 Transit GmbH (demo)"},
}

func write(path, dbType string, rec func(p place) mmdbtype.Map) {
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 28, IncludeReservedNetworks: true,
		Description: map[string]string{"en": "FlowTrim demo database (documentation ranges only)"}})
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range places {
		_, n, err := net.ParseCIDR(p.cidr)
		if err != nil {
			log.Fatal(err)
		}
		if err := w.Insert(n, rec(p)); err != nil {
			log.Fatal(err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		log.Fatal(err)
	}
}

func main() {
	dir := "demo/samples"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	write(filepath.Join(dir, "demo-city.mmdb"), "GeoLite2-City", func(p place) mmdbtype.Map {
		return mmdbtype.Map{
			"country":   mmdbtype.Map{"iso_code": mmdbtype.String(p.country), "names": mmdbtype.Map{"en": mmdbtype.String(p.countryName)}},
			"city":      mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(p.city)}},
			"continent": mmdbtype.Map{"code": mmdbtype.String(p.continent)},
			"location":  mmdbtype.Map{"latitude": mmdbtype.Float64(p.lat), "longitude": mmdbtype.Float64(p.lon)},
		}
	})
	write(filepath.Join(dir, "demo-asn.mmdb"), "GeoLite2-ASN", func(p place) mmdbtype.Map {
		return mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(p.asn), "autonomous_system_organization": mmdbtype.String(p.org)}
	})
	log.Printf("wrote demo MMDBs to %s", dir)
}
