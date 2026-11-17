package enrich

import (
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trip-nine/flowtrim/internal/config"
)

// Runs only when FLOWTRIM_SNMPSIM=host:port points at an SNMP agent
// (e.g. snmpsim with deploy/snmpsim/public.snmprec). CI skips it.
func TestSNMPPollAgainstAgent(t *testing.T) {
	target := os.Getenv("FLOWTRIM_SNMPSIM")
	if target == "" {
		t.Skip("set FLOWTRIM_SNMPSIM=127.0.0.1:1161 to run against snmpsim")
	}
	i := strings.LastIndexByte(target, ':')
	port, _ := strconv.Atoi(target[i+1:])
	c := config.SNMP{Enabled: true, Version: "2c", Community: "public", Port: port, Timeout: config.Duration(2 * time.Second), Retries: 1, Interval: config.Duration(time.Hour)}
	p, err := newSNMP(c, quiet, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	m, err := p.poll(netip.MustParseAddr(target[:i]))
	if err != nil {
		t.Fatal(err)
	}
	if m[3].Name != "Gi0/0/3" || m[3].Description != "uplink-isp-a" || m[3].SpeedMbps != 10000 || m[7].Name != "Te0/1/0" {
		t.Fatalf("unexpected IF-MIB result: %+v", m)
	}
}
