package netset

import (
	"net/netip"
	"strings"
	"testing"
)

func TestContains(t *testing.T) {
	s, err := Parse([]string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "::ffff:198.51.100.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{
		"10.200.1.1": true, "11.0.0.1": false, "192.0.2.7": true, "192.0.2.8": false,
		"2001:db8:1::5": true, "2001:db9::1": false, "198.51.100.9": true, "::ffff:10.1.1.1": true,
	} {
		if got := s.Contains(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}

func TestRead(t *testing.T) {
	s, err := Read(strings.NewReader("# feed\n198.51.100.7, c2 server\n203.0.113.0/24\n\n"))
	if err != nil || s.Len() != 2 || !s.Contains(netip.MustParseAddr("203.0.113.9")) {
		t.Fatalf("len=%d err=%v", s.Len(), err)
	}
	if _, err := Read(strings.NewReader("not-an-ip\n")); err == nil {
		t.Fatal("should error")
	}
}
