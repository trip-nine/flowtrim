package config

import (
	"os"
	"strings"
	"testing"
)

func TestExampleConfigParses(t *testing.T) {
	t.Setenv("NGSIEM_URL", "https://x.ingest.us-1.crowdstrike.com")
	t.Setenv("NGSIEM_TOKEN", "t")
	b, err := os.ReadFile("../../examples/flowtrim.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeShadow || c.RuleVersion == "" || len(c.Rules.Bypass) != 3 {
		t.Fatalf("unexpected %+v", c.Mode)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "mode: shadow\nbogus: 1\n",
		"empty drop match": "inputs: {netflow: {listen: ['0.0.0.0:2055']}}\noutput: {stdout: true}\nrules: {drop: [{name: all, match: {}}]}\n",
		"bad mode":         "mode: yolo\ninputs: {netflow: {listen: ['0.0.0.0:2055']}}\noutput: {stdout: true}\n",
		"no token":         "inputs: {netflow: {listen: ['0.0.0.0:2055']}}\noutput: {ngsiem: {url: 'https://x'}}\n",
		"bad rollup key":   "inputs: {netflow: {listen: ['0.0.0.0:2055']}}\noutput: {stdout: true}\nrules: {rollup: {key: [colour]}}\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestInterpolate(t *testing.T) {
	t.Setenv("FT_A", "alpha")
	got := string(Interpolate([]byte("${FT_A} ${FT_MISSING:-dflt} ${FT_MISSING}")))
	if got != "alpha dflt " {
		t.Fatalf("got %q", got)
	}
}

func TestParseBytes(t *testing.T) {
	for s, want := range map[string]int64{"4MiB": 4 << 20, "10GiB": 10 << 30, "512": 512, "1.5KiB": 1536} {
		if got, err := ParseBytes(s); err != nil || got != want {
			t.Errorf("%s: %d %v", s, got, err)
		}
	}
	if _, err := ParseBytes("lots"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Error("should reject")
	}
}
