// Package config loads and validates flowtrim.yaml. One file, strict parsing
// (unknown keys are errors), ${ENV} interpolation for secrets.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode values.
const (
	ModeShadow  = "shadow"
	ModeEnforce = "enforce"
)

// Config is the root of flowtrim.yaml.
type Config struct {
	Mode      string    `yaml:"mode"`
	LogLevel  string    `yaml:"log_level"`
	Networks  Networks  `yaml:"networks"`
	Inputs    Inputs    `yaml:"inputs"`
	Normalize Normalize `yaml:"normalize"`
	Rules     Rules     `yaml:"rules"`
	Enrich    Enrich    `yaml:"enrich"`
	Privacy   Privacy   `yaml:"privacy"`
	Output    Output    `yaml:"output"`
	Telemetry Telemetry `yaml:"telemetry"`

	// RuleVersion is a short hash of the rules section, stamped on every record.
	RuleVersion string `yaml:"-"`
}

// Networks defines what "internal" means for direction classification.
type Networks struct {
	Internal []string `yaml:"internal"`
}

// Inputs groups all listeners.
type Inputs struct {
	NetFlow     *UDPInput      `yaml:"netflow"`
	SFlow       *UDPInput      `yaml:"sflow"`
	AWSFirehose *FirehoseInput `yaml:"aws_firehose"`
}

// UDPInput configures a goflow2 UDP listener.
type UDPInput struct {
	Listen    []string `yaml:"listen"`       // host:port
	Sockets   int      `yaml:"sockets"`      // SO_REUSEPORT sockets per address
	Workers   int      `yaml:"workers"`      // decode workers per address
	QueueSize int      `yaml:"queue_size"`   // packets buffered between socket and decoder
	RcvBuf    ByteSize `yaml:"rcvbuf_bytes"` // SO_RCVBUF per socket (default 32MiB; needs net.core.rmem_max or CAP_NET_ADMIN)
	// AllowedExporters restricts which exporter IPs/CIDRs are accepted (empty = all).
	AllowedExporters []string `yaml:"allowed_exporters"`
}

// FirehoseInput is an HTTPS endpoint compatible with Amazon Data Firehose
// "HTTP endpoint" destinations, carrying AWS VPC Flow Logs.
type FirehoseInput struct {
	Listen    string   `yaml:"listen"`
	TLSCert   string   `yaml:"tls_cert"`
	TLSKey    string   `yaml:"tls_key"`
	AccessKey string   `yaml:"access_key"` // must match X-Amz-Firehose-Access-Key
	Fields    []string `yaml:"fields"`     // VPC flow log field order; default = AWS v2 default format
	MaxBody   ByteSize `yaml:"max_body"`
}

// Normalize controls record normalization.
type Normalize struct {
	ScaleBySamplingRate *bool              `yaml:"scale_by_sampling_rate"`
	SamplingOverrides   []SamplingOverride `yaml:"sampling_overrides"`
}

// SamplingOverride sets the sampling rate for exporters that don't report
// one (or always, with force).
type SamplingOverride struct {
	Exporter string `yaml:"exporter"` // IP or CIDR
	Rate     uint64 `yaml:"rate"`
	Force    bool   `yaml:"force"`
}

// Enrich adds context to records after reduction (so only the reduced
// stream is enriched). Every block is optional.
type Enrich struct {
	GeoIP         GeoIP        `yaml:"geoip"`
	DNS           DNS          `yaml:"dns"`
	HostnamesFile string       `yaml:"hostnames_file"` // YAML map: ip -> hostname (wins over DNS)
	MetadataFile  string       `yaml:"metadata_file"`  // YAML list: {cidr, tags{}}
	Interfaces    Interfaces   `yaml:"interfaces"`
	Apps          Apps         `yaml:"apps"`
	Threat        []ThreatList `yaml:"threat_lists"`
	CommunityID   CommunityID  `yaml:"community_id"`
	ClientServer  *bool        `yaml:"client_server"`
	Scope         EnrichScope  `yaml:"scope"`
}

// GeoIP uses MMDB files: MaxMind GeoLite2/GeoIP2, DB-IP Lite, or IPinfo Lite.
type GeoIP struct {
	CityDB       string `yaml:"city_db"`
	ASNDB        string `yaml:"asn_db"`
	SkipInternal *bool  `yaml:"skip_internal"`
}

// DNS is asynchronous reverse-DNS enrichment with a cache.
type DNS struct {
	Enabled     bool     `yaml:"enabled"`
	Nameserver  string   `yaml:"nameserver"` // host:port; empty = system resolver
	Timeout     Duration `yaml:"timeout"`
	CacheTTL    Duration `yaml:"cache_ttl"`
	NegativeTTL Duration `yaml:"negative_ttl"`
	MaxEntries  int      `yaml:"max_entries"`
	Workers     int      `yaml:"workers"`
	Queue       int      `yaml:"queue"`
	Include     []string `yaml:"include_cidrs"` // "internal" = networks.internal; empty = internal only
	Exclude     []string `yaml:"exclude_cidrs"`
}

// EnrichScope limits GeoIP/metadata lookups (DNS has its own include/exclude).
type EnrichScope struct {
	ExcludeCIDRs []string `yaml:"exclude_cidrs"`
}

// Interfaces maps exporter ifIndex to names, from a file and/or SNMP.
type Interfaces struct {
	File string `yaml:"file"` // YAML: exporter_ip -> ifindex -> {name, description, speed_mbps}
	SNMP SNMP   `yaml:"snmp"`
}

// SNMP polls IF-MIB on exporters.
type SNMP struct {
	Enabled   bool     `yaml:"enabled"`
	Version   string   `yaml:"version"` // 2c | 3
	Community string   `yaml:"community"`
	Port      int      `yaml:"port"`
	Timeout   Duration `yaml:"timeout"`
	Retries   int      `yaml:"retries"`
	Interval  Duration `yaml:"interval"`
	Exporters []string `yaml:"exporters"` // empty = every exporter seen
	V3        SNMPv3   `yaml:"v3"`
}

// SNMPv3 USM credentials.
type SNMPv3 struct {
	User      string `yaml:"user"`
	Level     string `yaml:"level"`      // noAuthNoPriv | authNoPriv | authPriv
	AuthProto string `yaml:"auth_proto"` // SHA | SHA256 | SHA512 | MD5
	AuthPass  string `yaml:"auth_pass"`
	PrivProto string `yaml:"priv_proto"` // AES | AES256 | DES
	PrivPass  string `yaml:"priv_pass"`
}

// Apps names services (by port) and SaaS/business apps (by CIDR).
type Apps struct {
	Services     *bool  `yaml:"services"`      // built-in port -> service names
	ServicesFile string `yaml:"services_file"` // YAML map: "tcp/8443" -> name (overrides built-ins)
	AppsFile     string `yaml:"apps_file"`     // YAML map: app name -> [cidr, ...]
}

// ThreatList tags flows touching listed IPs (it does not drop or bypass;
// use rules.bypass with the same file for that).
type ThreatList struct {
	Name     string `yaml:"name"`
	File     string `yaml:"file"`
	Severity string `yaml:"severity"` // low | medium | high | critical
}

// CommunityID computes the Community ID v1 flow hash (Zeek/Suricata compatible).
type CommunityID struct {
	Enabled *bool  `yaml:"enabled"`
	Seed    uint16 `yaml:"seed"`
}

// Privacy pseudonymizes addresses before they leave FlowTrim.
type Privacy struct {
	Key          string        `yaml:"key"` // HMAC key for mode: hash (use ${FLOWTRIM_PSEUDO_KEY})
	Pseudonymize []PrivacyRule `yaml:"pseudonymize"`
}

// PrivacyRule applies to IPs inside CIDR.
type PrivacyRule struct {
	CIDR string `yaml:"cidr"`
	Mode string `yaml:"mode"` // hash | truncate
	Bits int    `yaml:"bits"` // truncate: keep this many prefix bits (default 24 v4 / 48 v6)
}

// Rules is the reduction policy, applied in this fixed order:
// dedup -> bypass -> drop -> rollup -> (raw). Fanout summaries observe all
// non-dropped flows. Drop summaries report what was dropped.
type Rules struct {
	Bypass      []Rule      `yaml:"bypass"`
	Drop        []Rule      `yaml:"drop"`
	Dedup       Dedup       `yaml:"dedup"`
	Rollup      Rollup      `yaml:"rollup"`
	Fanout      Fanout      `yaml:"fanout"`
	DropSummary DropSummary `yaml:"drop_summary"`
	PruneFields []string    `yaml:"prune_fields"`
}

// Rule is a named matcher.
type Rule struct {
	Name  string `yaml:"name"`
	Match Match  `yaml:"match"`
}

// Match conditions are ANDed. A list inside one condition is ORed.
// Empty Match matches everything.
type Match struct {
	SrcCIDR      []string `yaml:"src_cidr"`
	DstCIDR      []string `yaml:"dst_cidr"`
	AnyCIDR      []string `yaml:"any_cidr"` // src OR dst in list
	SrcInList    string   `yaml:"src_ip_in_list"`
	DstInList    string   `yaml:"dst_ip_in_list"`
	AnyInList    string   `yaml:"any_ip_in_list"`
	SrcPort      []string `yaml:"src_port"` // "53", "1024-65535"
	DstPort      []string `yaml:"dst_port"`
	Proto        []string `yaml:"proto"` // "tcp", "udp", "6"
	Exporter     []string `yaml:"exporter"`
	Action       []string `yaml:"action"`
	LogStatus    []string `yaml:"log_status"`
	Direction    []string `yaml:"direction"`
	Source       []string `yaml:"source"`
	BytesLT      *uint64  `yaml:"bytes_lt"`
	BytesGT      *uint64  `yaml:"bytes_gt"`
	PacketsLT    *uint64  `yaml:"packets_lt"`
	PacketsGT    *uint64  `yaml:"packets_gt"`
	TCPFlagsAny  *uint8   `yaml:"tcp_flags_any"`  // any of these bits set
	TCPFlagsNone *uint8   `yaml:"tcp_flags_none"` // none of these bits set
	Not          *Match   `yaml:"not"`
}

// Dedup drops exact duplicate flow records (same flow exported by several
// devices on the path, or re-sent by an exporter).
type Dedup struct {
	Enabled        bool     `yaml:"enabled"`
	Key            []string `yaml:"key"`
	StartTolerance Duration `yaml:"start_tolerance"`
	Window         Duration `yaml:"window"`
	MaxEntries     int      `yaml:"max_entries"`
	ApplyToBypass  *bool    `yaml:"apply_to_bypass"`
}

// Rollup aggregates flows sharing a key over a window into one record that
// keeps security-relevant statistics.
type Rollup struct {
	Enabled    bool     `yaml:"enabled"`
	Match      Match    `yaml:"match"`
	Key        []string `yaml:"key"`
	Window     Duration `yaml:"window"`
	MaxKeys    int      `yaml:"max_keys"`
	IATSamples int      `yaml:"iat_samples"`
}

// Fanout emits per-source summaries when a source talks to many distinct
// destinations or ports in a window (scan / sweep visibility that survives rollup).
type Fanout struct {
	Enabled           bool     `yaml:"enabled"`
	Window            Duration `yaml:"window"`
	MinUniqueDstIPs   int      `yaml:"min_unique_dst_ips"`
	MinUniqueDstPorts int      `yaml:"min_unique_dst_ports"`
	Cap               int      `yaml:"cap"`
	MaxSources        int      `yaml:"max_sources"`
}

// DropSummary emits one audit record per drop rule per interval so the SIEM
// keeps evidence of what was discarded.
type DropSummary struct {
	Enabled  *bool    `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
}

// Output configures forwarding.
type Output struct {
	HEC    *HEC `yaml:"hec"`
	Stdout bool `yaml:"stdout"`
	// Deprecated alias for output.hec with target: ngsiem (v0.1.0 configs).
	LegacyNGSIEM *HEC `yaml:"ngsiem"`
}

// HEC targets.
const (
	TargetNGSIEM  = "ngsiem"  // Falcon Next-Gen SIEM HEC/HTTP Event Data Connector
	TargetOnum    = "onum"    // Falcon Onum Splunk-HEC-compatible Listener
	TargetGeneric = "generic" // any HEC-compatible receiver; URL must include the path
)

// HEC is an HTTP Event Collector output: Falcon NG-SIEM directly, or an
// Onum HEC Listener that forwards to NG-SIEM.
type HEC struct {
	Target      string   `yaml:"target"` // ngsiem | onum | generic
	URL         string   `yaml:"url"`    // endpoint; the target's default path is appended when the URL has none
	Token       string   `yaml:"token"`  // API key / HEC token
	AuthScheme  string   `yaml:"auth_scheme"`
	Path        string   `yaml:"path"` // override the target's default path
	Gzip        *bool    `yaml:"gzip"`
	Timeout     Duration `yaml:"timeout"`
	Concurrency int      `yaml:"concurrency"`
	Source      string   `yaml:"source"`
	Sourcetype  string   `yaml:"sourcetype"`
	Batch       Batch    `yaml:"batch"`
	Retry       Retry    `yaml:"retry"`
	TLS         TLS      `yaml:"tls"`
	Proxy       string   `yaml:"proxy"` // "" = use HTTPS_PROXY env; "none" = direct
	Queue       Queue    `yaml:"queue"`
}

// Batch limits.
type Batch struct {
	MaxEvents int      `yaml:"max_events"`
	MaxBytes  ByteSize `yaml:"max_bytes"` // uncompressed
	MaxWait   Duration `yaml:"max_wait"`
}

// Retry policy.
type Retry struct {
	Initial Duration `yaml:"initial"`
	Max     Duration `yaml:"max"`
}

// TLS client settings.
type TLS struct {
	CAFile             string `yaml:"ca_file"`
	ClientCert         string `yaml:"client_cert"`
	ClientKey          string `yaml:"client_key"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Queue is the batch buffer between the batcher and the senders.
type Queue struct {
	Dir      string   `yaml:"dir"`       // empty = memory only
	MaxBytes ByteSize `yaml:"max_bytes"` // cap on buffered (compressed) bytes
	Overflow string   `yaml:"overflow"`  // drop_oldest | block
}

// Telemetry configures the metrics/health HTTP server.
type Telemetry struct {
	Listen         string       `yaml:"listen"`
	ShadowInterval Duration     `yaml:"shadow_report_interval"`
	UI             *bool        `yaml:"ui"` // serve the FlowTrim Console at / (default true)
	Downstream     []Downstream `yaml:"downstream"`
}

// Downstream is a next hop whose stats the console may show. Real Onum and
// NG-SIEM endpoints don't expose these; the demo's mock receivers do.
type Downstream struct {
	Name     string `yaml:"name"`
	Role     string `yaml:"role"` // onum | ngsiem
	StatsURL string `yaml:"stats_url"`
}

var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// Interpolate replaces ${VAR} and ${VAR:-default} with environment values.
func Interpolate(b []byte) []byte {
	return envRe.ReplaceAllFunc(b, func(m []byte) []byte {
		sm := envRe.FindSubmatch(m)
		if v, ok := os.LookupEnv(string(sm[1])); ok {
			return []byte(v)
		}
		return sm[3]
	})
}

// Load reads, interpolates, parses, defaults and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse parses config bytes.
func Parse(raw []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(Interpolate(raw)))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	rb, _ := yaml.Marshal(c.Rules)
	h := sha256.Sum256(rb)
	c.RuleVersion = hex.EncodeToString(h[:])[:12]
	return &c, nil
}

func boolp(b bool) *bool { return &b }

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeShadow
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if len(c.Networks.Internal) == 0 {
		c.Networks.Internal = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"}
	}
	for _, in := range []*UDPInput{c.Inputs.NetFlow, c.Inputs.SFlow} {
		if in == nil {
			continue
		}
		if in.Sockets <= 0 {
			in.Sockets = 1
		}
		if in.Workers <= 0 {
			in.Workers = 2
		}
		if in.QueueSize <= 0 {
			in.QueueSize = 100000
		}
		if in.RcvBuf <= 0 {
			in.RcvBuf = 32 << 20
		}
	}
	if fh := c.Inputs.AWSFirehose; fh != nil {
		if len(fh.Fields) == 0 {
			fh.Fields = DefaultVPCFields
		}
		if fh.MaxBody == 0 {
			fh.MaxBody = 64 << 20
		}
	}
	if c.Normalize.ScaleBySamplingRate == nil {
		c.Normalize.ScaleBySamplingRate = boolp(true)
	}
	e := &c.Enrich
	if e.GeoIP.SkipInternal == nil {
		e.GeoIP.SkipInternal = boolp(true)
	}
	if e.DNS.Timeout == 0 {
		e.DNS.Timeout = Duration(time.Second)
	}
	if e.DNS.CacheTTL == 0 {
		e.DNS.CacheTTL = Duration(time.Hour)
	}
	if e.DNS.NegativeTTL == 0 {
		e.DNS.NegativeTTL = Duration(5 * time.Minute)
	}
	if e.DNS.MaxEntries == 0 {
		e.DNS.MaxEntries = 500_000
	}
	if e.DNS.Workers == 0 {
		e.DNS.Workers = 8
	}
	if e.DNS.Queue == 0 {
		e.DNS.Queue = 10_000
	}
	if len(e.DNS.Include) == 0 {
		e.DNS.Include = []string{"internal"}
	}
	s := &e.Interfaces.SNMP
	if s.Version == "" {
		s.Version = "2c"
	}
	if s.Port == 0 {
		s.Port = 161
	}
	if s.Timeout == 0 {
		s.Timeout = Duration(2 * time.Second)
	}
	if s.Retries == 0 {
		s.Retries = 1
	}
	if s.Interval == 0 {
		s.Interval = Duration(15 * time.Minute)
	}
	if e.Apps.Services == nil {
		e.Apps.Services = boolp(true)
	}
	if e.CommunityID.Enabled == nil {
		e.CommunityID.Enabled = boolp(true)
	}
	if e.ClientServer == nil {
		e.ClientServer = boolp(true)
	}
	for i := range c.Privacy.Pseudonymize {
		if c.Privacy.Pseudonymize[i].Mode == "" {
			c.Privacy.Pseudonymize[i].Mode = "hash"
		}
	}
	d := &c.Rules.Dedup
	if len(d.Key) == 0 {
		d.Key = []string{"src_ip", "dst_ip", "src_port", "dst_port", "proto", "start_time", "bytes", "packets"}
	}
	if d.StartTolerance == 0 {
		d.StartTolerance = Duration(time.Second)
	}
	if d.Window == 0 {
		d.Window = Duration(30 * time.Second)
	}
	if d.MaxEntries == 0 {
		d.MaxEntries = 2_000_000
	}
	if d.ApplyToBypass == nil {
		d.ApplyToBypass = boolp(true)
	}
	r := &c.Rules.Rollup
	if len(r.Key) == 0 {
		r.Key = []string{"src_ip", "dst_ip", "dst_port", "proto", "action"}
	}
	if r.Window == 0 {
		r.Window = Duration(60 * time.Second)
	}
	if r.MaxKeys == 0 {
		r.MaxKeys = 500_000
	}
	if r.IATSamples == 0 {
		r.IATSamples = 64
	}
	f := &c.Rules.Fanout
	if f.Window == 0 {
		f.Window = Duration(60 * time.Second)
	}
	if f.MinUniqueDstIPs == 0 {
		f.MinUniqueDstIPs = 50
	}
	if f.MinUniqueDstPorts == 0 {
		f.MinUniqueDstPorts = 50
	}
	if f.Cap == 0 {
		f.Cap = 1024
	}
	if f.MaxSources == 0 {
		f.MaxSources = 200_000
	}
	if c.Rules.DropSummary.Enabled == nil {
		c.Rules.DropSummary.Enabled = boolp(true)
	}
	if c.Rules.DropSummary.Interval == 0 {
		c.Rules.DropSummary.Interval = Duration(60 * time.Second)
	}
	if c.Output.HEC == nil && c.Output.LegacyNGSIEM != nil {
		c.Output.HEC = c.Output.LegacyNGSIEM
		if c.Output.HEC.Target == "" {
			c.Output.HEC.Target = TargetNGSIEM
		}
	}
	if o := c.Output.HEC; o != nil {
		if o.Target == "" {
			o.Target = TargetNGSIEM
		}
		preset := map[string][2]string{ // auth scheme, default path
			TargetNGSIEM:  {"Bearer", "/services/collector"},
			TargetOnum:    {"Splunk", "/services/collector/event"},
			TargetGeneric: {"Bearer", ""},
		}[o.Target]
		if o.AuthScheme == "" {
			o.AuthScheme = preset[0]
		}
		if o.Path == "" {
			o.Path = preset[1]
		}
		if o.Gzip == nil {
			o.Gzip = boolp(true)
		}
		if o.Timeout == 0 {
			o.Timeout = Duration(15 * time.Second)
		}
		if o.Concurrency <= 0 {
			o.Concurrency = 4
		}
		if o.Source == "" {
			o.Source = "flowtrim"
		}
		if o.Batch.MaxEvents <= 0 {
			o.Batch.MaxEvents = 1000
		}
		if o.Batch.MaxBytes <= 0 {
			o.Batch.MaxBytes = 2 << 20
		}
		if o.Batch.MaxWait <= 0 {
			o.Batch.MaxWait = Duration(2 * time.Second)
		}
		if o.Retry.Initial <= 0 {
			o.Retry.Initial = Duration(500 * time.Millisecond)
		}
		if o.Retry.Max <= 0 {
			o.Retry.Max = Duration(60 * time.Second)
		}
		if o.Queue.MaxBytes <= 0 {
			if o.Queue.Dir != "" {
				o.Queue.MaxBytes = 10 << 30
			} else {
				o.Queue.MaxBytes = 256 << 20
			}
		}
		if o.Queue.Overflow == "" {
			o.Queue.Overflow = "drop_oldest"
		}
	}
	if c.Telemetry.Listen == "" {
		c.Telemetry.Listen = "127.0.0.1:9109"
	}
	if c.Telemetry.UI == nil {
		c.Telemetry.UI = boolp(true)
	}
	if c.Telemetry.ShadowInterval == 0 {
		c.Telemetry.ShadowInterval = Duration(5 * time.Minute)
	}
}

// Rollup / dedup key fields accepted.
var (
	RollupKeyFields = map[string]bool{"src_ip": true, "dst_ip": true, "src_port": true, "dst_port": true, "proto": true, "action": true, "exporter": true, "in_if": true, "out_if": true, "direction": true, "source": true}
	DedupKeyFields  = map[string]bool{"src_ip": true, "dst_ip": true, "src_port": true, "dst_port": true, "proto": true, "action": true, "exporter": true, "in_if": true, "out_if": true, "start_time": true, "end_time": true, "bytes": true, "packets": true, "tcp_flags": true}
)

// DefaultVPCFields is the AWS VPC Flow Logs default (version 2) format.
var DefaultVPCFields = []string{"version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status"}

// Validate checks semantic correctness.
func (c *Config) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if c.Mode != ModeShadow && c.Mode != ModeEnforce {
		add("mode must be %q or %q, got %q", ModeShadow, ModeEnforce, c.Mode)
	}
	if c.Inputs.NetFlow == nil && c.Inputs.SFlow == nil && c.Inputs.AWSFirehose == nil {
		add("at least one input (inputs.netflow, inputs.sflow, inputs.aws_firehose) is required")
	}
	for name, in := range map[string]*UDPInput{"netflow": c.Inputs.NetFlow, "sflow": c.Inputs.SFlow} {
		if in == nil {
			continue
		}
		if len(in.Listen) == 0 {
			add("inputs.%s.listen is empty", name)
		}
		for _, l := range in.Listen {
			if _, _, err := SplitHostPort(l); err != nil {
				add("inputs.%s.listen %q: %v", name, l, err)
			}
		}
	}
	if fh := c.Inputs.AWSFirehose; fh != nil {
		if fh.Listen == "" {
			add("inputs.aws_firehose.listen is required")
		}
		if fh.AccessKey == "" {
			add("inputs.aws_firehose.access_key is required (Firehose sends it in X-Amz-Firehose-Access-Key)")
		}
		if (fh.TLSCert == "") != (fh.TLSKey == "") {
			add("inputs.aws_firehose.tls_cert and tls_key must be set together")
		}
	}
	for _, k := range c.Rules.Dedup.Key {
		if !DedupKeyFields[k] {
			add("rules.dedup.key: unknown field %q", k)
		}
	}
	for _, k := range c.Rules.Rollup.Key {
		if !RollupKeyFields[k] {
			add("rules.rollup.key: unknown field %q", k)
		}
	}
	seen := map[string]bool{}
	for _, grp := range []struct {
		n string
		r []Rule
	}{{"bypass", c.Rules.Bypass}, {"drop", c.Rules.Drop}} {
		for i, r := range grp.r {
			if r.Name == "" {
				add("rules.%s[%d]: name is required", grp.n, i)
			}
			if seen[r.Name] {
				add("rules.%s[%d]: duplicate rule name %q", grp.n, i, r.Name)
			}
			seen[r.Name] = true
			if grp.n == "drop" && r.Match.IsEmpty() {
				add("rules.drop[%d] %q: empty match would drop ALL traffic; refusing", i, r.Name)
			}
		}
	}
	if sn := c.Enrich.Interfaces.SNMP; sn.Enabled {
		switch sn.Version {
		case "2c":
			if sn.Community == "" {
				add("enrich.interfaces.snmp.community is required for version 2c (use ${SNMP_COMMUNITY})")
			}
		case "3":
			if sn.V3.User == "" {
				add("enrich.interfaces.snmp.v3.user is required for version 3")
			}
		default:
			add("enrich.interfaces.snmp.version must be 2c or 3")
		}
	}
	for i, t := range c.Enrich.Threat {
		if t.Name == "" || t.File == "" {
			add("enrich.threat_lists[%d]: name and file are required", i)
		}
	}
	for i, p := range c.Privacy.Pseudonymize {
		if p.Mode != "hash" && p.Mode != "truncate" {
			add("privacy.pseudonymize[%d].mode must be hash or truncate", i)
		}
		if p.Mode == "hash" && len(c.Privacy.Key) < 16 {
			add("privacy.key must be at least 16 characters for mode: hash (use ${FLOWTRIM_PSEUDO_KEY})")
		}
	}
	for i, o := range c.Normalize.SamplingOverrides {
		if o.Exporter == "" || o.Rate == 0 {
			add("normalize.sampling_overrides[%d]: exporter and rate are required", i)
		}
	}
	if c.Output.HEC != nil && c.Output.LegacyNGSIEM != nil && c.Output.HEC != c.Output.LegacyNGSIEM {
		add("use output.hec or the older output.ngsiem, not both")
	}
	if c.Output.HEC == nil && !c.Output.Stdout {
		add("an output is required (output.hec or output.stdout: true)")
	}
	if o := c.Output.HEC; o != nil {
		switch o.Target {
		case TargetNGSIEM, TargetOnum, TargetGeneric:
		default:
			add("output.hec.target must be ngsiem, onum or generic, got %q", o.Target)
		}
		if o.URL == "" {
			add("output.hec.url is required (NG-SIEM: the connector's API URL; Onum: the Listener address)")
		} else if !strings.HasPrefix(o.URL, "https://") && !strings.HasPrefix(o.URL, "http://") {
			add("output.hec.url must start with https://")
		}
		if o.Token == "" {
			add("output.hec.token is required (set it via ${HEC_TOKEN})")
		}
		if o.Queue.Overflow != "drop_oldest" && o.Queue.Overflow != "block" {
			add("output.hec.queue.overflow must be drop_oldest or block")
		}
		if o.Batch.MaxEvents > 100000 {
			add("output.hec.batch.max_events too large (max 100000)")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// IsEmpty reports whether a match has no conditions.
func (m *Match) IsEmpty() bool {
	return len(m.SrcCIDR) == 0 && len(m.DstCIDR) == 0 && len(m.AnyCIDR) == 0 && m.SrcInList == "" && m.DstInList == "" && m.AnyInList == "" &&
		len(m.SrcPort) == 0 && len(m.DstPort) == 0 && len(m.Proto) == 0 && len(m.Exporter) == 0 && len(m.Action) == 0 &&
		len(m.LogStatus) == 0 && len(m.Direction) == 0 && len(m.Source) == 0 && m.BytesLT == nil && m.BytesGT == nil &&
		m.PacketsLT == nil && m.PacketsGT == nil && m.TCPFlagsAny == nil && m.TCPFlagsNone == nil && m.Not == nil
}

// SplitHostPort parses "host:port" with a numeric port.
func SplitHostPort(s string) (string, int, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("expected host:port")
	}
	host := strings.Trim(s[:i], "[]")
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p < 0 || p > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return host, p, nil
}

// Duration is a YAML-friendly time.Duration ("30s", "2m").
type Duration time.Duration

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML parses durations.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders durations.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// ByteSize accepts "4MiB", "512KiB", "10GiB", "1000".
type ByteSize int64

// UnmarshalYAML parses sizes.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseBytes(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = ByteSize(v)
	return nil
}

// ParseBytes parses a human byte size.
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	for _, u := range []struct {
		s string
		m int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}, {"B", 1}} {
		if strings.HasSuffix(s, u.s) {
			mult = u.m
			s = strings.TrimSpace(strings.TrimSuffix(s, u.s))
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(f * float64(mult)), nil
}
