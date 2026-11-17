package enrich

import "fmt"

// builtinServices is a compact set of well-known service names (IANA and
// common practice). Users extend/override it with apps.services_file.
var builtinServices = map[string]string{
	"tcp/20": "ftp-data", "tcp/21": "ftp", "tcp/22": "ssh", "tcp/23": "telnet", "tcp/25": "smtp",
	"udp/53": "dns", "tcp/53": "dns", "udp/67": "dhcp", "udp/68": "dhcp", "udp/69": "tftp",
	"tcp/80": "http", "tcp/88": "kerberos", "udp/88": "kerberos", "tcp/110": "pop3", "udp/123": "ntp",
	"tcp/135": "msrpc", "udp/137": "netbios-ns", "udp/138": "netbios-dgm", "tcp/139": "netbios-ssn",
	"tcp/143": "imap", "udp/161": "snmp", "udp/162": "snmp-trap", "tcp/179": "bgp", "tcp/389": "ldap",
	"udp/389": "ldap", "tcp/443": "https", "udp/443": "quic", "tcp/445": "smb", "udp/500": "ike",
	"udp/514": "syslog", "tcp/514": "syslog", "tcp/587": "submission", "tcp/636": "ldaps",
	"tcp/853": "dns-over-tls", "tcp/873": "rsync", "tcp/989": "ftps-data", "tcp/990": "ftps",
	"tcp/993": "imaps", "tcp/995": "pop3s", "udp/1194": "openvpn", "tcp/1433": "mssql",
	"tcp/1521": "oracle", "udp/1812": "radius", "udp/1813": "radius-acct", "tcp/2049": "nfs",
	"udp/2055": "netflow", "tcp/2375": "docker", "tcp/2376": "docker-tls", "tcp/3268": "ldap-gc",
	"tcp/3269": "ldaps-gc", "tcp/3306": "mysql", "tcp/3389": "rdp", "udp/3389": "rdp",
	"udp/4500": "ipsec-nat-t", "udp/4739": "ipfix", "tcp/5060": "sip", "udp/5060": "sip",
	"tcp/5061": "sips", "tcp/5432": "postgresql", "udp/5353": "mdns", "tcp/5671": "amqps",
	"tcp/5672": "amqp", "tcp/5900": "vnc", "tcp/5985": "winrm", "tcp/5986": "winrm-https",
	"tcp/6379": "redis", "tcp/6443": "kubernetes-api", "udp/6343": "sflow", "tcp/8080": "http-alt",
	"tcp/8443": "https-alt", "tcp/9092": "kafka", "tcp/9200": "elasticsearch", "tcp/10250": "kubelet",
	"tcp/27017": "mongodb", "udp/51820": "wireguard",
}

func protoKey(proto uint8, port uint16) string {
	switch proto {
	case 6:
		return fmt.Sprintf("tcp/%d", port)
	case 17:
		return fmt.Sprintf("udp/%d", port)
	case 132:
		return fmt.Sprintf("sctp/%d", port)
	}
	return ""
}

// serverSide infers which side is the server: "dst", "src" or "" (unknown).
// Known service port wins; otherwise the side using a port below 1024.
func serverSide(services map[string]string, proto uint8, sport, dport uint16, sportValid bool) string {
	if proto != 6 && proto != 17 && proto != 132 {
		return ""
	}
	_, dKnown := services[protoKey(proto, dport)]
	sKnown := false
	if sportValid {
		_, sKnown = services[protoKey(proto, sport)]
	}
	switch {
	case dKnown && !sKnown:
		return "dst"
	case sKnown && !dKnown:
		return "src"
	case !sportValid:
		return "dst" // a rollup folded many ephemeral source ports
	case dport < 1024 && sport >= 1024:
		return "dst"
	case sport < 1024 && dport >= 1024:
		return "src"
	case dKnown && sKnown:
		if dport <= sport {
			return "dst"
		}
		return "src"
	}
	return ""
}
