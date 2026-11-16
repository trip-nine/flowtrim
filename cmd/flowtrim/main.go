// Command flowtrim collects NetFlow/IPFIX/sFlow and AWS VPC Flow Logs,
// reduces them safely, and forwards them to Falcon Next-Gen SIEM over HTTPS.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tripnine/flowtrim/internal/app"
	"github.com/tripnine/flowtrim/internal/config"
	"github.com/tripnine/flowtrim/internal/rules"
)

const usage = `flowtrim — flow-log reducer for Falcon Next-Gen SIEM

Usage:
  flowtrim [run]   -config flowtrim.yaml   start the collector
  flowtrim check   -config flowtrim.yaml   validate config and rules, print a summary
  flowtrim version

Signals: SIGHUP reloads rules; SIGINT/SIGTERM drain and exit.
`

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", envOr("FLOWTRIM_CONFIG", "/etc/flowtrim/flowtrim.yaml"), "path to flowtrim.yaml")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	_ = fs.Parse(args)

	switch cmd {
	case "version":
		fmt.Println(app.Version)
		return
	case "check":
		os.Exit(check(*cfgPath))
	case "run":
	case "help", "-h", "--help":
		fs.Usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fs.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log := newLogger(cfg.LogLevel)
	a := app.New(*cfgPath, cfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := a.Reload(); err != nil {
				log.Error("reload failed", "err", err)
			}
		}
	}()
	if err := a.Run(ctx); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func check(path string) int {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := rules.New(cfg, rules.ConfigDir(path), nil, rules.Hooks{}, false); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("config OK  (mode=%s, rule_version=%s)\n", cfg.Mode, cfg.RuleVersion)
	if c := cfg.Inputs.NetFlow; c != nil {
		fmt.Printf("  input netflow      %v\n", c.Listen)
	}
	if c := cfg.Inputs.SFlow; c != nil {
		fmt.Printf("  input sflow        %v\n", c.Listen)
	}
	if c := cfg.Inputs.AWSFirehose; c != nil {
		fmt.Printf("  input aws_firehose %s (tls=%v)\n", c.Listen, c.TLSCert != "")
	}
	r := cfg.Rules
	fmt.Printf("  bypass rules       %d\n", len(r.Bypass))
	for _, x := range r.Bypass {
		fmt.Printf("    - %s\n", x.Name)
	}
	fmt.Printf("  drop rules         %d\n", len(r.Drop))
	for _, x := range r.Drop {
		fmt.Printf("    - %s\n", x.Name)
	}
	fmt.Printf("  dedup              %v (key=%v, window=%s)\n", r.Dedup.Enabled, r.Dedup.Key, r.Dedup.Window.D())
	fmt.Printf("  rollup             %v (key=%v, window=%s)\n", r.Rollup.Enabled, r.Rollup.Key, r.Rollup.Window.D())
	fmt.Printf("  fanout summaries   %v\n", r.Fanout.Enabled)
	fmt.Printf("  drop summaries     %v\n", *r.DropSummary.Enabled)
	if o := cfg.Output.NGSIEM; o != nil {
		q := "memory"
		if o.Queue.Dir != "" {
			q = o.Queue.Dir
		}
		fmt.Printf("  output ngsiem      %s (gzip=%v, queue=%s)\n", redact(o.URL), *o.Gzip, q)
	}
	if cfg.Mode == config.ModeEnforce {
		fmt.Println("\n  WARNING: enforce mode drops and aggregates data. Run in shadow mode first and review /shadow.")
	}
	return 0
}

func redact(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '.'); j > 4 {
			return u[:i+3] + rest[:4] + "…" + rest[j:]
		}
	}
	return u
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
