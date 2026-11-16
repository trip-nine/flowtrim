// Package app wires inputs -> engine -> output and owns lifecycle, reloads
// and the telemetry HTTP server.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tripnine/flowtrim/internal/config"
	"github.com/tripnine/flowtrim/internal/flow"
	"github.com/tripnine/flowtrim/internal/ingest"
	"github.com/tripnine/flowtrim/internal/ocsf"
	"github.com/tripnine/flowtrim/internal/output"
	"github.com/tripnine/flowtrim/internal/rules"
	"github.com/tripnine/flowtrim/internal/telemetry"
)

// Version is set at build time.
var Version = "dev"

type stopper interface{ Stop() }

// App is a running FlowTrim.
type App struct {
	cfgPath string
	cfg     *config.Config
	log     *slog.Logger
	out     *output.NGSIEM
	shadow  *telemetry.Shadow
	in      chan *flow.Flow
	reload  chan *config.Config
	done    chan struct{}
	inputs  []stopper
	httpSrv *http.Server

	decMu   sync.Mutex
	decCtrs map[string]prometheus.Counter

	// Stdout, when set, receives every forwarded NDJSON line (debug/tests).
	Stdout io.Writer
	// Ready is closed once all listeners are up.
	Ready chan struct{}
}

// New prepares an App from a loaded config.
func New(cfgPath string, cfg *config.Config, log *slog.Logger) *App {
	return &App{
		cfgPath: cfgPath, cfg: cfg, log: log,
		shadow:  telemetry.NewShadow(),
		in:      make(chan *flow.Flow, 262144),
		reload:  make(chan *config.Config, 1),
		done:    make(chan struct{}),
		decCtrs: map[string]prometheus.Counter{},
		Ready:   make(chan struct{}),
	}
}

func (a *App) hooks() rules.Hooks {
	return rules.Hooks{
		Decision: func(d, r string) {
			k := d + "\x00" + r
			c, ok := a.decCtrs[k] // only the engine goroutine calls this
			if !ok {
				c = telemetry.Decisions.WithLabelValues(d, r)
				a.decCtrs[k] = c
			}
			c.Inc()
			if a.cfg.Mode == config.ModeShadow {
				a.shadow.Decision(d, r)
			}
		},
		Gauge: func(n string, v float64) { telemetry.EngineGauge.WithLabelValues(n).Set(v) },
	}
}

func (a *App) newEngine(cfg *config.Config) (*rules.Engine, error) {
	shadow := cfg.Mode == config.ModeShadow
	emit := func(ev ocsf.Event) {
		if shadow {
			ev.Shadow = ocsf.ShadowReduced
		}
		a.out.Send(ev)
	}
	return rules.New(cfg, filepath.Dir(a.cfgPath), emit, a.hooks(), shadow)
}

// Reload re-reads the config file and swaps rules (inputs/outputs need a restart).
func (a *App) Reload() error {
	nc, err := config.Load(a.cfgPath)
	if err != nil {
		telemetry.ConfigReloads.WithLabelValues("error").Inc()
		return err
	}
	if nc.Mode != a.cfg.Mode {
		a.log.Warn("mode change requires restart; keeping current mode", "current", a.cfg.Mode, "new", nc.Mode)
		nc.Mode = a.cfg.Mode
	}
	a.reload <- nc
	return nil
}

// Run blocks until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	var err error
	if a.cfg.Output.Stdout && a.Stdout == nil {
		a.Stdout = os.Stdout
	}
	a.out, err = output.New(a.cfg.Output.HEC, a.log.With("component", "output"), a.shadow, a.Stdout)
	if err != nil {
		return err
	}
	eng, err := a.newEngine(a.cfg)
	if err != nil {
		return err
	}
	telemetry.BuildInfo.WithLabelValues(Version, a.cfg.RuleVersion, a.cfg.Mode).Set(1)
	a.out.Start()

	engineDone := make(chan struct{})
	go a.engineLoop(eng, engineDone)

	if err := a.startTelemetry(); err != nil {
		return err
	}
	sink := func(f *flow.Flow) { a.in <- f }
	if c := a.cfg.Inputs.NetFlow; c != nil {
		u, err := ingest.NewUDP("netflow", c, sink, a.log)
		if err != nil {
			return err
		}
		if err := u.Start(); err != nil {
			return err
		}
		a.inputs = append(a.inputs, u)
	}
	if c := a.cfg.Inputs.SFlow; c != nil {
		u, err := ingest.NewUDP("sflow", c, sink, a.log)
		if err != nil {
			return err
		}
		if err := u.Start(); err != nil {
			return err
		}
		a.inputs = append(a.inputs, u)
	}
	if c := a.cfg.Inputs.AWSFirehose; c != nil {
		fh := ingest.NewFirehose(c, sink, a.log)
		if err := fh.Start(); err != nil {
			return err
		}
		a.inputs = append(a.inputs, fh)
	}
	a.log.Info("flowtrim running", "version", Version, "mode", a.cfg.Mode, "rule_version", a.cfg.RuleVersion)
	if a.cfg.Mode == config.ModeShadow {
		a.log.Info("SHADOW MODE: forwarding everything unreduced; measuring what enforce mode would save (see /shadow)")
	}
	close(a.Ready)

	<-ctx.Done()
	a.log.Info("shutting down")
	for _, in := range a.inputs {
		in.Stop()
	}
	close(a.in)
	<-engineDone
	a.out.Close(30 * time.Second)
	if a.httpSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.httpSrv.Shutdown(sctx)
	}
	return nil
}

func (a *App) engineLoop(eng *rules.Engine, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	shadow := a.cfg.Mode == config.ModeShadow
	var nextReport time.Time
	if shadow {
		nextReport = time.Now().Add(a.cfg.Telemetry.ShadowInterval.D())
	}
	rv := a.cfg.RuleVersion
	for {
		select {
		case f, ok := <-a.in:
			now := time.Now()
			if !ok {
				eng.FlushAll(now)
				if shadow {
					a.sendShadowReport(now, rv)
				}
				return
			}
			eng.Normalize(f)
			if shadow {
				ev := ocsf.FromFlow(f, f.Start, f.End, f.Bytes, f.Packets, f.TCPFlags,
					ocsf.Reduction{Kind: "none", RuleVersion: rv, Shadow: true})
				ev.Shadow = ocsf.ShadowRaw
				a.out.Send(ev)
			}
			eng.Process(f, now)
		case now := <-tick.C:
			eng.Tick(now)
			telemetry.EngineQueue.Set(float64(len(a.in)))
			if shadow && !now.Before(nextReport) {
				a.sendShadowReport(now, rv)
				nextReport = now.Add(a.cfg.Telemetry.ShadowInterval.D())
			}
		case nc := <-a.reload:
			now := time.Now()
			ne, err := a.newEngine(nc)
			if err != nil {
				telemetry.ConfigReloads.WithLabelValues("error").Inc()
				a.log.Error("reload failed; keeping current rules", "err", err)
				continue
			}
			eng.FlushAll(now)
			eng = ne
			a.cfg.Rules, a.cfg.Networks, a.cfg.Normalize, a.cfg.RuleVersion = nc.Rules, nc.Networks, nc.Normalize, nc.RuleVersion
			rv = nc.RuleVersion
			telemetry.ConfigReloads.WithLabelValues("ok").Inc()
			a.log.Info("rules reloaded", "rule_version", rv)
		}
	}
}

func (a *App) sendShadowReport(now time.Time, rv string) {
	r := a.shadow.Snapshot(true)
	a.log.Info("shadow report",
		"raw_events", r.Total.RawEvents, "reduced_events", r.Total.ReducedEvents,
		"event_reduction_pct", r.TotalEventSaving, "byte_reduction_pct", r.TotalByteSaving,
		"window_byte_reduction_pct", r.WindowByteSaving)
	b, _ := json.Marshal(r)
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	a.out.Send(ocsf.Summary("shadow_report", now, "flowtrim", fields, rv))
}

func (a *App) startTelemetry() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-a.Ready:
			_, _ = w.Write([]byte("ready\n"))
		default:
			http.Error(w, "starting", http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("/shadow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if a.cfg.Mode != config.ModeShadow {
			_ = json.NewEncoder(w).Encode(map[string]string{"mode": a.cfg.Mode, "note": "shadow report is only collected in shadow mode"})
			return
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(a.shadow.Snapshot(false))
	})
	a.httpSrv = &http.Server{Addr: a.cfg.Telemetry.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		if err := a.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return fmt.Errorf("telemetry listen %s: %w", a.cfg.Telemetry.Listen, err)
	case <-time.After(100 * time.Millisecond):
	}
	return nil
}
