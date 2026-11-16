// Package output delivers records to Falcon Next-Gen SIEM through the
// HEC/HTTP Event Data Connector: NDJSON-style HEC envelopes, batched,
// optionally gzip-compressed, buffered in a (disk) queue, retried with
// exponential backoff, split on 413, dead-lettered on permanent 4xx.
package output

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tripnine/flowtrim/internal/config"
	"github.com/tripnine/flowtrim/internal/ocsf"
	"github.com/tripnine/flowtrim/internal/queue"
	"github.com/tripnine/flowtrim/internal/telemetry"
)

// HECPath is appended when the configured URL has no path.
const HECPath = "/services/collector"

// NGSIEM is the output.
type NGSIEM struct {
	cfg      *config.HEC
	url      string
	auth     string
	client   *http.Client
	q        *queue.Queue
	log      *slog.Logger
	gzipOn   atomic.Bool
	in       chan ocsf.Event
	lines    chan line
	shadow   *telemetry.Shadow
	stdout   io.Writer
	encWG    sync.WaitGroup
	batchWG  sync.WaitGroup
	sendWG   sync.WaitGroup
	sendCtx  context.Context
	cancel   context.CancelFunc
	encoders int
}

type line struct {
	b      []byte
	events int
}

// NormalizeURL appends /services/collector when the URL has no path.
func NormalizeURL(raw string) (string, error) { return NormalizeURLPath(raw, HECPath) }

// NormalizeURLPath appends defPath when the URL has no path.
func NormalizeURLPath(raw, defPath string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("url scheme must be https")
	}
	if (u.Path == "" || u.Path == "/") && defPath != "" {
		u.Path = defPath
	}
	return u.String(), nil
}

// New builds the output. stdout (optional) also receives every NDJSON line.
func New(cfg *config.HEC, log *slog.Logger, shadow *telemetry.Shadow, stdout io.Writer) (*NGSIEM, error) {
	o := &NGSIEM{cfg: cfg, log: log, shadow: shadow, stdout: stdout, encoders: 4}
	o.in = make(chan ocsf.Event, 65536)
	o.lines = make(chan line, 65536)
	if cfg == nil { // stdout-only mode
		return o, nil
	}
	u, err := NormalizeURLPath(cfg.URL, cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("output.hec.url: %w", err)
	}
	o.url = u
	o.auth = strings.TrimSpace(cfg.AuthScheme + " " + cfg.Token)
	o.gzipOn.Store(*cfg.Gzip)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = cfg.Concurrency * 2
	tr.ForceAttemptHTTP2 = true
	switch cfg.Proxy {
	case "":
		tr.Proxy = http.ProxyFromEnvironment
	case "none":
		tr.Proxy = nil
	default:
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("output.hec.proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TLS.InsecureSkipVerify} //nolint:gosec // opt-in for labs
	if cfg.TLS.CAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("output.hec.tls.ca_file: no certificates found")
		}
		tc.RootCAs = pool
	}
	if cfg.TLS.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCert, cfg.TLS.ClientKey)
		if err != nil {
			return nil, err
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	tr.TLSClientConfig = tc
	o.client = &http.Client{Transport: tr, Timeout: cfg.Timeout.D()}

	q, err := queue.New(cfg.Queue.Dir, int64(cfg.Queue.MaxBytes), cfg.Queue.Overflow)
	if err != nil {
		return nil, fmt.Errorf("output.hec.queue: %w", err)
	}
	q.OnDrop = func(b queue.Batch) {
		telemetry.OutBatches.WithLabelValues("dropped_overflow").Inc()
		telemetry.EventsDropped.WithLabelValues("queue_overflow").Add(float64(b.Events))
		log.Warn("queue full: dropped oldest batch", "batch", b.ID, "events", b.Events)
	}
	if n, b := q.Len(); n > 0 {
		log.Info("recovered spooled batches from disk", "batches", n, "bytes", b)
	}
	o.q = q
	return o, nil
}

// Send hands an event to the output (blocks when the pipeline is saturated,
// which pushes backpressure to the engine and, ultimately, the UDP socket).
func (o *NGSIEM) Send(ev ocsf.Event) { o.in <- ev }

// Start launches encoders, batcher and senders.
func (o *NGSIEM) Start() {
	o.sendCtx, o.cancel = context.WithCancel(context.Background())
	for i := 0; i < o.encoders; i++ {
		o.encWG.Add(1)
		go o.encodeLoop()
	}
	o.batchWG.Add(1)
	go o.batchLoop()
	if o.q != nil {
		for i := 0; i < o.cfg.Concurrency; i++ {
			o.sendWG.Add(1)
			go o.sendLoop()
		}
		go o.gaugeLoop()
	}
}

// Close drains: stops intake, seals the last batch, gives senders until
// drainTimeout to empty the queue. Disk-queued batches survive restart.
func (o *NGSIEM) Close(drainTimeout time.Duration) {
	close(o.in)
	o.encWG.Wait()
	close(o.lines)
	o.batchWG.Wait()
	if o.q == nil {
		return
	}
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		if n, _ := o.q.Len(); n == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	o.cancel()
	o.q.Close()
	o.sendWG.Wait()
	if n, _ := o.q.Len(); n > 0 {
		if o.cfg.Queue.Dir != "" {
			o.log.Info("shutdown: batches left on disk will be sent on next start", "batches", n)
		} else {
			o.log.Warn("shutdown: undelivered in-memory batches lost (configure output.hec.queue.dir)", "batches", n)
		}
	}
}

type hecEnvelope struct {
	Time       float64        `json:"time"`
	Host       string         `json:"host,omitempty"`
	Source     string         `json:"source,omitempty"`
	Sourcetype string         `json:"sourcetype,omitempty"`
	Event      map[string]any `json:"event"`
}

// Encode renders one HEC envelope line (with trailing newline).
func (o *NGSIEM) Encode(ev ocsf.Event) ([]byte, error) {
	src, st := "flowtrim", ""
	if o.cfg != nil {
		src, st = o.cfg.Source, o.cfg.Sourcetype
	}
	env := hecEnvelope{Time: float64(ev.Time.UnixMilli()) / 1000, Host: ev.Host, Source: src, Sourcetype: st, Event: ev.Body}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func (o *NGSIEM) encodeLoop() {
	defer o.encWG.Done()
	for ev := range o.in {
		b, err := o.Encode(ev)
		if err != nil {
			telemetry.EventsDropped.WithLabelValues("encode_error").Inc()
			continue
		}
		switch ev.Shadow {
		case ocsf.ShadowReduced:
			o.shadow.Reduced(ev.Kind, len(b))
			continue // would-have-sent: count only
		case ocsf.ShadowRaw:
			o.shadow.Raw(len(b))
		}
		telemetry.EventsEmitted.WithLabelValues(ev.Kind).Inc()
		o.lines <- line{b: b, events: 1}
	}
}

func (o *NGSIEM) batchLoop() {
	defer o.batchWG.Done()
	var buf bytes.Buffer
	n := 0
	maxEv, maxB, maxWait := 1000, 2<<20, 2*time.Second
	if o.cfg != nil {
		maxEv, maxB, maxWait = o.cfg.Batch.MaxEvents, int(o.cfg.Batch.MaxBytes), o.cfg.Batch.MaxWait.D()
	}
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	seal := func() {
		if n == 0 {
			return
		}
		data := append([]byte(nil), buf.Bytes()...)
		o.seal(data, n)
		buf.Reset()
		n = 0
	}
	for {
		select {
		case l, ok := <-o.lines:
			if !ok {
				seal()
				return
			}
			if o.stdout != nil {
				_, _ = o.stdout.Write(l.b)
			}
			if o.q == nil {
				continue
			}
			if n > 0 && buf.Len()+len(l.b) > maxB {
				seal()
			}
			if n == 0 {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(maxWait)
			}
			buf.Write(l.b)
			n += l.events
			if n >= maxEv {
				seal()
			}
		case <-timer.C:
			seal()
			timer.Reset(maxWait)
		}
	}
}

func (o *NGSIEM) seal(data []byte, events int) {
	if o.q == nil {
		return
	}
	compressed := false
	if o.gzipOn.Load() {
		if z, err := gzipBytes(data); err == nil {
			data, compressed = z, true
		}
	}
	if err := o.q.Put(data, events, compressed); err != nil {
		telemetry.EventsDropped.WithLabelValues("queue_closed").Add(float64(events))
	}
}

func gzipBytes(b []byte) ([]byte, error) {
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func (o *NGSIEM) gaugeLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-o.sendCtx.Done():
			return
		case <-t.C:
			n, b := o.q.Len()
			telemetry.QueueBatches.Set(float64(n))
			telemetry.QueueBytes.Set(float64(b))
		}
	}
}

// result classes
type outcome int

const (
	okSent outcome = iota
	retry
	split
	noGzip
	authErr
	dead
)

func classify(code int, compressed bool) outcome {
	switch {
	case code >= 200 && code < 300:
		return okSent
	case code == 413:
		return split
	case (code == 415 || code == 400) && compressed:
		// receivers that can't read gzip answer 415 or 400; resend uncompressed
		// once before treating it as a bad batch
		return noGzip
	case code == 401 || code == 403:
		return authErr
	case code == 408 || code == 429 || code >= 500:
		return retry
	default:
		return dead
	}
}

func (o *NGSIEM) sendLoop() {
	defer o.sendWG.Done()
	for {
		if o.sendCtx.Err() != nil {
			return
		}
		b, err := o.q.Get()
		if errors.Is(err, queue.ErrClosed) {
			return
		}
		if err != nil {
			o.log.Error("queue read", "err", err)
			continue
		}
		o.deliver(b)
	}
}

func (o *NGSIEM) backoff(attempt int, retryAfter time.Duration) bool {
	d := o.cfg.Retry.Initial.D() << min(attempt, 16)
	if d > o.cfg.Retry.Max.D() || d <= 0 {
		d = o.cfg.Retry.Max.D()
	}
	d = d/2 + time.Duration(rand.Int64N(int64(d/2)+1)) // jitter
	if retryAfter > d {
		d = retryAfter
	}
	select {
	case <-o.sendCtx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (o *NGSIEM) deliver(b queue.Batch) {
	for attempt := 0; ; attempt++ {
		code, ra, err := o.post(b)
		var oc outcome
		if err != nil && o.sendCtx.Err() != nil {
			o.q.Nack(b.ID) // shutting down: keep the batch for the next start
			return
		}
		if err != nil {
			oc = retry
			if attempt == 0 || attempt%10 == 0 {
				o.log.Warn("HEC request failed; will retry", "batch", b.ID, "attempt", attempt+1, "err", err)
			}
		} else {
			telemetry.OutStatus.WithLabelValues(strconv.Itoa(code)).Inc()
			oc = classify(code, b.Compressed)
		}
		switch oc {
		case okSent:
			telemetry.OutBatches.WithLabelValues("ok").Inc()
			telemetry.OutEvents.Add(float64(b.Events))
			telemetry.OutWireBytes.Add(float64(len(b.Data)))
			if b.Compressed {
				if raw, err := gunzipLen(b.Data); err == nil {
					telemetry.OutRawBytes.Add(float64(raw))
				}
			} else {
				telemetry.OutRawBytes.Add(float64(len(b.Data)))
			}
			o.q.Ack(b.ID)
			return
		case retry:
			telemetry.OutBatches.WithLabelValues("retry").Inc()
			if err == nil && (attempt == 0 || attempt%10 == 0) {
				o.log.Warn("receiver asked us to retry", "batch", b.ID, "status", code, "attempt", attempt+1)
			}
			if !o.backoff(attempt, ra) {
				o.q.Nack(b.ID)
				return
			}
		case authErr:
			telemetry.OutBatches.WithLabelValues("auth_error").Inc()
			o.log.Error("receiver rejected the token (check output.hec.token and the connector/Listener); holding data and retrying", "status", code, "batch", b.ID)
			if !o.backoff(16, 0) {
				o.q.Nack(b.ID)
				return
			}
		case noGzip:
			raw, err := gunzip(b.Data)
			if err != nil {
				o.q.DeadLetter(b.ID)
				return
			}
			// Probe: is it the compression or the content? Only a success
			// uncompressed proves the receiver can't read gzip.
			probe := queue.Batch{ID: b.ID, Data: raw, Events: b.Events}
			pc, _, perr := o.post(probe)
			if perr == nil && pc >= 200 && pc < 300 {
				o.log.Warn("receiver cannot read gzip bodies; gzip disabled for this run (set gzip: false to make it permanent)", "status", code)
				o.gzipOn.Store(false)
				telemetry.OutBatches.WithLabelValues("ok").Inc()
				telemetry.OutEvents.Add(float64(b.Events))
				telemetry.OutWireBytes.Add(float64(len(raw)))
				telemetry.OutRawBytes.Add(float64(len(raw)))
				o.q.Ack(b.ID)
				return
			}
			if perr == nil && classify(pc, false) == dead {
				telemetry.OutBatches.WithLabelValues("dead_letter").Inc()
				telemetry.EventsDropped.WithLabelValues("dead_letter").Add(float64(b.Events))
				o.log.Error("receiver rejected batch permanently (also uncompressed); moved to dead-letter", "status", pc, "batch", b.ID)
				o.q.DeadLetter(b.ID)
				return
			}
			// transient error during the probe: keep the original and retry later
			if !o.backoff(attempt, 0) {
				o.q.Nack(b.ID)
				return
			}
		case split:
			raw := b.Data
			if b.Compressed {
				var err error
				if raw, err = gunzip(b.Data); err != nil {
					o.q.DeadLetter(b.ID)
					return
				}
			}
			lines := bytes.SplitAfter(bytes.TrimRight(raw, "\n"), []byte("\n"))
			if len(lines) <= 1 {
				telemetry.OutBatches.WithLabelValues("dead_letter").Inc()
				telemetry.EventsDropped.WithLabelValues("oversize_event").Inc()
				o.log.Error("single event too large for receiver (413); dead-lettered", "batch", b.ID, "bytes", len(raw))
				o.q.DeadLetter(b.ID)
				return
			}
			telemetry.OutBatches.WithLabelValues("split").Inc()
			half := len(lines) / 2
			for _, part := range [][][]byte{lines[:half], lines[half:]} {
				data := bytes.Join(part, nil)
				if len(data) > 0 && data[len(data)-1] != '\n' {
					data = append(data, '\n')
				}
				comp := false
				if o.gzipOn.Load() {
					if z, err := gzipBytes(data); err == nil {
						data, comp = z, true
					}
				}
				_ = o.q.Put(data, len(part), comp)
			}
			o.log.Info("receiver returned 413; split batch", "batch", b.ID, "events", b.Events)
			o.q.Ack(b.ID)
			return
		case dead:
			telemetry.OutBatches.WithLabelValues("dead_letter").Inc()
			telemetry.EventsDropped.WithLabelValues("dead_letter").Add(float64(b.Events))
			o.log.Error("receiver rejected batch permanently; moved to dead-letter", "status", code, "batch", b.ID, "events", b.Events)
			o.q.DeadLetter(b.ID)
			return
		}
	}
}

func gunzipLen(b []byte) (int64, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	return io.Copy(io.Discard, zr)
}

func (o *NGSIEM) post(b queue.Batch) (int, time.Duration, error) {
	ctx, cancel := context.WithTimeout(o.sendCtx, o.cfg.Timeout.D())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url, bytes.NewReader(b.Data))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Authorization", o.auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "flowtrim")
	if b.Compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	start := time.Now()
	resp, err := o.client.Do(req)
	telemetry.OutLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		return 0, 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	var ra time.Duration
	if s := resp.Header.Get("Retry-After"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil {
			ra = time.Duration(secs) * time.Second
		}
	}
	return resp.StatusCode, ra, nil
}
