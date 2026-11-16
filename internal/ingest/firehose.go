package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tripnine/flowtrim/internal/config"
	"github.com/tripnine/flowtrim/internal/flow"
	"github.com/tripnine/flowtrim/internal/telemetry"
)

// Firehose implements the Amazon Data Firehose HTTP endpoint delivery
// contract for AWS VPC Flow Logs: POST JSON {requestId, timestamp,
// records:[{data:base64}]} with X-Amz-Firehose-Access-Key; reply
// {requestId, timestamp} with HTTP 200. Firehose retries on non-200.
type Firehose struct {
	cfg  *config.FirehoseInput
	sink Sink
	log  *slog.Logger
	srv  *http.Server
	cols []string
}

// NewFirehose builds the endpoint.
func NewFirehose(cfg *config.FirehoseInput, sink Sink, log *slog.Logger) *Firehose {
	return &Firehose{cfg: cfg, sink: sink, log: log.With("input", "aws_firehose"), cols: cfg.Fields}
}

type fhRequest struct {
	RequestID string `json:"requestId"`
	Timestamp int64  `json:"timestamp"`
	Records   []struct {
		Data string `json:"data"`
	} `json:"records"`
}

type fhResponse struct {
	RequestID    string `json:"requestId"`
	Timestamp    int64  `json:"timestamp"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

func (h *Firehose) reply(w http.ResponseWriter, code int, id, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(fhResponse{RequestID: id, Timestamp: time.Now().UnixMilli(), ErrorMessage: msg})
}

// ServeHTTP handles one Firehose delivery.
func (h *Firehose) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Amz-Firehose-Request-Id")
	if r.Method != http.MethodPost {
		h.reply(w, http.StatusMethodNotAllowed, id, "POST only")
		return
	}
	key := r.Header.Get("X-Amz-Firehose-Access-Key")
	if subtle.ConstantTimeCompare([]byte(key), []byte(h.cfg.AccessKey)) != 1 {
		telemetry.FlowsRejected.WithLabelValues("aws_firehose", "bad_access_key").Inc()
		h.reply(w, http.StatusUnauthorized, id, "invalid access key")
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, int64(h.cfg.MaxBody))
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			h.reply(w, http.StatusBadRequest, id, "bad gzip body")
			return
		}
		defer zr.Close()
		body = zr
	}
	var req fhRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		h.reply(w, http.StatusBadRequest, id, "invalid JSON")
		return
	}
	if req.RequestID != "" {
		id = req.RequestID
	}
	recv := time.Now().UTC()
	n := 0
	for _, rec := range req.Records {
		raw, err := base64.StdEncoding.DecodeString(rec.Data)
		if err != nil {
			telemetry.FlowsRejected.WithLabelValues("aws_firehose", "bad_base64").Inc()
			continue
		}
		n += h.handleRecord(raw, recv)
	}
	h.log.Debug("firehose delivery", "records", len(req.Records), "flows", n)
	h.reply(w, http.StatusOK, id, "")
}

// handleRecord accepts: plain flow-log lines; gzip-compressed payloads;
// CloudWatch Logs subscription envelopes ({"logEvents":[{"message":...}]});
// JSON objects with a "message" field.
func (h *Firehose) handleRecord(raw []byte, recv time.Time) int {
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err == nil {
			if b, err := io.ReadAll(zr); err == nil {
				raw = b
			}
			zr.Close()
		}
	}
	n := 0
	trim := bytes.TrimSpace(raw)
	if len(trim) > 0 && trim[0] == '{' {
		dec := json.NewDecoder(bytes.NewReader(trim))
		for dec.More() {
			var obj struct {
				MessageType string `json:"messageType"`
				LogEvents   []struct {
					Message string `json:"message"`
				} `json:"logEvents"`
				Message string `json:"message"`
			}
			if err := dec.Decode(&obj); err != nil {
				break
			}
			if obj.MessageType == "CONTROL_MESSAGE" {
				continue
			}
			for _, le := range obj.LogEvents {
				n += h.line(le.Message, recv)
			}
			if obj.Message != "" {
				n += h.line(obj.Message, recv)
			}
		}
		return n
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		n += h.line(sc.Text(), recv)
	}
	return n
}

func (h *Firehose) line(s string, recv time.Time) int {
	f, err := ParseVPCLine(s, h.cols, recv)
	if err != nil {
		if err != errHeader {
			telemetry.FlowsRejected.WithLabelValues("aws_firehose", "parse_error").Inc()
		}
		return 0
	}
	telemetry.FlowsReceived.WithLabelValues("aws_firehose").Inc()
	h.sink(f)
	return 1
}

var errHeader = fmt.Errorf("header line")

// ParseVPCLine parses one space-delimited AWS VPC Flow Log record given the
// field order configured on the flow log ("-" = not applicable).
func ParseVPCLine(s string, cols []string, recv time.Time) (*flow.Flow, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty")
	}
	if fields[0] == "version" || fields[0] == "account-id" {
		return nil, errHeader
	}
	if len(fields) != len(cols) {
		return nil, fmt.Errorf("got %d fields, expected %d", len(fields), len(cols))
	}
	f := &flow.Flow{Received: recv, Source: "aws_firehose", Type: "AWS_VPC", Cloud: map[string]string{}}
	for i, c := range cols {
		v := fields[i]
		if v == "-" {
			continue
		}
		switch c {
		case "srcaddr":
			f.Src, _ = netip.ParseAddr(v)
		case "dstaddr":
			f.Dst, _ = netip.ParseAddr(v)
		case "srcport":
			p, _ := strconv.ParseUint(v, 10, 16)
			f.SrcPort = uint16(p)
		case "dstport":
			p, _ := strconv.ParseUint(v, 10, 16)
			f.DstPort = uint16(p)
		case "protocol":
			p, _ := strconv.ParseUint(v, 10, 8)
			f.Proto = uint8(p)
		case "packets":
			f.Packets, _ = strconv.ParseUint(v, 10, 64)
		case "bytes":
			f.Bytes, _ = strconv.ParseUint(v, 10, 64)
		case "start":
			sec, _ := strconv.ParseInt(v, 10, 64)
			f.Start = time.Unix(sec, 0).UTC()
		case "end":
			sec, _ := strconv.ParseInt(v, 10, 64)
			f.End = time.Unix(sec, 0).UTC()
		case "action":
			f.Action = v
		case "log-status":
			f.LogStatus = v
		case "tcp-flags":
			p, _ := strconv.ParseUint(v, 10, 8)
			f.TCPFlags = uint8(p)
		case "version":
			// informational
		default:
			f.Cloud[strings.ReplaceAll(c, "-", "_")] = v
		}
	}
	if !f.Src.IsValid() || !f.Dst.IsValid() {
		if f.LogStatus == "NODATA" || f.LogStatus == "SKIPDATA" {
			// keep: drop rules decide; give them a zero address so they parse
			f.Src, f.Dst = netip.IPv4Unspecified(), netip.IPv4Unspecified()
			return f, nil
		}
		return nil, fmt.Errorf("missing srcaddr/dstaddr")
	}
	return f, nil
}

// Start serves HTTPS (or HTTP when no cert is given; only for a TLS-terminating proxy).
func (h *Firehose) Start() error {
	h.srv = &http.Server{Addr: h.cfg.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if h.cfg.TLSCert != "" {
			err = h.srv.ListenAndServeTLS(h.cfg.TLSCert, h.cfg.TLSKey)
		} else {
			h.log.Warn("firehose input has no TLS cert: Firehose requires HTTPS, so terminate TLS in front of FlowTrim")
			err = h.srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(200 * time.Millisecond):
	}
	h.log.Info("listening", "addr", h.cfg.Listen, "tls", h.cfg.TLSCert != "")
	return nil
}

// Stop shuts down gracefully.
func (h *Firehose) Stop() {
	if h.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.srv.Shutdown(ctx)
	}
}
