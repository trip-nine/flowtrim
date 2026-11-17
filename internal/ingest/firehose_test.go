package ingest

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/trip-nine/flowtrim/internal/config"
	"github.com/trip-nine/flowtrim/internal/flow"
)

func TestParseVPCLineDefault(t *testing.T) {
	l := "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"
	f, err := ParseVPCLine(l, config.DefaultVPCFields, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if f.Src.String() != "172.31.16.139" || f.DstPort != 22 || f.Proto != 6 || f.Bytes != 4249 || f.Action != "ACCEPT" {
		t.Fatalf("bad parse %+v", f)
	}
	if f.Cloud["interface_id"] != "eni-1235b8ca123456789" || f.Cloud["account_id"] != "123456789010" {
		t.Fatalf("cloud fields %v", f.Cloud)
	}
	if f.Start.Unix() != 1418530010 {
		t.Fatal("start")
	}
}

func TestParseVPCNoData(t *testing.T) {
	l := "2 123456789010 eni-1235b8ca123456789 - - - - - - - 1431280876 1431280934 - NODATA"
	f, err := ParseVPCLine(l, config.DefaultVPCFields, time.Now())
	if err != nil || f.LogStatus != "NODATA" {
		t.Fatalf("NODATA should parse for drop rules: %v %v", f, err)
	}
	if _, err := ParseVPCLine("version account-id interface-id", config.DefaultVPCFields, time.Now()); err != errHeader {
		t.Fatal("header line should be skipped")
	}
}

func TestFirehoseHandler(t *testing.T) {
	var got []*flow.Flow
	h := NewFirehose(&config.FirehoseInput{AccessKey: "k", Fields: config.DefaultVPCFields, MaxBody: 1 << 20},
		func(f *flow.Flow) { got = append(got, f) }, slog.New(slog.NewTextHandler(io.Discard, nil)))

	lines := "2 1 eni-a 10.0.0.1 10.0.0.2 1 2 6 1 100 1 2 ACCEPT OK\n2 1 eni-a 10.0.0.3 10.0.0.4 1 2 17 1 100 1 2 REJECT OK\n"
	// CloudWatch-subscription style, gzip-compressed record
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write([]byte(`{"messageType":"DATA_MESSAGE","logEvents":[{"message":"2 1 eni-b 10.0.0.5 10.0.0.6 1 2 6 1 100 1 2 ACCEPT OK"}]}`))
	_ = zw.Close()
	body, _ := json.Marshal(map[string]any{
		"requestId": "req-1", "timestamp": 1,
		"records": []map[string]string{
			{"data": base64.StdEncoding.EncodeToString([]byte(lines))},
			{"data": base64.StdEncoding.EncodeToString(z.Bytes())},
		},
	})

	// wrong key
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("X-Amz-Firehose-Access-Key", "nope")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("want 401, got %d", w.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("X-Amz-Firehose-Access-Key", "k")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
	var resp fhResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.RequestID != "req-1" || resp.Timestamp == 0 {
		t.Fatalf("bad response %+v", resp)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 flows, got %d", len(got))
	}
}
