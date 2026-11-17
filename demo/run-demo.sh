#!/usr/bin/env bash
# FlowTrim end-to-end demo on one machine:
#
#   flowgen replay ──UDP 4739──► FlowTrim ──HEC/HTTPS──► Falcon Onum (mock :8089) ──HEC──► Falcon NG-SIEM (mock :8088)
#
# Console: http://127.0.0.1:9109      Ctrl-C stops everything.
#
# Env overrides: SAMPLE=demo/samples/campus.v9.pcap  SPEED=2  REAL_HEC_URL=... REAL_HEC_TOKEN=...
#   REAL_HEC_URL/TOKEN send FlowTrim's output to a real Onum Listener or NG-SIEM connector instead of the mocks.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SAMPLE="${SAMPLE:-demo/samples/enterprise-mix.ipfix.pcap}"
SPEED="${SPEED:-1}"
WORK="${TMPDIR:-/tmp}/flowtrim-demo"
mkdir -p "$WORK"

BIN=bin
if [ -x ./flowtrim ] && [ -x ./flowgen ] && [ -x ./mockhec ]; then
  BIN=.            # unpacked release archive: binaries sit next to demo/
elif [ ! -x bin/flowtrim ] || [ ! -x bin/flowgen ] || [ ! -x bin/mockhec ]; then
  command -v go >/dev/null || { echo "Go 1.24+ is required to build the demo (https://go.dev/dl/), or use a release archive from https://github.com/trip-nine/flowtrim/releases"; exit 1; }
  echo "→ building flowtrim, flowgen, mockhec"
  CGO_ENABLED=0 go build -o bin/ ./cmd/...
fi

pids=()
cleanup() { echo; echo "→ stopping demo"; for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT INT TERM

if [ -n "${REAL_HEC_URL:-}" ]; then
  echo "→ sending to REAL endpoint $REAL_HEC_URL (mocks not started)"
  export HEC_URL="$REAL_HEC_URL" HEC_TOKEN="${REAL_HEC_TOKEN:?set REAL_HEC_TOKEN}"
  export ONUM_STATS="http://127.0.0.1:1/none" NGSIEM_STATS="http://127.0.0.1:1/none"
else
  "$BIN"/mockhec -role ngsiem -listen 127.0.0.1:8088 -token demo-token -out "$WORK/ngsiem-received.ndjson" >"$WORK/ngsiem.log" 2>&1 & pids+=($!)
  "$BIN"/mockhec -role onum -listen 127.0.0.1:8089 -token demo-token -forward http://127.0.0.1:8088/services/collector -forward-token demo-token >"$WORK/onum.log" 2>&1 & pids+=($!)
  export HEC_URL=http://127.0.0.1:8089 HEC_TOKEN=demo-token
fi
export FLOWTRIM_QUEUE="$WORK/queue"
"$BIN"/flowtrim check -config demo/flowtrim-demo.yaml >/dev/null
"$BIN"/flowtrim run -config demo/flowtrim-demo.yaml 2>"$WORK/flowtrim.log" & pids+=($!)
for i in $(seq 1 50); do curl -fsS http://127.0.0.1:9109/readyz >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN"/flowgen replay -pcap "$SAMPLE" -target 127.0.0.1:4739 -loop 0 -speed "$SPEED" >"$WORK/flowgen.log" 2>&1 & pids+=($!)

cat <<MSG

  FlowTrim demo is running
  ─────────────────────────────────────────────────────────────
  Console        http://127.0.0.1:9109
  Sample         $SAMPLE (looping, speed ${SPEED}x)
  Mock Onum      http://127.0.0.1:8089/stats
  Mock NG-SIEM   http://127.0.0.1:8088/stats   ·   /events?limit=5
  Logs           $WORK/*.log
  Received data  $WORK/ngsiem-received.ndjson
  ─────────────────────────────────────────────────────────────
  Ctrl-C to stop.
MSG
( [ "$(uname)" = Darwin ] && open http://127.0.0.1:9109 ) >/dev/null 2>&1 || ( command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:9109 ) >/dev/null 2>&1 || true
wait
