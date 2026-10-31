#!/bin/bash
# 为 airplay_rtp_timing 阶段导出 15 个定向函数的 Ghidra 反编译（只作阅读辅助）。
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PATH="$JAVA_HOME/bin:$PATH"
HEADLESS="$ROOT/firmware/tools/ghidra/support/analyzeHeadless"
BIN="$ROOT/firmware/extracted/24A446/binaries/AirPlaySender/AirPlaySender"
PROJ="$ROOT/firmware/analysis/24A446/airplay-rtp/project"
REQ="$ROOT/research/protocol/airplay_rtp_timing/source/metadata/AirPlaySender/ghidra-request.json"
OUT="$ROOT/research/protocol/airplay_rtp_timing/readable/AirPlaySender"
mkdir -p "$PROJ" "$OUT"
"$HEADLESS" "$PROJ" airplay-rtp \
  -import "$BIN" \
  -scriptPath "$ROOT/firmware/tools/ghidra-scripts" \
  -postScript ExportDecomp.java "$REQ" "$OUT" \
  -analysisTimeoutPerFile 900 \
  -max-cpu 4 \
  > "$ROOT/firmware/analysis/24A446/airplay-rtp/headless.log" 2>&1
echo "exit=$?"
tail -5 "$ROOT/firmware/analysis/24A446/airplay-rtp/headless.log"
