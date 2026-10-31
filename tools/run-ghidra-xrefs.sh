#!/bin/bash
# 定向查一个地址的 xref（用于找被桩函数调用的实现）。
# 用法： run-ghidra-xrefs.sh <二进制路径> <目标地址>
set -u
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
export PATH="$JAVA_HOME/bin:$PATH"
BIN="${1:?binary}"
TARGET="${2:?target address}"
HEADLESS="$ROOT/firmware/tools/ghidra/support/analyzeHeadless"
PROJECT=/tmp/gp-xref
rm -rf "$PROJECT"
mkdir -p "$PROJECT"
"$HEADLESS" "$PROJECT" xrefs \
  -import "$BIN" \
  -scriptPath "$ROOT/firmware/tools/ipsw-research/ghidra" \
  -postScript Xrefs.java "$TARGET" \
  -analysisTimeoutPerFile 120 \
  -max-cpu 2 \
  -deleteProject
