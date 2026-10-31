#!/bin/bash
# 定向反编译 MediaToolbox 的某个函数（默认 timestampInfo 提供者）。
# 关键：分析超时只给 30 秒；脚本按地址按需反汇编，不做全量自动分析。
# 用法： run-ghidra-mtb.sh [0x地址 或 符号名]
set -u
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
export PATH="$JAVA_HOME/bin:$PATH"
TARGET="${1:-0x196f5bca4}"
DSC="$ROOT/firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
OUT=/tmp/mtb
if [ ! -f "$OUT/MediaToolbox" ]; then
  mkdir -p "$OUT"
  ipsw dyld extract "$DSC" /System/Library/Frameworks/MediaToolbox.framework/MediaToolbox -o "$OUT"
fi
HEADLESS="$ROOT/firmware/tools/ghidra/support/analyzeHeadless"
PROJECT=/tmp/gp-mtb
rm -rf "$PROJECT"
mkdir -p "$PROJECT"
"$HEADLESS" "$PROJECT" mtb \
  -import "$OUT/MediaToolbox" \
  -scriptPath "$ROOT/firmware/tools/ipsw-research/ghidra" \
  -postScript DumpOne.java "$TARGET" \
  -analysisTimeoutPerFile 30 \
  -max-cpu 2 \
  -deleteProject
