#!/usr/bin/env bash
# 通用辅助:命令失败时打印该命令的 --help,便于现场适配 ipsw CLI 版本差异
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/work"
mkdir -p "$WORK"

need() { command -v "$1" >/dev/null 2>&1 || { echo "缺少命令: $1(先运行 ./setup.sh)" >&2; exit 2; }; }

# run_or_help <说明> <argv...>  — 失败时输出 <cmd> --help 帮助并返回 1
run_or_help() {
  local desc="$1"; shift
  echo "==> $desc"
  echo "    \$ $*"
  if "$@"; then return 0; fi
  local rc=$?
  echo "!! 命令失败 (rc=$rc): $*" >&2
  echo "---- 该子命令的 --help(用于人工核对语法) ----" >&2
  "$@" --help 2>&1 | head -60 >&2 || true
  return 1
}

probe_build() {
  # 从 BuildManifest 探测设备型号与 build(用于查密钥)
  local ipsw="$1"
  local manifest
  manifest=$(find "$WORK" -maxdepth 3 -name 'BuildManifest*.plist' | head -1 || true)
  if [[ -z "$manifest" ]]; then return 0; fi
  /usr/libexec/PlistBuddy -c 'Print :ProductType' "$manifest" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c 'Print :ProductBuildVersion' "$manifest" 2>/dev/null || true
}
