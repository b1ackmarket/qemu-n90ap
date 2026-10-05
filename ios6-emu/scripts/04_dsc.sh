#!/usr/bin/env bash
# Layer 2 前置:解析 dyld_shared_cache(iOS 6 的 UIKit/Foundation 二进制都在缓存里)
set -euo pipefail
source "$(dirname "$0")/common.sh"

CACHE="$WORK/rootfs/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7"
[[ -f "$CACHE" ]] || CACHE=$(find "$WORK" -maxdepth 5 -iname 'dyld_shared_cache*' ! -iname '*.plist' | head -1)
[[ -n "$CACHE" && -f "$CACHE" ]] || { echo "没找到 dyld_shared_cache,先运行 01-03" >&2; exit 1; }
echo "==> 缓存: $CACHE ($(du -h "$CACHE" | cut -f1))"

PY=python3
[[ -x "$ROOT/.venv/bin/python3" ]] && PY="$ROOT/.venv/bin/python3"
"$PY" "$ROOT/emu/dsc_list.py" list "$CACHE"
echo
echo "说明:iOS 6 框架二进制在缓存内。当前执行层(xnu_boot.py)由真实 dyld 自己"
echo "打开并映射缓存(open/mmap 都走虚拟文件系统),无需预先解出 dylib;"
echo "dsc_list.py 用于结构诊断与后续 Qiling 路线的依赖定位。"
