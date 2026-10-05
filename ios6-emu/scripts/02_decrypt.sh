#!/usr/bin/env bash
# Layer 1 - 第二步:查密钥 + 解密 rootfs DMG(iOS 6 rootfs 是 "encrcdsa" FileVault-V2 加密)
set -euo pipefail
source "$(dirname "$0")/common.sh"
need ipsw
need PlistBuddy

MANIFEST=$(find "$WORK" -maxdepth 2 -iname 'BuildManifest*' | head -1 || true)
[[ -n "$MANIFEST" ]] || { echo "先运行 ./scripts/01_extract.sh" >&2; exit 1; }

DEV=$(PlistBuddy -c 'Print :ProductType' "$MANIFEST" 2>/dev/null || true)
BUILD=$(PlistBuddy -c 'Print :ProductBuildVersion' "$MANIFEST" 2>/dev/null || true)
[[ -n "$DEV" && -n "$BUILD" ]] || { echo "无法读取设备/build: $MANIFEST" >&2; exit 1; }
echo "==> 设备: $DEV  build: $BUILD"

# 密钥(theiphonewiki 公开库;rootfs 条目的 72-hex = AES key 32 + HMAC key 40)
if [[ ! -f "$WORK/keys.json" ]]; then
  ipsw download keys --device "$DEV" --build "$BUILD" --output "$WORK" || \
    { echo "密钥下载失败:可手动到 theiphonewiki 查 $DEV $BUILD 的 rootfs key" >&2; exit 1; }
  K=$(find "$WORK" -maxdepth 2 -iname 'keys*.json' | head -1)
  [[ -n "$K" ]] && cp -f "$K" "$WORK/keys.json"
fi
[[ -f "$WORK/keys.json" ]] || { echo "缺少 $WORK/keys.json" >&2; exit 1; }

KEY=$(python3 - "$WORK/keys.json" <<'EOF'
import json, sys, glob, os
d = json.load(open(sys.argv[1]))
# ipsw 的 keys 文件可能包一层目录
if 'keys' in d and isinstance(d['keys'], list):
    d = {k: v for item in d['keys'] for k, v in (item.items() if isinstance(item, dict) else [])}
dmgs = []
for k, v in d.items():
    fns = v.get('filename', [])
    if any(fn.endswith('.dmg') for fn in fns) and v.get('key'):
        dmgs.append((k, v))
if not dmgs:
    sys.exit('keys.json 里没有 rootfs 条目')
# 取 fs dmg(排除 ramdisk:通常 rootfs 条目最大/带 rootfs 字样)
rootfs = [x for x in dmgs if 'rootfs' in x[0].lower()] or dmgs
k = rootfs[0][1]['key'][0]
print(k)
EOF
)
[[ -n "$KEY" ]] || { echo "未能从 keys.json 提取 rootfs key" >&2; exit 1; }
echo "==> rootfs key: ${KEY:0:16}…(${#KEY} hex)"

DMG=$(find "$WORK" -maxdepth 2 -iname '*.dmg' ! -iname '*dec*' | head -1)
[[ -n "$DMG" ]] || { echo "没有 DMG,先运行 01" >&2; exit 1; }
OUT="$WORK/$(basename "${DMG%.dmg}")_dec.dmg"

echo "==> 解密 $DMG → $OUT"
PY=python3
[[ -x "$ROOT/.venv/bin/python3" ]] && PY="$ROOT/.venv/bin/python3"
"$PY" "$ROOT/emu/dmg_decrypt.py" "$DMG" "$OUT" "$KEY"
echo
echo "下一步: ./scripts/03_rootfs.sh"
