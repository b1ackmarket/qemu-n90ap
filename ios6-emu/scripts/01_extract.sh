#!/usr/bin/env bash
# Layer 1 - 第一步:解包 IPSW(iOS 6 时代为 IMG3 格式,新版 ipsw CLI 解析不了,直接按 ZIP 解包)
set -euo pipefail
source "$(dirname "$0")/common.sh"

IPSW="${1:?用法: $0 <iOS6.ipsw>}"
[[ -f "$IPSW" ]] || { echo "找不到文件: $IPSW" >&2; exit 1; }
need unzip

echo "==> 固件元数据"
ipsw info "$IPSW" || true

echo "==> BuildManifest(查密钥用)"
unzip -o -q "$IPSW" 'BuildManifest.plist' -d "$WORK"

echo "==> rootfs DMG(从 BuildManifest 取文件名)"
DMG_NAME=$(python3 - <<'EOF'
import plistlib, re
m = plistlib.load(open('$WORK/BuildManifest.plist','rb'))
names = set()
for p in m.get('RestoreImageGroups', []):
    names.update(re.findall(r'[\w.-]+\.dmg', str(p)))
# 兜底:直接在 zip 里找最大的 dmg
import zipfile
z = zipfile.ZipFile('$IPSW')
dmgs = [(i.file_size, i.filename) for i in z.infolist() if i.filename.endswith('.dmg')]
dmgs.sort(reverse=True)
print(dmgs[0][1] if dmgs else '')
EOF
)
[[ -n "$DMG_NAME" ]] || { echo "未找到 DMG 文件名" >&2; exit 1; }
echo "    rootfs = $DMG_NAME"
unzip -o -q "$IPSW" "$DMG_NAME" -d "$WORK"

echo "==> kernelcache(IMG3,暂留加密,Layer3 备料)"
unzip -o -q "$IPSW" 'kernelcache*' -d "$WORK" || echo "    (没有 kernelcache,跳过)"

echo
echo "==> 解包完成,产物在 $WORK/"
ls -lh "$WORK" | grep -v '^total'
echo
echo "下一步: ./scripts/02_decrypt.sh"
