#!/usr/bin/env bash
# Layer 1 - 第三步:挂载解密 DMG,展开为 work/rootfs(Qiling/自研层的 sysroot)
set -euo pipefail
source "$(dirname "$0")/common.sh"

OUT="$WORK/rootfs"
[[ -e "$OUT/System" ]] && { echo "rootfs 已存在于 $OUT(如需重建请先删除)"; exit 0; }

DMG=$(find "$WORK" -maxdepth 2 -iname '*_dec.dmg' | head -1 || true)
[[ -n "$DMG" ]] || DMG=$(find "$WORK" -maxdepth 2 -iname '*.dmg' | head -1 || true)
[[ -n "$DMG" ]] || { echo "没有解密后的 DMG,先运行 01/02" >&2; exit 1; }
echo "==> 使用 $DMG"

mkdir -p "$OUT"
case "$(uname -s)" in
  Darwin)
    MNT=$(mktemp -d /tmp/ios6rootfs.XXXXXX)
    hdiutil attach -readonly -nobrowse -mountpoint "$MNT" "$DMG" || {
      echo "hdiutil 挂载失败(镜像可能未解密,回看 02 输出)" >&2; exit 1; }
    trap 'hdiutil detach "$MNT" -force >/dev/null 2>&1 || true' EXIT
    echo "==> 拷贝 rootfs(约 1GB,稍等;排除卷上无关的 macOS 元数据)"
    rsync -a --exclude='.Trashes' --exclude='.file' --exclude='.fseventsd' \
          --exclude='.Spotlight-V100' --exclude='.DS_Store' "$MNT/" "$OUT/"
    ;;
  Linux)
    echo "Linux: dmg2img 转换后挂载 hfsplus:" >&2
    echo "    dmg2img '$DMG' /tmp/rootfs.img && sudo mount -o ro,loop /tmp/rootfs.img '$OUT'" >&2
    exit 1
    ;;
esac

echo "==> rootfs 就绪: $OUT"
du -sh "$OUT" 2>/dev/null || true
echo
echo "下一步: 用自研执行层启动真实 dyld ——"
echo "    .venv/bin/python3 emu/xnu_boot.py --bin $OUT/sbin/launchd --trace-syscalls"
echo "  IPA 静态分析:"
echo "    .venv/bin/python3 emu/run_binary.py --rootfs $OUT --ipa <应用>.ipa --info"
