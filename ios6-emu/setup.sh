#!/usr/bin/env bash
# 依赖安装:iPSW 工具链 + Qiling 仿真框架
set -euo pipefail
cd "$(dirname "$0")"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }

bold "==> 检查 Homebrew"
if ! command -v brew >/dev/null 2>&1; then
  echo "未找到 brew。请先安装 Homebrew: https://brew.sh" >&2
  exit 1
fi

bold "==> 安装 ipsw CLI(解包/解密 IPSW,blacktop/ipsw)"
if command -v ipsw >/dev/null 2>&1; then
  ipsw version || true
else
  brew install ipsw
fi

bold "==> 安装 Python 仿真栈(qiling + unicorn + capstone,装入 .venv)"
PY=
if [[ ! -x .venv/bin/python3 ]]; then
  ${PYTHON:-python3} -m venv .venv
fi
PY=.venv/bin/python3
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet --upgrade qiling unicorn capstone

bold "==> 自检"
"$PY" - <<'EOF'
import unicorn, capstone
print("unicorn:", unicorn.__version__)
print("capstone:", capstone.__version__)
try:
    import qiling
    print("qiling:", qiling.__version__)
except Exception as e:
    print("qiling 导入失败:", e)
EOF

bold "==> 完成。下一步:把 iOS 6 的 .ipsw 放进 ios6-emu/ 目录,然后:"
echo "    ./scripts/01_extract.sh <文件名>.ipsw"
echo "提示:运行 python 脚本请用 .venv/bin/python3(或把 .venv/bin 加进 PATH)"
