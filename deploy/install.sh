#!/bin/bash
# GunGK 一键安装（草案：须在干净 Debian 12 环境实测后定稿，当前不要直接用于生产）
# 流程：渲染模板 -> 备份旧配置 -> 写 /etc/gnugk/gatekeeper.ini、路由脚本、nftables、
# systemd 单元 -> systemctl daemon-reload -> 按顺序启用并启动服务。
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f deploy/variables.env ] || { echo "缺少 deploy/variables.env，请先复制 variables.env.example 并填写真实值"; exit 1; }
[ "$(id -u)" = "0" ] || { echo "请用 root 运行"; exit 1; }
RENDERED=$(mktemp -d)
python3 deploy/render.py deploy/variables.env deploy/ "$RENDERED"
cp -r web /opt/gnugk-web-new 2>/dev/null || true
echo "渲染结果在 $RENDERED，请先人工检查（尤其 gatekeeper.ini 与 nftables）再继续。"
echo "检查无误后，手动执行后续步骤（写配置、装单元、起服务），或在干净环境验证通过后再把本脚本改为自动版。"
echo "TODO(干净环境验证后)：cp gatekeeper.ini /etc/gnugk/；cp gnugk-routes.sh /usr/local/sbin/ 并 chmod +x；"
echo "  cp nftables.conf /etc/nftables.conf；cp systemd/*.service /etc/systemd/system/；"
echo "  systemctl daemon-reload；systemctl enable --now gnugk-routes nftables gnugk gnugk-web"
