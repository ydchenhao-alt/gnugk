#!/bin/bash
# GnuGk 可复现构建（草案，须在干净 Debian 12 环境验证后定稿）
# 版本基线：PTLib 2.10.9 / H323Plus 1.28.0 / GnuGk 5.16.0（生产基线）
# 关键点：三者构建方式必须一致（全部 optnoshared）；GnuGk 必须 --enable-h46018。
set -euo pipefail
SRC="${SRC:-/usr/local/src/gnugk-build}"
mkdir -p "$SRC" && cd "$SRC"

# 1. 依赖（Debian 12，具体包名以干净环境实测为准）
# apt-get update && apt-get install -y build-essential libssl-dev libexpat1-dev \
#   libsdl1.2-dev libavahi-client-dev bison flex pkg-config git

# 2. 依次 clone（上游 willamowius 仓库）并按顺序编译
# for repo in ptlib h323plus gnugk; do ...; done
# PTLib:    ./configure && make optnoshared && make install
# H323Plus: ./configure && make optnoshared && make install
# GnuGk:    ./configure --enable-h46018 && make optdepend && make optnoshared && make install

echo "TODO: 在干净环境实测后，把上面注释的步骤落为真实命令，并记录每步耗时与报错。"
echo "验证：gnugk 状态口 Version 行应含 h46018=1；替换二进制前先 systemctl stop gnugk，替换后 pkill -x gnugk 再起单实例。"
