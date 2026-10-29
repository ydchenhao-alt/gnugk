#!/bin/bash
# GunGK 部署验证清单（在目标机上运行，每项失败即停下来排查，不要跳过）
set -u
fail=0
check() { if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }
check "gnugk 单实例" "[ \"$(pgrep -c -x gnugk)\" = 1 ]"
check "gnugk 服务 active" "systemctl is-active --quiet gnugk"
check "gnugk-web 服务 active" "systemctl is-active --quiet gnugk-web"
check "gnugk-routes 服务 active" "systemctl is-active --quiet gnugk-routes"
check "状态口 Version 含 h46018=1" "echo s | nc -w 3 127.0.0.1 7000 | grep -q h46018=1"
echo "以下须人工验证（见 DEPLOY.md 第 6 节）："
echo "  - ip route get <外网IP> 走公网口且源地址为公网 IP；ip route get <内网终端IP> 走内网口"
echo "  - 状态口 rv 可见终端 + MCU；本地会议拨号、集团/外呼、媒体双向、新建通话速率"
echo "  - 防火墙从允许端与禁止端各测一次；Web 登录/注销/挂断/重载与操作日志"
exit $fail
