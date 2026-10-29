# GunGK Web 管理台（重写版）

Python 标准库 only，无第三方依赖，可直接在 Debian 12 上跑。

## 文件

- `server.py`：后端（状态口客户端、配置白名单编辑、口令/会话/CSRF、操作审计、conntrack 速率采样）
- `static/index.html`、`static/app.js`、`static/style.css`：前端（仪表盘、终端、通话、网络、端口与防火墙、功能设置、系统）

## 运行（目标机）

```bash
# 首次：设置口令（交互输入两次，至少 8 位；只存 scrypt 哈希，文件 600）
python3 server.py --set-password
# 启动：默认监听 $WEB_BIND:$WEB_PORT（部署时 WEB_BIND 填内网 IP，绝不填 0.0.0.0）
WEB_BIND=<INTERNAL_IP> WEB_PORT=8090 GK_HOST=127.0.0.1 GK_PORT=7000 \
  GK_CONFIG=/etc/gnugk/gatekeeper.ini python3 server.py
```

环境变量：`WEB_BIND`、`WEB_PORT`、`GK_HOST`、`GK_PORT`、`GK_CONFIG`、`PASS_FILE`、
`ACTIONS_LOG`、`GK_LOG`、`STATIC_DIR`，见 `server.py` 头部注释。

## 接口

- `POST /api/login`、`POST /api/logout`、`GET /api/me`
- `GET /api/state`：注册（rv）、通话（cv）、统计（s）+ conntrack 速率；网闸离线时返回 `gk_online: false`，不崩溃
- `POST /api/action`：`unregister_alias/ip/all`、`disconnect_call/ip/alias/all`、`reload`（CSRF + 确认 + 审计）
- `GET/POST /api/config`：只改白名单字段，保存前时间戳备份，保存后 reload（只影响新呼叫）
- `GET /api/network`、`GET /api/firewall`、`GET /api/services`、`GET /api/logs`（只读）
- `POST /api/service`：启停 gnugk / gnugk-web / gnugk-routes / nftables（固定白名单，无用户输入进 shell）
- `POST /api/change-password`

## 安全基线（不得降级）

scrypt 口令哈希、同 IP 5 次失败锁定 300 秒、会话 12 小时 + HttpOnly + SameSite=Strict、
写操作 CSRF + `X-Requested-With`、响应头 nosniff/DENY/no-referrer/no-store、操作审计日志。

## 已验证（本地，2026-10-29）

- `python3 -m py_compile server.py` 通过；状态口解析器对上游 `RCF|`/`Number of Endpoints`/`Total Endpoints` 格式单测通过。
- 本地实测：错误口令拒绝、正确口令登录 + 会话、网闸离线时 `/api/state` 优雅返回离线、配置读取正常。
- 模拟状态口实测：`rv` 2 终端、`cv` 1 通话、`s` 统计均正确解析并返回。
- 未验证（需干净环境 + 真实 GnuGk）：真实状态口 banner/交互细节、conntrack 速率数值、systemd 下的 `gnugk-web` 重启、
  配置保存后的真实 reload 与回滚。部署前请按 `DEPLOY.md` 第 6 节逐项验证。
