# GunGK fork（基于 GnuGk）

> 本文件是本 fork 新增的 GunGK 部署与 Web 管理层说明；上游原 README 仍为 `Readme.md`。

> 目标：把一次“手工调通、不可复制”的 GnuGk 部署，变成“变量文件 + 一键脚本 + Web 管理台”就能重建的版本。
> 上游：https://github.com/willamowius/gnugk（本 fork 保留上游 GPLv2 许可与信令核心，不改核心呼叫逻辑）
> 生产基线（供参考，不写真实值）：GnuGk 5.16.0 + H323Plus 1.28.0 + PTLib 2.10.9，Debian 12。

## 这个 fork 多了什么（上游没有的）

1. `deploy/`：可复现部署。构建脚本、变量化 `gatekeeper.ini` 模板、双网口路由脚本、
   nftables 模板、systemd 单元与启动顺序、安装与验证清单。
2. `web/`（已从头重写实现，见 `WEB-UI-SPEC.md` 与 `web/README.md`）：功能完整的 Web 管理台，
   替代只能看注册/通话的简易版：网络、端口/防火墙、功能开关、客户端管理、日志与备份。
3. `DEPLOY.md`：从空机到验证通过的完整步骤，含每个历史坑的回归检查。

## 安全红线（提交前必查）

- 本仓库**只放占位符**，绝不提交真实内网/公网 IP、MCU 地址、SSH 口令、Web 口令哈希。
- 真实值只放在部署目标机上的 `deploy/variables.env`，不要提交该文件（本 fork 保留上游 `.gitignore`，见下方“提交说明”）。
- 示例文件统一用 `<...>` 占位符命名，例如 `<INTERNAL_IP>`、`<PUBLIC_IP>`。

## 目录结构

```
deploy/
  variables.env.example     # 复制为 variables.env 后填真实值（不提交）
  build-gnugk.sh            # PTLib -> H323Plus -> GnuGk，--enable-h46018
  gatekeeper.ini.template   # 由变量渲染，含 Routed/Proxy/动态IP/状态口Auth
  gnugk-routes.sh.template  # 双网口路由：默认走公网，RFC1918 走内网
  nftables.conf.template    # INPUT 默认 DROP 的端口表
  systemd/                  # gnugk / gnugk-routes / gnugk-web
web/                        # 见 WEB-UI-SPEC.md
DEPLOY.md                   # 部署与验证手册
WEB-UI-SPEC.md              # Web 管理台功能规格
```

## 快速开始（目标机，Debian 12）

```bash
cp deploy/variables.env.example deploy/variables.env
# 编辑 variables.env，填本环境的 IP/网段/MCU/前缀
bash deploy/build-gnugk.sh
bash deploy/install.sh   # 渲染模板并提示人工检查后再写配置、装 systemd、起服务（草案，须干净环境实测）
bash deploy/verify.sh    # 服务/单实例/状态口检查 + 人工验证清单
```

## 已确认的事项（2026-10-29）

- 公开 fork：文档/模板中的真实 IP 已全部替换为占位符，可公开。
- `web/` 从头重写，不移植旧版 8090 页面。
- 部署目标：Debian 12 + systemd + nftables 为 v1，Docker 仅作为后续选项。
- 版本：先钉生产基线 5.16.0，验证通过后再考虑升级。
- 尚未在干净环境 + 真实 GnuGk 上验证：见 `web/README.md` 末尾的“未验证”清单与 `DEPLOY.md` 第 6 节。
