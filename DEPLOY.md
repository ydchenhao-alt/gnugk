# 可复现部署手册（草案，待干净环境验证）

来源：生产移交文档中已验证的结论（第 6、7、8、9、13、17 节），本文件把它们从“事后总结”
变成“安装脚本的前置条件 + 验证断言”。所有地址均为占位符。

## 0. 变量文件（唯一真实值入口）

复制 `deploy/variables.env.example` 为 `deploy/variables.env`，填：

| 变量 | 含义 |
|---|---|
| `INTERNAL_IF` / `INTERNAL_IP` / `INTERNAL_GW` | 内网口、内网地址、内网网关 |
| `PUBLIC_IF` / `PUBLIC_IP` / `PUBLIC_GW` | 公网口、公网地址、公网网关 |
| `MGMT_NETS` | 允许访问 22/7000/8090 的管理网段（逗号分隔） |
| `MCU_SIGNAL_IP` / `MCU_ALIAS` / `LOCAL_PREFIX` | MCU 信令 IP、MCU 别名、本地会议前缀 |
| `RECORD_IP` | 录播等只收不发端点的媒体 IP（单列进 AllowSignaledIPs） |
| `GROUP_MCU_IPS` | 集团 MCU IP（直拨媒体白名单，逗号分隔） |

## 1. 构建（顺序不能错，构建方式必须一致）

1. Debian 12 安装构建依赖（gcc/g++、make、libssl-dev、libexpat-dev 等，以构建脚本为准）。
2. 按顺序编译，全部用 `optnoshared`（或全部 `debugnoshared`，不混用）：
   PTLib 2.10.9 -> H323Plus 1.28.0 -> GnuGk 5.16.0。
3. GnuGk 必须 `./configure --enable-h46018`，否则免注册 NAT 直呼媒体不通。
   验证：状态口 Version 行应含 `h46018=1`。
4. 替换运行中的二进制前必须先 `systemctl stop gnugk`（否则 `Text file busy`），
   替换后 `pkill -x gnugk` 再起，确保 `pgrep -x gnugk` 只有 1 个实例（避免孤儿进程同听 1719）。

## 2. 双网口路由（外网注册“正在连接”的根因）

- 默认路由走公网口/公网网关；`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 走内网口/内网网关。
- 由 `gnugk-routes.service`（oneshot）开机执行路由脚本，并用 systemd drop-in 保证路由先于 gnugk。
- 验证断言：`ip route get <外网IP>` 走公网口且源地址为公网 IP；
  `ip route get <内网终端IP>` 走内网口。

## 3. 防火墙（nftables，INPUT 默认 DROP）

放行（其余按模板，管理口只对管理网段开放）：

| 端口 | 协议 | 用途 |
|---|---|---|
| 22 | TCP | SSH，仅管理网段 |
| 7000 | TCP | GnuGk 状态口，仅管理网段 |
| 8090 | TCP | Web 管理台，仅管理网段 |
| 1719 | UDP | H.225 RAS |
| 1720 | TCP | Q.931 |
| 21000-21999 | TCP | H.245 |
| 30000-30999 | UDP | RTP/RTCP 媒体代理 |

注意：1718 发现口、T.120 默认不开放；容器无 NET_ADMIN 时，把同等 ACL 落到宿主/上级防火墙；
启用 INPUT DROP 前先留一条 SSH 逃生通道。

## 4. systemd 与 SSH

- `gnugk.service` 用 `network.target`，不用 `network-online.target`（后者会因 ifupdown-wait-online 阻塞开机）。
- `gnugk-web.service` 的 drop-in 在 `ExecStartPre` 置 `net.netfilter.nf_conntrack_acct=1`
 （解决 LXC 启动时序问题；媒体速率统计依赖 conntrack 计数，且须用新建通话验证，历史通话不回补）。
- SSH 只在内网口监听（`ListenAddress <INTERNAL_IP>`），且必须 `systemctl disable --now ssh.socket`，
  否则 socket 激活抢占 `*:22` 导致 ListenAddress 不生效。

## 5. gatekeeper.ini 关键项（由模板渲染，勿手工改生产文件）

- `Home` 同时绑定内网 + 公网 IP；状态口默认 TCP 7000 随 Home 监听。
- `[RoutedMode] AcceptUnregisteredCalls=1`，`H245PortRange=21000-21999`。
- `[Proxy] RTPPortRange=30000-30999`，`InternalNetwork=<内网网段>`，
  `IgnoreSignaledIPs=1`，`AllowSignaledIPsFrom=<管理网段>`。
- `AllowSignaledIPs` 只列真正可达的固定 IP（MCU、录播、集团 MCU），**不要填全部私网段**，
  否则外网 NAT 终端信令里的私网地址被误信，媒体再次不通。
- `[RasSrv::RRQFeatures] SupportDynamicIP=1` + `OverwriteEPOnSameAddress=1`
  （换网/换热点后同别名换 IP 不再 securityDenial）。
- `[GkStatus::Auth] rule=regex`，只放行管理网段与回环，`default=forbid`，`Shutdown=forbid`。
- 本地会议前缀路由到 MCU 别名；集团会议直拨走 IP 直拨语义（不经网闸中转时不占网闸带宽）。

## 6. 验证顺序（按序通过才算部署成功）

1. 服务启动：三个 systemd 服务均为 active，gnugk 单实例，Version 含 `h46018=1`。
2. 路由断言（第 2 节两条 `ip route get`）。
3. 注册表：终端 + MCU 均在状态口 `rv` 中可见。
4. 本地会议拨号、集团/外呼、媒体双向、每路速率（新建通话，约 1 Mbps 级/路估算带宽余量）。
5. 防火墙：从允许端与禁止端各测一次（公网 22/7000 应拒绝，内网管理口放行）。
6. Web 管理台：未登录接口 401、登录/退出、注销/挂断/重载均有操作日志。
