# Android 加速器可行性、架构与验证计划

> 状态：实验实现 + 实验室验证
> 基线：`experiment/android-certless-ip`
> 目标：在 Android 上复用 DevSidecar 规则，支持有证书 MITM 和免证书隧道两条路径，并明确哪些能力可行、哪些不可行。

## 1. 目标与边界

目标：

- 复用 DevSidecar 的声明式规则（域名、路径、SNI、镜像、反代、预置 IP、排除列表、请求/响应头替换）。
- 有证书时：MITM + SNI 伪装 + 镜像/反代，覆盖 GitHub、Hugging Face、Pixiv（P站）等公开资源。
- 无证书时：通过本地 SOCKS5 sidecar 做 ClientHello 分段、预置 IP、DoH 和可选上游中继。
- 支持按规则组启用，避免一次性对所有站点做 MITM。
- 私有仓库、带 `Authorization`/会话 Cookie/签名 URL 的请求，绝不进入公共镜像或第三方节点。
- 日志可诊断、可保留、可清理，且不记录敏感头。

非目标：

- 不保证绕过所有网络封锁。任何方案都依赖具体网络、IP 可达性和 DPI 行为。
- 不在 Android 上直接运行 Electron/Node 版 DevSidecar。
- 不承诺免证书场景下能做 URL 级镜像改写。
- 不承诺对启用证书固定（pinning）的应用做 MITM。

## 2. 结论摘要

| 能力 | 可行性 | 条件 |
|---|---|---|
| 解析 DevSidecar 配置并映射规则 | 可行 | 需要 JSON5 兼容解析；本项目已实现 |
| MITM + SNI 伪装 | 可行 | 客户端信任根证书；上游证书校验按当前实现放行 |
| 预置 IP + 延迟选路 | 可行 | 需要 DNS 干净或预置 IP 可用 |
| 镜像重定向（ghp.ci 等） | 可行 | 仅公开、无凭证请求；路径正则匹配 |
| 私有仓库直连/SNI 伪装 | 可行 | 不带凭证进镜像；MITM 下可转发 Cookie/Basic Auth |
| 请求/响应头替换 | 可行 | 需要 MITM；已支持 `[remove]` 语义 |
| 规则组选择 | 可行 | 按域名关键字归类，未选中的组不参与匹配 |
| 免证书 SNI 分片 | 条件可行 | 对只检查首包/前几个包的 DPI 有效；对会重组流的设备无效（实验室已验证） |
| 免证书 SNI 改写 | 仅实验 | 只有源站忽略 SNI 或返回原域名证书时才成立，不能通用 |
| DoH | 可行 | 只解决 DNS 污染，不解决 IP/SNI 阻断；已接入 sidecar |
| 可信中继 | 可行 | 需要节点；TLS 端到端，不需要证书；已支持 SOCKS5 上游中继 |
| 按应用分流 | 可行 | Android VpnService 支持 allowed/disallowed application |
| 对所有应用 MITM | 条件可行 | 需要系统 CA（通常 root）或应用主动信任用户 CA |
| 对 pinning 应用 MITM | 不可行 | 只能隧道/直连 |
| 在当前 Linux 沙箱构建 2.8.3 APK | 不可行 | 旧版 Xamarin.Android 需要 macOS/Windows |

## 3. DevSidecar 的实际机制

参考仓库：

- GUI/历史主仓：<https://github.com/docmirror/dev-sidecar>
- 内核：<https://github.com/Blue-Frontier/ds-core>
- 默认配置：<https://github.com/Blue-Frontier/ds-core/blob/main/core/src/config/remote_config.json5>
- SNI 拦截器：<https://github.com/Blue-Frontier/ds-core/blob/main/mitmproxy/src/lib/interceptor/impl/req/sni.js>
- overwall 中继插件：<https://github.com/Blue-Frontier/ds-core/blob/main/core/src/modules/plugin/overwall/config.js>

### 3.1 配置格式是 JSON5，不是 JSON

官方 `remote_config.json5` 使用未加引号的键、`//` 注释、尾随逗号，部分字段用单引号。直接交给 `System.Text.Json` 会在第一个字符处失败：

```text
'a' is an invalid start of a property name. Expected a '"'. LineNumber: 1
```

这会导致“规则启用成功但一条都不生效”。本项目新增 `Json5.ToJson` 规整器，只处理 DevSidecar 实际使用的 JSON5 子集，再交给 `System.Text.Json`。对 2026-11-03 版本配置的实测结果：

- 规则 69 条
- 排除域名 48 条
- 预置 IP 表 59 组

### 3.2 关键事实

1. DevSidecar 的 GitHub 直连加速是通过修改 SNI 实现的，思路来自 FastGithub；首次使用要求安装根证书。
2. 默认配置对 `github.com`、`api.github.com`、`*.githubusercontent.com` 等设置 `sni: "baidu.com"`。
3. 默认配置对 `*.huggingface.co` 设置 `sni: "huggingface.cn"`、`verifyHost: "huggingface.cn"`。
4. Pixiv（P站）图片域名 `*.pixiv.org`、`*.pximg.net` 使用 `sni: "baidu.com"` + `unVerifySsl`；`i.pximg.net` 额外通过 `requestReplace.headers.referer` 伪造 Referer。
5. `server.preSetIpList.github.com` 提供一批 GitHub IP，避免 DNS 污染并按测速选择。
6. `github.com` 只有 release/archive 路径会重定向到镜像；普通网页、API、私有仓库请求走 MITM + 真实 GitHub + SNI 伪装。
7. `proxy.excludeIpList` 排除镜像、上传、Windows 证书等域名，避免二次代理；配置中 `null`/`false` 表示从排除列表移除，只有 `true` 表示排除。
8. `plugin.overwall` 是可选中的外部中继，默认关闭，需要服务器和口令。
9. 许可证为 MPL-2.0：仅消费配置数据并独立实现解析器风险较低。

结论：**DevSidecar 的“私有仓库正常”不是因为镜像支持私有库，而是因为私有请求根本没有走镜像；它走 MITM + 真实 GitHub + SNI 伪装。** 这也解释了为什么必须装证书。

### 3.3 本项目支持的规则字段

| 字段 | 处理方式 |
|---|---|
| `sni` | MITM 时替换上游 ClientHello 的 SNI；`"none"` 表示删除 SNI 扩展 |
| `verifyHost` | 兼容解析；Titanium 当前默认放行上游证书 |
| `redirect` | 仅无凭证请求；支持 `{path}`、`{args}`、`${name}` 命名组 |
| `proxy` / `backup` | 连接第三方反代 IP；主目标失败后尝试备用目标 |
| `abort` | 直接终止会话 |
| `unVerifySsl` | 记录；Titanium 当前全局放行上游证书 |
| `requestReplace.headers` | 替换/删除上游请求头；`[remove]` 表示删除 |
| `responseReplace.headers` | 替换/删除返回给客户端的响应头 |
| `preSetIpList` | 按主机名匹配，多 IP 并行探测选最低延迟 |
| `excludeIpList` | 命中后直连/不代理 |
| `cacheDays` / `script` / `success` / `options` | 暂不执行，仅保留解析能力 |
| `overwall` | 只解析记录；由用户显式开启本项目自己的上游中继 |

同一主机名命中多条规则时会合并，而不是只取第一条。DevSidecar 本身会合并 `*.pximg.net` 的 SNI 与 `i.pximg.net` 的 Referer；只取首条会导致 P站图片规则失效。

## 4. Android 约束

### 4.1 用户证书

- Android 7.0（API 24）起，应用默认不信任用户安装的 CA；只有应用通过 Network Security Config 主动信任，或 CA 被安装到系统证书区（通常需要 root），才会被信任。
- 参考：<https://developer.android.com/training/articles/security-config>
- 因此：
  - 浏览器通常可以使用用户 CA；
  - 普通应用不一定；
  - 启用 pinning 的应用无法 MITM；
  - 若要让所有应用都走 MITM，系统 CA/root 或按应用分流是必须的。

### 4.2 VpnService 按应用分流

- `VpnService.Builder.addAllowedApplication` / `addDisallowedApplication` 可以限制哪些应用走 VPN。
- 参考：<https://developer.android.com/guide/topics/connectivity/vpn>
- 本项目已加入“增强模式仅浏览器走 VPN”实验开关，默认只包含常见浏览器包名；找不到浏览器时回退为全局。
- 注意：按应用分流只能决定“是否进入 VPN”，不能决定某个应用内某个域名是否 MITM。

### 4.3 QUIC / UDP

- 当前 tun2socks 链路以 TCP 为主。若应用使用 QUIC/HTTP3，而本地 SOCKS5 不支持 UDP ASSOCIATE，会出现“代理开启后部分应用异常”。
- 本地 sidecar 现在会对 UDP ASSOCIATE 返回 SOCKS5 `Command not supported (0x07)`，避免客户端无限等待。
- 处理方式：
  - 在 VPN 内阻断 UDP 443，迫使应用回退 TCP；
  - 或为 SOCKS5 sidecar 增加 UDP relay；
  - 或按应用排除使用 QUIC 的应用。

### 4.4 DoH / ECH

- DoH 只改变 DNS 解析方式（RFC 8484），不隐藏后续 TLS 的 SNI。
- 如果应用自己使用 DoH/DoT，DNS 拦截无效，但 TLS 的 SNI 仍然可以被隧道侧观察和分流。
- 如果启用 ECH，SNI 被加密，基于 SNI 的分流会失效；只能退回 IP 规则或整条隧道。

## 5. 协议与机制

### 5.1 SNI

- SNI 定义见 RFC 6066：<https://www.rfc-editor.org/rfc/rfc6066>
- SNI 分片/乱序：不改 SNI，只把 ClientHello 拆成多个 TCP 段发送，绕过只检查首包/前几包的 DPI。它不保证对所有设备有效，必须真机验证。
- SNI 改写（无 MITM）：直接改写 ClientHello 中的 SNI 字节。客户端仍然按原域名校验证书；只有源站忽略 SNI、或仍返回原域名证书时才成立，不能作为通用方案。
- SNI 伪装（MITM）：本地代理先以本地 CA 与客户端完成 TLS，再以伪装的 SNI 连接真实站点；客户端看到的是本地 CA 签发的原域名证书。DevSidecar 采用的就是这一条。

### 5.2 SNI 分片策略

本项目实现三种策略：

| 策略 | 行为 | 说明 |
|---|---|---|
| 固定大小 | 每 N 字节一个 TCP 段 | 最细，但段数多、开销大 |
| SNI 边界 | 在 SNI 主机名首字节处拆成三段 | 推荐；任何一段都不含完整域名 |
| TLS 记录头 | 拆 record header / handshake header | 最温和，强度较弱 |

ClientHello 可能跨多个 TCP 读事件到达。sidecar 会先按 TLS record 长度缓冲完整 ClientHello，再做改写/分片；解析失败则原样转发。

### 5.3 DoH/DoT

- DoH 定义见 RFC 8484：<https://www.rfc-editor.org/rfc/rfc8484>
- 作用：绕过 DNS 污染，拿到干净 IP。
- 局限：不解决 IP 黑洞、TCP RST、SNI 阻断；必须和多 IP/中继配合。
- 本项目默认使用 `https://dns.alidns.com/resolve`（JSON 接口），可改为 `https://dns.google/resolve`。DoH 失败后是否回退系统 DNS 可配置。

### 5.4 预置 IP 与多 IP 选路

- DevSidecar 的 `preSetIpList` 是经验 IP 列表。
- 本项目新增 `PresetIpSelector`：并行 TCP 探测、选最低延迟、缓存 5 分钟、失败回退 DoH/系统 DNS。
- 免证书 sidecar 还会读取内置加速组里已启用项目的 `ForwardDomainIP`，因此不启用 DevSidecar 规则也能对 GitHub/Pixiv 使用预置 IP。
- 仍不能保证 IP 可用；需要定期更新列表或从干净 DNS 获取。

### 5.5 中继

- 可信 SOCKS5 中继是免证书场景下最可靠的 IP/SNI 阻断绕过方式。
- TLS 仍然端到端；中继看不到 `Authorization`/`Cookie`。
- 本项目 sidecar 支持 SOCKS5 上游中继，支持无认证和用户名/密码认证。排除列表内的域名不会走中继。

## 6. 本项目架构

### 6.1 两种模式

**增强模式（有证书）**

```text
App -> VPN/tun2socks -> Titanium SOCKS5 -> MITM
    -> 规则引擎（域名/路径/组）
    -> SNI 伪装 / 镜像重定向 / 反代 / 请求头替换 / 预置 IP
    -> 真实站点或公开镜像
```

**免证书模式（无证书）**

```text
App -> VPN/tun2socks -> SNI sidecar SOCKS5
    -> ClientHello 分段（可选改写）
    -> 预置 IP / DoH / 上游 SOCKS5 中继
    -> 直连或可信中继
```

**VPN 出口选择**：只有“免证书模式”或“根证书未安装”时，VPN 才把流量交给 sidecar；有证书时仍走 Titanium，否则 DevSidecar 的 MITM 规则不会生效。

### 6.2 规则匹配顺序

1. `proxy.excludeIpList`：命中则直连/不代理。
2. 带凭证请求：
   - `Redirect` / 第三方 `proxy` / `ServerAccelerate`：跳过，直连或同源 SNI。
   - 同源 `sni` / `Local` / 预置 IP / 请求头替换：允许。
3. 路径规则优先于 `.*`；同一主机名命中多条规则时合并。
4. 域名匹配：精确、通配符、DevSidecar 正则/混合写法。
5. 动作：`Block` → `Redirect` → `Proxy` → `Sni/VerifyHost` → `PresetIps` → 请求/响应头。

### 6.3 规则组

DevSidecar 没有组的概念，本项目按域名关键字归类：

| 组 ID | 名称 | 默认 |
|---|---|---|
| `github` | GitHub | 开 |
| `huggingface` | Hugging Face | 开 |
| `pixiv` | Pixiv / P站 | 开 |
| `google` | Google | 关 |
| `youtube` | YouTube | 关 |
| `wikipedia` | Wikipedia | 关 |
| `docker` | Docker Hub | 关 |
| `reddit` | Reddit | 关 |
| `steam` | Steam 社区 | 关 |
| `other` | 其它站点 | 关 |

未选中的组不会参与匹配，也不会使用该组的预置 IP。设置页支持全选/仅默认组。

### 6.4 内置加速组

不依赖远程规则也能使用：

- **GitHub SNI 加速**：网页、API、Gist、静态资源、头像、Raw、Release Assets、用户图片、Media/LFS。
- **Hugging Face SNI 镜像**：主站、`cdn-lfs*`，上游 `huggingface.cn`。
- **Pixiv / P站 SNI 加速**：`i.pximg.net`、`s.pximg.net`、`a.pixiv.org`、`www.fanbox.cc`、`api.fanbox.cc`，SNI 伪装为 `baidu.com`；图片请求自动补 `Referer: https://www.pixiv.net/`。

### 6.5 当前代码对应

| 模块 | 文件 |
|---|---|
| JSON5 规整 | `src/ST.Client/Services/Rules/Json5.cs` |
| 规则模型/匹配/合并 | `src/ST.Client/Services/Rules/ProxyRule.cs` |
| 规则组归类 | `src/ST.Client/Services/Rules/ProxyRuleGroups.cs` |
| DevSidecar 配置解析 | `src/ST.Client/Services/Rules/DevSidecarConfigLoader.cs` |
| 规则引擎入口/组过滤 | `src/ST.Client/Services/Rules/ProxyRuleEngine.cs` |
| 预置 IP 选路 | `src/ST.Client/Services/Implementation/PresetIpSelector.cs` |
| DoH 解析 | `src/ST.Client/Services/Implementation/DohResolver.cs` |
| SNI sidecar | `src/ST.Client/Services/Implementation/Sni/SniFragmentSocks5Server.cs` |
| SNI 运行统计 | `src/ST.Client/Services/Implementation/Sni/SniSidecarStats.cs` |
| SNI 自测 | `src/ST.Client/Services/Implementation/Sni/SniConnectivityTester.cs` |
| TLS ClientHello | `src/ST.Client/Services/Implementation/Sni/TlsClientHello.cs` |
| 诊断日志 | `src/ST.Client/Services/Implementation/ProxyDiagnostics.cs` |
| 内置加速组 | `src/ST.Client/Services/Implementation/BuiltInAccelerateProjects.cs` |
| Titanium 接入 | `src/ST.Client.ReverseProxy.Titanium/TitaniumReverseProxyServiceImpl.cs` |
| VPN 出口选择 | `src/ST.Client.Android/Services/Shadowsocks/VpnService.cs` |
| 实验设置页 | `src/ST.Client.Android/UI/Activities/ExperimentalSettingsActivity.cs` |
| 实验设置项 | `src/ST.Client/Settings/ProxySettings.cs` |

## 7. 安全模型

1. **凭证不进第三方**：`Authorization`、GitHub 会话 Cookie、签名 URL 命中时，跳过镜像和第三方反代；同源 SNI/IP 伪装仍可用。
2. **远端配置是信任边界**：只允许 HTTPS；缓存后使用；解析失败回退缓存/空规则；不自动启用 `overwall` 中继。
3. **日志脱敏**：不记录 `Authorization`/`Cookie`/请求体；查询参数中的 token/sig/jwt/password 等替换为 `***`；可关闭主机名记录。
4. **MITM 的固有风险**：本地代理能看到明文。免证书模式不终止 TLS，隐私更好；增强模式应优先只给浏览器或用户信任的应用。
5. **许可证**：DevSidecar 为 MPL-2.0。消费配置数据、独立实现解析与执行逻辑，风险较低；如果复制源码文件，需要保留 MPL 声明并遵守文件级 copyleft。

## 8. 可行性验证

### 8.1 已完成的自动化验证

规则解析/TLS 单元测试（Linux + .NET 8 独立测试工程）：

- JSON5：注释、未加引号键、单引号、尾随逗号、字符串内 `//`。
- 官方配置：69 条规则、48 条排除、59 组预置 IP 全部解析成功。
- 规则命中：GitHub SNI、Hugging Face `verifyHost`、Pixiv Referer、jsDelivr `backup`、Google `${pre}` 命名组。
- 域名匹配：通配符、精确匹配、混合 `(*account*|scholar)`、负向前瞻、IPv6。
- ClientHello：解析 SNI、加长/缩短改写、删除扩展、record/handshake 长度一致。
- 分片：固定大小、SNI 边界、TLS 记录头三种策略重组后与原始字节完全一致；SNI 边界三段均不含完整主机名。
- 仓库内 NUnit 测试 6 项全部通过；独立 sidecar 端到端测试 3 种策略握手全部成功。

### 8.2 SNI 分片实验室结果

测试方法：本机 Python TLS 服务器 + 模拟 DPI 的 TCP 代理。DPI 有两种模式：

1. **first-packet**：只检查客户端连接的第一个 TCP 段，包含被阻断域名就断开。
2. **reassembling**：等待 150ms，把客户端发来的所有字节重组成流后再检查。

使用 Python `ssl.MemoryBIO` 生成真实 TLS 1.3 ClientHello（517 字节，SNI 偏移 127），分别用不同策略发送：

| 策略 | first-packet DPI | reassembling DPI | TLS 握手 |
|---|---|---|---|
| 不分片 | 被阻断 | 被阻断 | 失败 |
| SNI 边界（3 段） | 通过 | 被阻断 | 成功 / 失败 |
| 固定 64B | 通过 | 被阻断 | 成功 / 失败 |
| 固定 2B | 通过 | 被阻断 | 成功 / 失败 |
| TLS 记录头（5+4+rest） | 通过 | 被阻断 | 成功 / 失败 |

结论：

- SNI 分片对“只看首包/前几包”的 DPI 有效，且 TLS 握手可以正常完成。
- 对“会等一小段时间重组 TCP 流”的 DPI 完全无效。
- 因此不能把 SNI 分片宣传为通用绕过方案；它只是一个低成本、可开关的尝试项。真正稳定的是可信中继。

### 8.3 真机验证计划

| 场景 | 模拟方式 | 期望 |
|---|---|---|
| DNS 污染 | hosts/错误 DNS | 预置 IP/DoH 可恢复 |
| SNI 阻断 | 本地 DPI/iptables 规则 | SNI 分片或中继可恢复 |
| IP 黑洞 | 丢弃目标 IP | 多 IP 选路/中继可恢复 |
| 慢链路 | 限速/高延迟 | 预置 IP 选路降低 TTFB |
| 私有库 | GitHub 私有仓库 | 不经过镜像，Auth/Cookie 正常 |
| 公开 release | GitHub release | 可走镜像，Range/签名参数保留 |
| HF 公开/私有 | 公开模型 + gated 模型 | 公开走镜像，私有直连 |
| P站图片 | `i.pximg.net` | MITM + Referer 后可加载 |
| QUIC 应用 | 视频/社交应用 | 阻断 UDP 443 后应回退 TCP |

设备覆盖：

- Android 7/10/14 各一台（覆盖用户 CA 策略差异）。
- 浏览器：Chrome、Firefox、Edge、国产浏览器。
- 应用：Git 客户端、GitHub App、Hugging Face 客户端、Pixiv 客户端、普通银行/DRM 应用（验证不被误伤）。
- 证书：用户 CA、系统 CA（root）、未安装证书三种状态。

### 8.4 应用内自测

实验设置页提供“测试 SNI 分片是否有效”：

1. 直连目标域名做 TLS 握手（忽略证书校验，只测连通性）。
2. 通过本地 sidecar 做同样的握手。
3. 输出成功/失败、耗时、当前策略、DoH/中继状态和运行统计。

判读：

- 直连失败 + sidecar 成功：当前策略很可能有效。
- 两者都失败：IP 不可达、TLS 被重置，或分片不足以绕过当前 DPI；尝试预置 IP、DoH、中继。
- 两者都成功：当前网络没有阻断该目标，无法据此判断分片效果。

### 8.5 成功指标

- 私有仓库访问成功率 ≥ 99%（网络可达时）。
- 凭证泄露测试：镜像/第三方节点日志中不出现 `Authorization`/Cookie。
- 免证书模式开启后，未匹配应用的联网成功率不下降。
- 日志可定位每次规则命中/跳过原因。
- 崩溃率、ANR 不高于基线。

## 9. 设置项说明

实验设置页按组保存，修改后建议停止并重新启动加速：

- **规则组**：GitHub / Hugging Face / Pixiv / Google / YouTube / Wikipedia / Docker / Reddit / Steam / 其它。
- **免证书模式**：VPN 出口切换为 sidecar。
- **SNI 分片**：开关、策略、生效域名、仅 TLS、固定大小、间隔、最大缓冲、读取超时。
- **SNI 改写**：开关、目标域名（`none` 表示删除 SNI）、允许改写的域名。
- **Sidecar 端口**：仅监听 127.0.0.1。
- **上游 SOCKS5 中继**：地址、端口、用户名、密码。
- **DoH**：开关、JSON 接口、失败是否回退系统 DNS。
- **VPN**：增强模式仅浏览器走 VPN。
- **日志**：开关、最低级别、是否保留主机名、保留天数、单文件上限、清理与查看目录。
- **恢复默认值**：只重置实验设置，不修改代理端口/二级代理。

## 10. 已知缺口与路线图

1. **UDP/QUIC**：sidecar 已明确拒绝 UDP ASSOCIATE，但尚未在 VPN 内阻断 UDP 443 或做 UDP relay。
2. **按应用分流 UI**：目前是常见浏览器包名硬编码 + 开关，尚未做应用选择器。
3. **缓存**：`cacheDays` 只解析不执行；GitHub raw 图片/脚本缓存尚未实现。
4. **脚本/油猴**：`script`/`tampermonkeyScript` 只解析不执行。
5. **`success`/`options`**：DevSidecar 的本地假响应和 OPTIONS 处理尚未完整实现。
6. **规则更新签名**：远端配置只做 HTTPS/缓存，尚未做签名校验和回滚策略。
7. **构建/真机验证**：当前 Linux 沙箱无 Android SDK/Xamarin.Android 12，需要在 macOS/Windows 或 CI 完成。
8. **SNI 分片对抗升级**：当前实现只对抗首包 DPI；对重组型 DPI 只能依赖中继。

## 11. 参考资料

- DevSidecar：<https://github.com/docmirror/dev-sidecar>
- DevSidecar 内核：<https://github.com/Blue-Frontier/ds-core>
- 默认远程配置：<https://github.com/Blue-Frontier/ds-core/blob/main/core/src/config/remote_config.json5>
- SNI 拦截器：<https://github.com/Blue-Frontier/ds-core/blob/main/mitmproxy/src/lib/interceptor/impl/req/sni.js>
- overwall 插件：<https://github.com/Blue-Frontier/ds-core/blob/main/core/src/modules/plugin/overwall/config.js>
- FastGithub：<https://github.com/dotnetcore/FastGithub>
- Android VpnService：<https://developer.android.com/guide/topics/connectivity/vpn>
- Android Network Security Config：<https://developer.android.com/training/articles/security-config>
- RFC 6066（TLS SNI）：<https://www.rfc-editor.org/rfc/rfc6066>
- RFC 8484（DoH）：<https://www.rfc-editor.org/rfc/rfc8484>
- MPL-2.0：<https://www.mozilla.org/en-US/MPL/2.0/>
- ByeDPI（SNI 分片/desync 参考实现）：<https://github.com/hufrea/byedpi>
- GoodbyeDPI（DPI 绕过参考）：<https://github.com/ValdikSS/GoodbyeDPI>
