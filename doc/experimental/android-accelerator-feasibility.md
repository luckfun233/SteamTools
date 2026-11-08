# Android 加速器可行性、架构与验证计划

> 状态：实验设计稿
> 基线：`experiment/android-certless-ip`
> 目标：在 Android 上复用 DevSidecar 规则，支持有证书 MITM 和免证书隧道两条路径，并明确哪些能力可行、哪些不可行。

## 1. 目标与边界

目标：

- 复用 DevSidecar 的声明式规则（域名、路径、SNI、镜像、预置 IP、排除列表）。
- 有证书时：MITM + SNI 伪装 + 镜像/反代，覆盖 GitHub、Hugging Face 等公开资源。
- 无证书时：通过本地 SOCKS5 sidecar 做 SNI 分片、实验性 SNI 改写、DoH/中继（后两项为后续）。
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
| 解析 DevSidecar 配置并映射规则 | 可行 | 只实现代理相关子集；不执行它的 Node 脚本 |
| MITM + SNI 伪装 | 可行 | 客户端信任根证书；上游证书校验按当前实现放行 |
| 预置 IP + 延迟选路 | 可行 | 需要 DNS 干净或预置 IP 可用 |
| 镜像重定向（ghp.ci 等） | 可行 | 仅公开、无凭证请求；路径正则匹配 |
| 私有仓库直连/SNI 伪装 | 可行 | 不带凭证进镜像；MITM 下可转发 Cookie/Basic Auth |
| 免证书 SNI 分片 | 条件可行 | 对只检查首包的 DPI 有效；对会重组流的设备无效 |
| 免证书 SNI 改写 | 仅实验 | 只有源站忽略 SNI 或返回原域名证书时才成立，不能通用 |
| DoH/DoT | 可行 | 只解决 DNS 污染，不解决 IP/SNI 阻断 |
| 可信中继 | 可行 | 需要节点；TLS 端到端，不需要证书 |
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

关键事实：

1. DevSidecar 的 README 明确写了 GitHub 直连加速是“通过修改 SNI 实现”，思路来自 FastGithub；首次使用要求安装根证书。
2. 默认配置对 `github.com`、`api.github.com`、`*.githubusercontent.com` 等设置 `sni: "baidu.com"`。
3. 默认配置对 `*.huggingface.co` 设置 `sni: "huggingface.cn"`、`verifyHost: "huggingface.cn"`。
4. `server.preSetIpList.github.com` 提供一批 GitHub IP，避免 DNS 污染并按测速选择。
5. `github.com` 只有 release/archive 路径重定向到 `ghp.ci/https://github.com`；普通网页、API、私有仓库请求不走镜像。
6. `proxy.excludeIpList` 排除镜像、上传、Windows 证书等域名，避免二次代理。
7. `plugin.overwall` 是可选中的外部中继，默认关闭，需要服务器和口令。
8. 许可证为 MPL-2.0：如果复制/修改它的源码文件，需要遵守 MPL；仅消费配置数据并实现独立解析器风险更低。

结论：**DevSidecar 的“私有仓库正常”不是因为镜像支持私有库，而是因为私有请求根本没有走镜像；它走 MITM + 真实 GitHub + SNI 伪装。** 这也解释了为什么必须装证书。

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
- SNI 分片/乱序：不改 SNI，只把 ClientHello 拆成多个 TCP 段发送，绕过只检查首包的 DPI。它不保证对所有设备有效，必须真机验证。
- SNI 改写（无 MITM）：直接改写 ClientHello 中的 SNI 字节。客户端仍然按原域名校验证书；只有源站忽略 SNI、或仍返回原域名证书时才成立，不能作为通用方案。
- SNI 伪装（MITM）：本地代理先以本地 CA 与客户端完成 TLS，再以伪装的 SNI 连接真实站点；客户端看到的是本地 CA 签发的原域名证书。DevSidecar 采用的就是这一条。

### 5.2 DoH/DoT

- DoH 定义见 RFC 8484：<https://www.rfc-editor.org/rfc/rfc8484>
- 作用：绕过 DNS 污染，拿到干净 IP。
- 局限：不解决 IP 黑洞、TCP RST、SNI 阻断；必须和多 IP/中继配合。

### 5.3 预置 IP 与多 IP 选路

- DevSidecar 的 `preSetIpList` 是经验 IP 列表。
- 本项目新增 `PresetIpSelector`：并行 TCP 探测、选最低延迟、缓存 5 分钟、失败回退。
- 仍不能保证 IP 可用；需要定期更新列表或从干净 DNS 获取。

### 5.4 中继

- 可信 SOCKS5/TCP 中继是免证书场景下最可靠的 IP/SNI 阻断绕过方式。
- TLS 仍然端到端；中继看不到 `Authorization`/`Cookie`。
- DevSidecar 的 `overwall` 插件就是这一类，默认关闭。

## 6. 本项目架构

### 6.1 两种模式

**增强模式（有证书）**

```text
App -> VPN/tun2socks -> 本地 SOCKS5/HTTP 代理
    -> Titanium MITM
    -> 规则引擎（域名/路径）
    -> SNI 伪装 / 镜像重定向 / 反代 / 预置 IP
    -> 真实站点或公开镜像
```

**兼容模式（无证书）**

```text
App -> VPN/tun2socks -> SNI sidecar SOCKS5
    -> TLS ClientHello 分片（可选改写）
    -> DoH/预置 IP（后续）
    -> 直连或可信中继
```

两种模式不要同时期望生效：sidecar 运行时它会接管 VPN 的 SOCKS 出口，Titanium 的 MITM/镜像规则不会同时应用。

### 6.2 规则匹配顺序

1. `proxy.excludeIpList`：命中则直连/不代理。
2. 带凭证请求：
   - `Redirect` / 第三方 `proxy` / `ServerAccelerate`：跳过，直连或同源 SNI。
   - 同源 `sni` / `Local` / 预置 IP：允许。
3. 路径规则优先于 `.*`。
4. 域名匹配：精确、通配符、DevSidecar 正则。
5. 动作：`Block` → `Redirect` → `Proxy` → `Sni/VerifyHost` → `PresetIps`。

### 6.3 当前代码对应

| 模块 | 文件 |
|---|---|
| 规则模型/匹配 | `src/ST.Client/Services/Rules/ProxyRule.cs` |
| DevSidecar 配置解析 | `src/ST.Client/Services/Rules/DevSidecarConfigLoader.cs` |
| 规则引擎入口 | `src/ST.Client/Services/Rules/ProxyRuleEngine.cs` |
| 预置 IP 选路 | `src/ST.Client/Services/Implementation/PresetIpSelector.cs` |
| SNI sidecar | `src/ST.Client/Services/Implementation/Sni/SniFragmentSocks5Server.cs` |
| TLS ClientHello | `src/ST.Client/Services/Implementation/Sni/TlsClientHello.cs` |
| 诊断日志 | `src/ST.Client/Services/Implementation/ProxyDiagnostics.cs` |
| Titanium 接入 | `src/ST.Client.ReverseProxy.Titanium/TitaniumReverseProxyServiceImpl.cs` |
| 实验设置 | `src/ST.Client.Android/UI/Activities/ExperimentalSettingsActivity.cs` |

## 7. 安全模型

1. **凭证不进第三方**：`Authorization`、GitHub 会话 Cookie、签名 URL 命中时，跳过镜像和第三方反代；同源 SNI/IP 伪装仍可用。
2. **远端配置是信任边界**：只允许 HTTPS；缓存后使用；解析失败回退缓存/空规则；不自动启用 `overwall` 中继。
3. **日志脱敏**：不记录 `Authorization`/`Cookie`/请求体；查询参数中的 token/sig/jwt/password 等替换为 `***`。
4. **MITM 的固有风险**：本地代理能看到明文。免证书模式不终止 TLS，隐私更好；增强模式应优先只给浏览器或用户信任的应用。
5. **许可证**：DevSidecar 为 MPL-2.0。消费配置数据、独立实现解析与执行逻辑，风险较低；如果复制源码文件，需要保留 MPL 声明并遵守文件级 copyleft。

## 8. 可行性验证计划

### 8.1 编译与静态检查

- 在 macOS/Windows + Xamarin.Android 12.0 环境构建 Debug APK。
- 对 `TlsClientHello`、`DomainPatternMatcher`、`DevSidecarConfigLoader` 增加单元测试：
  - 解析真实 ClientHello（Chrome/Firefox/okhttp）；
  - SNI 改写后长度字段正确；
  - 分片重组后字节完全一致；
  - 通配符/正则/路径规则命中。
- 用 DevSidecar 官方 `remote_config.json5` 做解析回归，确认不抛异常。

### 8.2 实验室网络场景

| 场景 | 模拟方式 | 期望 |
|---|---|---|
| DNS 污染 | hosts/错误 DNS | 预置 IP/DoH 可恢复 |
| SNI 阻断 | 本地 DPI/iptables 规则 | SNI 分片或中继可恢复 |
| IP 黑洞 | 丢弃目标 IP | 多 IP 选路/中继可恢复 |
| 慢链路 | 限速/高延迟 | 预置 IP 选路降低 TTFB |
| 私有库 | GitHub 私有仓库 | 不经过镜像，Auth/Cookie 正常 |
| 公开 release | GitHub release | 可走镜像，Range/签名参数保留 |
| HF 公开/私有 | 公开模型 + gated 模型 | 公开走镜像，私有直连 |
| QUIC 应用 | 视频/社交应用 | 阻断 UDP 443 后应回退 TCP |

### 8.3 设备覆盖

- Android 7/10/14 各一台（覆盖用户 CA 策略差异）。
- 浏览器：Chrome、Firefox、Edge、国产浏览器。
- 应用：Git 客户端、GitHub App、Hugging Face 客户端、普通银行/DRM 应用（验证不被误伤）。
- 证书：用户 CA、系统 CA（root）、未安装证书三种状态。

### 8.4 成功指标

- 私有仓库访问成功率 ≥ 99%（网络可达时）。
- 凭证泄露测试：镜像/第三方节点日志中不出现 `Authorization`/Cookie。
- 免证书模式开启后，未匹配应用的联网成功率不下降。
- 日志可定位每次规则命中/跳过原因。
- 崩溃率、ANR 不高于基线。

## 9. 已知缺口与路线图

1. **DoH/DoT 解析器**：当前只保留设置/架构，尚未接入 sidecar 和 Titanium。
2. **可信中继**：`overwall` 只解析记录，未自动启用；sidecar 尚未实现上游 SOCKS5 中继。
3. **路径级镜像**：依赖 DevSidecar 规则启用；内置 GitHub 组本身没有 release/archive 路径规则。
4. **UDP/QUIC**：尚未在 VPN 内阻断 UDP 443 或做 UDP relay。
5. **按应用分流 UI**：目前是常见浏览器包名硬编码 + 开关，尚未做应用选择器。
6. **构建/真机验证**：当前沙箱无 Android SDK，需在 macOS/Windows 或 CI 完成。
7. **规则更新签名**：远端配置只做 HTTPS/缓存，尚未做签名校验和回滚策略。

## 10. 参考资料

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
