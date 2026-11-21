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

本项目实现六种策略：

| 策略 | 行为 | 适用场景 |
|---|---|---|
| 固定大小 | 每 N 字节一个 TCP 段 | 兼容选项，段数多、开销大 |
| SNI 边界 | 在 SNI 主机名首字节处拆成三段 | 通用；任何一段都不含完整域名 |
| TLS 记录头 | 拆 record header / handshake header | 兼容选项，强度较弱 |
| SNI 多段 | 把域名拆成 2~8 段 | 域名较长、首段 DPI 检查时更稳 |
| TLS record 拆分 | 重新封装成多个合法 TLS record，并让 SNI 跨 record | 对“重组 TCP 但逐 record 检查”的 DPI 有效 |
| 随机分片 | 随机大小 TCP 段 | 降低固定长度指纹 |

ClientHello 可能跨多个 TCP 读事件到达。sidecar 会先按 TLS record 长度缓冲完整 ClientHello，再做改写/分片；解析失败则原样转发。TLS record 拆分不是简单切片，而是重新写 record 头；接收端会按 TLS 规范跨 record 重组 handshake。

### 5.3 其他绕过方式对比

| 方式 | 本项目可行性 | 能解决什么 | 主要限制 |
|---|---|---|---|
| TCP 分段 | 已实现 | 只检查首包/前几包的 DPI | 会重组 TCP 的 DPI 无效 |
| TLS record 拆分 | 已实现 | 重组 TCP、逐 record 检查的 DPI | 会重组 handshake 的 DPI 无效 |
| SNI 改写 | 已实现（实验） | 个别忽略 SNI 的源站 | 证书校验通常失败，不通用 |
| SNI 伪装（MITM） | 已实现 | 基于 SNI 的阻断 | 需要根证书；pinning 应用不可用 |
| 镜像/反代 | 已实现 | 公开资源下载 | 不能接触凭证；依赖第三方可用性 |
| 预置 IP / DoH | 已实现 | DNS 污染、部分 IP 黑洞 | 不解决 SNI/IP 封锁 |
| 可信 SOCKS5 中继 | 已实现 | IP/SNI 阻断，最稳 | 需要节点；速度取决于节点 |
| 按应用分流 | 已实现 | 避免误伤不信任证书的应用 | 只能决定是否进 VPN |
| ECH | 不可由本代理强制 | 加密整个 ClientHello | 需要客户端与服务端都支持 ECH；代理无法替应用发起 |
| 域前置（domain fronting） | 不可用 | 借 CDN 隐藏目标 | 需要服务端/CDN 配合，主流 CDN 已限制 |
| TTL 伪造 / 假包 / 乱序 / 序列重叠 | 不可用 | 对抗更复杂的 DPI | 需要 raw socket / NFQUEUE / root；VpnService 用户态 TCP 无法直接改包 |
| QUIC / HTTP3 中继 | 未实现 | 部分应用的 UDP 流量 | 当前 sidecar 不支持 UDP ASSOCIATE，需要 UDP relay |

结论：在非 root Android 上，应用层能稳定做到的是 **TLS record 拆分 + 延迟抖动 + 自动回退 + 中继**。TTL/假包/乱序属于需要 root 或内核转发的方案，不适合放进当前 VpnService 架构。

### 5.3.1 SNI 分片稳定性实验（2026-11）

测试方法：本机 TLS 1.3 服务器 + 可编程 TCP 代理模拟四种 DPI：

1. `first`：只检查连接的第一个 TCP 段。
2. `tcp`：等待 150ms，重组客户端 TCP 流后检查。
3. `record`：重组 TCP 后逐 TLS record 检查 payload。
4. `handshake`：重组 TLS record 后再拼接 handshake 检查。

ClientHello 517 字节，SNI 偏移 127。分片之间间隔 20ms（模拟 sidecar 默认行为）。

| 策略 | first | tcp | record | handshake |
|---|---|---|---|---|
| 不分片 | 阻断 | 阻断 | 阻断 | 阻断 |
| SNI 边界（TCP 3 段） | 通过 | 阻断 | 阻断 | 阻断 |
| SNI 多段（3 段） | 通过 | 阻断 | 阻断 | 阻断 |
| 固定 64B | 通过 | 阻断 | 阻断 | 阻断 |
| TLS 记录头 | 通过 | 阻断 | 阻断 | 阻断 |
| **TLS record @SNI** | **通过** | **通过** | **通过** | 阻断 |
| **TLS record 64B** | **通过** | **通过** | **通过** | 阻断 |
| 随机 32B | 通过 | 阻断 | 阻断 | 阻断 |

延迟与重组窗口（TCP 重组 DPI，窗口 150ms）：

| 分片间隔 | 结果 |
|---|---|
| 0ms | 阻断 |
| 10ms | 阻断 |
| 50ms | 阻断 |
| 100ms | 阻断 |
| 200ms | 通过（但每次握手额外增加约 400ms） |

分片不友好中间设备 + 自动回退：

| 场景 | 结果 |
|---|---|
| 不分片 | 成功 |
| 分片、无回退 | 失败 |
| 分片失败后重连不分片 | 成功 |

随机分片：20 次随机 16~96B 分片，对 first-packet DPI 成功 20/20。

结论：

- TCP 分段只能对抗首包 DPI；一旦 DPI 重组 TCP 就失效。
- TLS record 拆分能同时通过 first / tcp / record 三种模拟，是目前最强的免证书应用层方案。
- 任何应用层分片都无法对抗会重组 handshake 的 DPI；这类网络只能依赖可信中继。
- 把分片间隔调到 200ms 可以跨过 150ms 的重组窗口，但延迟代价明显；默认 10ms 更实用。
- 自动回退对“分片被中间设备丢弃”的网络有效，应默认开启。

### 5.4 DoH/DoT

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
- 本项目 sidecar 支持 SOCKS5 上游中继，支持无认证和用户名/密码认证。排除列表内的域名不会走中继；还可以用“中继生效域名”限制只有指定域名走中继。

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

### 6.5 自定义规则（与远程规则合并）

自定义规则保存在应用数据目录的 `DevSidecar/custom_rules.json`，格式与 DevSidecar 相同，但可以省略 `server` 包装，也允许 JSON5 注释、单引号和尾随逗号：

```json5
{
  intercepts: {
    "example.com": {
      ".*": { sni: "baidu.com", desc: "示例" }
    },
    "downloads.example.com": {
      "^/(repo|release)/.*": {
        redirect: "https://ghp.ci/https://downloads.example.com"
      }
    }
  },
  preSetIpList: {
    "example.com": ["1.2.3.4", "5.6.7.8"]
  },
  excludeIpList: {
    "*.local": true
  }
}
```

合并规则：

1. 自定义规则优先于远程规则，同域名/同路径时先命中自定义。
2. 远程规则仍按规则组过滤；自定义规则不受远程组开关影响，只受“启用自定义规则”总开关控制。
3. 排除列表取并集；预置 IP 同键时自定义覆盖远程。
4. 自定义规则支持 `sni`、`verifyHost`、`redirect`、`proxy`、`backup`、`abort`、`desc`、`requestReplace.headers`、`responseReplace.headers`。
5. 保存前会先解析校验，失败不会覆盖现有文件；保存成功后立即生效，无需重启代理。

设置页提供两种编辑方式：

- 文本编辑器：直接粘贴完整 DevSidecar 规则，支持校验、复制、插入示例、清空。
- 快速添加/删除：按域名、路径、动作和值生成规则，再回写到编辑器，避免手写 JSON 结构。

### 6.6 当前代码对应

| 模块 | 文件 |
|---|---|
| JSON5 规整 | `src/ST.Client/Services/Rules/Json5.cs` |
| 规则模型/匹配/合并 | `src/ST.Client/Services/Rules/ProxyRule.cs` |
| 规则组归类 | `src/ST.Client/Services/Rules/ProxyRuleGroups.cs` |
| 自定义规则存储/序列化 | `src/ST.Client/Services/Rules/CustomProxyRules.cs` |
| DevSidecar 配置解析 | `src/ST.Client/Services/Rules/DevSidecarConfigLoader.cs` |
| 规则引擎入口/组过滤/合并 | `src/ST.Client/Services/Rules/ProxyRuleEngine.cs` |
| 预置 IP 选路 | `src/ST.Client/Services/Implementation/PresetIpSelector.cs` |
| DoH 解析 | `src/ST.Client/Services/Implementation/DohResolver.cs` |
| SNI sidecar | `src/ST.Client/Services/Implementation/Sni/SniFragmentSocks5Server.cs` |
| SNI 运行统计/回退缓存 | `src/ST.Client/Services/Implementation/Sni/SniSidecarStats.cs` |
| SNI 自测/策略矩阵 | `src/ST.Client/Services/Implementation/Sni/SniConnectivityTester.cs` |
| TLS ClientHello/record 拆分 | `src/ST.Client/Services/Implementation/Sni/TlsClientHello.cs` |
| 实验室测试/报告 | `src/ST.Client/Services/Implementation/AcceleratorLabService.cs` |
| 诊断日志 | `src/ST.Client/Services/Implementation/ProxyDiagnostics.cs` |
| 内置加速组 | `src/ST.Client/Services/Implementation/BuiltInAccelerateProjects.cs` |
| Titanium 接入 | `src/ST.Client.ReverseProxy.Titanium/TitaniumReverseProxyServiceImpl.cs` |
| VPN 出口选择 | `src/ST.Client.Android/Services/Shadowsocks/VpnService.cs` |
| 实验设置页 | `src/ST.Client.Android/UI/Activities/ExperimentalSettingsActivity.cs` |
| 自定义规则页 | `src/ST.Client.Android/UI/Activities/CustomRulesActivity.cs` |
| 加速实验室页 | `src/ST.Client.Android/UI/Activities/AcceleratorLabActivity.cs` |
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
- 分片：固定大小、SNI 边界、TLS 记录头、SNI 多段、TLS record 拆分、随机分片；可重组的策略重组后与原始字节完全一致，SNI 相关策略各段均不含完整主机名。
- 自定义规则：简化/完整格式解析、分组标记、预置 IP/排除合并、优先级覆盖、序列化往返。
- 仓库内 NUnit 测试 11 项全部通过；独立 sidecar 端到端测试 6 种策略握手全部成功，并验证了分片失败后的自动回退重连。

### 8.2 SNI 分片实验室结果

测试方法：本机 Python TLS 1.3 服务器 + 可编程 TCP 代理模拟四种 DPI：

1. `first`：只检查客户端连接的第一个 TCP 段。
2. `tcp`：等待 150ms，重组客户端 TCP 流后检查。
3. `record`：重组 TCP 后逐 TLS record 检查 payload。
4. `handshake`：重组 TLS record 后再拼接 handshake 检查。

ClientHello 517 字节，SNI 偏移 127，分片间隔 20ms：

| 策略 | first | tcp | record | handshake |
|---|---|---|---|---|
| 不分片 | 阻断 | 阻断 | 阻断 | 阻断 |
| SNI 边界（TCP 3 段） | 通过 | 阻断 | 阻断 | 阻断 |
| SNI 多段（3 段） | 通过 | 阻断 | 阻断 | 阻断 |
| 固定 64B | 通过 | 阻断 | 阻断 | 阻断 |
| TLS 记录头 | 通过 | 阻断 | 阻断 | 阻断 |
| **TLS record @SNI** | **通过** | **通过** | **通过** | 阻断 |
| **TLS record 64B** | **通过** | **通过** | **通过** | 阻断 |
| 随机分片 | 通过 | 阻断 | 阻断 | 阻断 |

延迟与重组窗口（TCP 重组 DPI，窗口 150ms）：

| 分片间隔 | 结果 |
|---|---|
| 0 / 10 / 50 / 100ms | 阻断 |
| 200ms | 通过（每次握手额外约 400ms） |

分片不友好中间设备 + 自动回退：

| 场景 | 结果 |
|---|---|
| 不分片 | 成功 |
| 分片、无回退 | 失败 |
| 分片失败后重连不分片 | 成功 |

随机分片：20 次随机 16~96B 分片，对 first-packet DPI 成功 20/20。

结论：

- TCP 分段只能对抗首包/前几包 DPI；一旦 DPI 重组 TCP 就失效。
- TLS record 拆分能同时通过 first / tcp / record 三种模拟，是目前最强的免证书应用层方案。
- 任何应用层分片都无法对抗会重组 handshake 的 DPI；这类网络只能依赖可信中继。
- 把分片间隔调到 200ms 可以跨过 150ms 的重组窗口，但延迟代价明显；默认 10ms 更实用。
- 自动回退对“分片被中间设备丢弃”的网络有效，应默认开启。

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

### 8.4 应用内实验室

实验设置页提供两个入口：

**SNI 快速自测**：输入域名，分别做直连 TLS 和 sidecar TLS 握手，输出结果、耗时、当前策略、DoH/中继状态和运行统计。

**加速实验室**（`AcceleratorLabActivity`）把只能在真机上验证的项目集中到一次运行：

1. 规则集：自定义/远程/排除/预置 IP 数量与错误。
2. 当前设置快照。
3. 系统 DNS 解析。
4. DoH 解析（启用时）。
5. TCP 443 连接。
6. 直连 TLS 握手。
7. Sidecar TLS 握手（当前策略）。
8. Titanium 代理 HTTP（读取 `github.com/robots.txt`，信任本地根证书）。
9. UDP 443 探测（仅证明本机可发出 UDP，不能判定是否被阻断）。
10. 根证书与设备信息（厂商/型号/Android 版本/ABI/VPN 授权）。

额外功能：

- **分片策略矩阵**：依次运行 SNI 边界、SNI 多段、TLS record 拆分、固定大小、TLS 记录头、随机分片，每种重复 1~10 次，输出成功次数、中位耗时和最后错误。
- **报告导出**：通过系统文件选择器（SAF）导出为 `.txt`，无需存储权限；内容包含设备信息、设置快照、测试结果、运行统计、回退域名和最近诊断日志。
- **复制报告**：直接写入剪贴板，方便在手机上贴到聊天工具。
- **清空统计**：同时清空运行统计和分片失败回退缓存。

判读：

- 直连失败 + Sidecar 成功：当前策略/预置 IP/中继很可能有效；关闭分片复测可进一步区分。
- 两者都失败：IP 不可达、TLS 被重置，或分片不足以绕过当前 DPI；尝试预置 IP、DoH、中继。
- 两者都成功：当前网络没有阻断该目标，无法据此判断分片效果。
- 策略矩阵全部成功：通常说明网络未阻断；部分成功说明策略不稳定。

### 8.5 成功指标

- 私有仓库访问成功率 ≥ 99%（网络可达时）。
- 凭证泄露测试：镜像/第三方节点日志中不出现 `Authorization`/Cookie。
- 免证书模式开启后，未匹配应用的联网成功率不下降。
- 日志可定位每次规则命中/跳过原因。
- 崩溃率、ANR 不高于基线。

## 9. 设置项说明

实验设置页按组保存，修改后建议停止并重新启动加速：

- **规则组 / 服务分组**：分组名直接读取 `remote_config.json5` 的 `//` 注释（与 DevSidecar 2.3.x 一致），默认全部开启；支持按组开关、按单个域名开关，以及包含 / 正则 / 匹配域名三种搜索。
- **自定义规则**：启用开关、管理页（文本编辑、校验、快速添加、删除、示例、复制、清空），与远程规则合并且优先匹配。
- **免证书模式**：VPN 出口切换为 sidecar。
- **SNI 分片**：开关、七种策略、生效域名、仅 TLS、分片大小、SNI 多段数、间隔、随机抖动、最大缓冲、读取超时。
  - 默认策略改为 **TLS record 拆分**：重封装成多个 TLS record，SNI 跨 record，可绕过“重组 TCP 但按 record 解析”的 DPI。
  - 新增 **TLS record 随机拆分**：在 SNI 内部强制切一刀，其余切点随机，降低固定三段指纹。
- **分片自动回退**：开关、首字节探测超时、跳过分片缓存分钟数。
- **SNI 改写**：开关、目标域名（`none` 表示删除 SNI）、允许改写的域名。
- **Sidecar 端口**：仅监听 127.0.0.1；被占用时自动向后寻找端口。
- **上游 SOCKS5 中继**：地址、端口、生效域名、用户名、密码。
- **DoH / DNS**：
  - DoH JSON 接口（sidecar 选路解析）。
  - DoH wire 接口（本地 DNS 代理转发完整 DNS 报文）。
  - DevSidecar `dns.mapping`：按域名选择配置里的 HTTPS DoH provider；`tls://` DoT provider 当前跳过并回退默认 DoH。
  - 本地 DNS 代理开关、端口、回退 DNS 服务器列表。
  - VPN 通过 `tun2socks --dnsgw 127.0.0.1:<port>` 把 UDP:53 送到本地 DNS 代理，不再依赖 SOCKS5 UDP ASSOCIATE。
- **VPN**：增强模式仅浏览器走 VPN。
- **日志**：开关、最低级别、是否保留主机名、保留天数、单文件上限、清理与查看目录。
- **加速实验室**：一键测试、分片策略矩阵、DNS / UDP 检查、规则匹配、导出/复制报告、清空统计。
- **恢复默认值**：只重置实验设置，不修改代理端口/二级代理。

## 10. 已知缺口与路线图

1. **UDP/QUIC**：sidecar 已实现 SOCKS5 UDP ASSOCIATE（DNS 优先走 DoH，其它 UDP 直接转发）；QUIC 仍可能受运营商 UDP 策略影响。
2. **按应用分流 UI**：目前是常见浏览器包名硬编码 + 开关，尚未做应用选择器。
3. **缓存**：`cacheDays` 只解析不执行；GitHub raw 图片/脚本缓存尚未实现。
4. **脚本/油猴**：`script`/`tampermonkeyScript` 只解析不执行。
5. **`success`/`options`**：DevSidecar 的本地假响应和 OPTIONS 处理尚未完整实现。
6. **规则更新签名**：远端配置只做 HTTPS/大小限制/缓存，尚未做签名校验和回滚策略。
7. **分片对抗上限**：TLS record 拆分能对抗逐 record 检查的 DPI；会完整重组 TLS handshake 的 DPI 只能依赖中继。
8. **需要 root 的方案**：TTL 伪造、假包、乱序、TCP 序列重叠需要 raw socket / NFQUEUE / 内核转发，当前 VpnService 用户态架构不实现。
9. **ECH**：无法由代理替应用发起；需要客户端与服务端协商 ECH。
10. **自定义规则的执行范围**：只执行代理相关子集，不支持 DevSidecar 的 Node 脚本、`cacheDays`、`success`/`options`。
11. **策略矩阵的判定局限**：如果当前网络没有阻断目标，所有策略都会成功，矩阵无法证明分片有效；需要在不阻断/阻断两种网络下对比。
12. **DoH 引导**：本地 DNS 代理使用域名访问 DoH 服务，首次解析仍依赖系统 DNS；后续可加入 DoH 服务器 IP 引导。

## 11. 本次 Linux 实测记录（2026-11）

环境：.NET SDK 6.0.428、`dotnet workload install android`（32.0.509）、JDK 11、Android SDK `platforms;android-31` + `build-tools;32.0.0`、Linux x64。

已实际运行并通过的测试：

| 测试 | 结果 | 说明 |
|---|---|---|
| `TlsClientHelloTest`（6 项） | 通过 | 解析/改写/删除 SNI；固定、SNI 边界、SNI 多段、记录头、TLS record、TLS record 随机拆分均可无损重组 |
| `DevSidecarConfigTest`（6 项） | 通过 | 注释分组、`dns.mapping`、`whiteList`、`excludeIpList`、按组/服务过滤、通配符/正则匹配、ReDoS 超时保护 |
| `Parse_Real_Remote_Config_When_Available` | 通过 | 使用官方 `remote_config.json5` 实测：解析出 69 条可执行规则、预置 IP、GitHub/Pixiv/DockerHub 等注释分组 |
| `DohWire_Query_Real_Network` | 通过 | 通过 `https://dns.alidns.com/dns-query` 实际解析 `github.com`，返回 NOERROR |
| `DnsProxy_Uses_Doh_When_Enabled` | 通过 | 本地 DNS 代理走真实 DoH，返回 A 记录 |
| `DnsProxy_Forwards_To_Fallback_Server` | 通过 | DoH 关闭时回退到指定 DNS，返回 A 记录 |
| `SniSidecar_TlsRecordSplit_Handshake_Succeeds` | 通过 | 本地自签 TLS 服务端 + SOCKS5 只传 IP；sidecar 从 ClientHello 识别 SNI，TLS record 拆分后握手成功 |
| APK Release 构建 | 通过 | `dotnet build ... -f net6.0-android -p:AndroidPackageFormat=apk` 产出 70MB universal APK |

> 说明：以上是 Linux 环境下的自动化/本地回环实测，不等价于在所有运营商网络上的真机验证；真机仍需在“会阻断 SNI”的网络下对比直连、分片和中继三种路径。


## 12. 第二轮真机反馈修正（2026-11-18）

真机实验室报告暴露的问题与处理：

1. **Hugging Face 仍然打不开**
   - 官方远程配置里 `*.huggingface.co` 的规则是 `sni: huggingface.cn` + `verifyHost: huggingface.cn`，这需要 MITM/根证书；免证书模式无法改写 SNI 后通过证书校验。桌面端之所以“100% 能用”，是因为它在 MITM 层同时改写 SNI/Host 并用自己的证书答复客户端。
   - 官方 `preSetIpList` 里有 `3.167.200.113`，但原来的 VPN 只把 IP 交给 sidecar，预置 IP 没有被 DNS 使用；而且浏览器可能开启 Private DNS/DoH，完全绕过本地 DNS 代理。
   - 修复：
     - 本地 DNS 代理把 `preSetIpList` 直接写进 A/AAAA 响应；
     - sidecar 改为 **先回 SOCKS 成功、再读 ClientHello、再连目标**，因此即使目标 IP 被黑洞、DNS 被绕过，也能从 SNI 认出域名并改用预置 IP；
     - Hugging Face 额外提供 CloudFront 兜底 IP；
     - 设置页新增“允许 UDP / HTTP/3（QUIC）”开关。
   - 仍不承诺所有网络可用：如果预置 IP 也被封、或 DPI 会完整重组 TLS handshake，免证书模式无法像桌面 MITM 一样保证 100%，只能走中继或 HTTP/3。

2. **远端规则“看起来太少”**
   - 旧实现只把带 `sni`/`proxy`/`redirect`/头替换/abort 的规则计入分组，所以只有 69 条、25 组。
   - 现在额外收集 `intercepts` 里所有域名、`preSetIpList`、`dns.mapping`、`whiteList`、`dns.ech.domains`、`dns.nat64.domains`、`familyMapping`、`overwall.targets`，形成完整服务目录；实测 **30 组 / 174 个服务**。服务分组页面会展示所有组和服务，即使该服务当前没有可执行的 MITM 规则。

3. **客户端错误 1006 / 加速页空白**
   - `api/Accelerate/All` 需要登录，未登录或返回非 MessagePack 时会反复抛 `ClientException`（1006），加速页图标和列表都加载失败。
   - 修复：Android 端不再请求该接口，加速页改为显示 DevSidecar 规则摘要和“管理/搜索规则组”入口；脚本基础接口也关闭了错误弹窗。

4. **设置项过多**
   - 主界面只保留总开关、策略、域名和自动回退；分片参数、SNI 改写、DoH 细节、中继、日志细节收进“高级”折叠区。
   - DoH 与本地 DNS 代理合并成一个“安全 DNS”开关。

5. **日志不好导出**
   - 实验设置页新增“导出日志”（系统文件选择器，可保存到下载/网盘）和“分享日志”（分享文本）。

### 其他 SNI/DPI 绕过路线筛选

| 路线 | 免证书 | 可行性 | 结论 |
|---|---|---|---|
| TCP 分段 / SNI 边界拆分 | 是 | 只对不重组 TCP 的 DPI 有效 | 保留为兼容策略 |
| TLS record 拆分 / 随机 record 拆分 | 是 | 对按 record 解析的 DPI 有效 | 默认策略 |
| DoH + 预置 IP 覆盖 | 是 | 解决 DNS 污染和 IP 黑洞 | 已实现，GitHub/HF 的关键 |
| SOCKS5 上游中继 | 是 | 最可靠，但依赖用户有可用代理 | 已实现 |
| HTTP/3 / QUIC（UDP 443） | 是 | 绕过 TCP SNI DPI，取决于运营商 UDP 策略 | UDP ASSOCIATE 已支持 |
| SNI 改写 / 镜像 / Host 改写 | 否（需 MITM） | 需要根证书 | 仅证书模式 |
| ECH | 是 | 需要客户端/服务端支持，Android 13 不可控 | 不实现 |
| 假包 / TTL / 乱序 / TCP 序列重叠（GoodbyeDPI、Zapret、ByeDPI） | 是 | 需要 raw socket/NFQUEUE/root | 当前 VpnService 用户态不可行 |

## 13. 第三轮真机日志分析（2026-11-19）

用户网络下 GitHub 已基本可用，但 Hugging Face 仍然失败。新日志（`1watt-lab-20261119-220640/220727`、`1watt-logs-20261119-221252/221627`）显示：

- 预置 IP 已生效：sidecar 实际连接 `3.167.200.113 / 18.155.129.x`，TCP 可连通。
- TLS record 分片已生效：`分片: huggingface.co:443 策略=TlsRecordSplit 段数=3`，但约 44ms 后立即 `分片握手被重置`。
- 结论：该网络的 DPI 能重组 TCP 流和普通 TLS record，单纯 record 拆分不足以绕过 Hugging Face 的 SNI 黑名单。
- `DoH` 走 AliDNS 时返回 `210.56.51.193`，系统 DNS 返回 `128.242.245.29` 和 Facebook IPv6 `2a03:2880:...`，均是被污染结果；而 `doh.pub` 实测返回真实 CloudFront 地址（`3.168.178.x` / `2600:9000:2751:...`）。
- 证书模式启动时报 `Failed to make system trust root certificate ... Access is denied.`：Titanium 尝试写 Windows 证书存储，Android 上必然失败。

### 本轮新增

1. **Tiny record 脉冲（策略 7）**
   把 ClientHello 拆成几十到上百个 1~64 字节的小 TLS record，SNI 内部逐字节一条 record，并在发送之间加入少量延迟。服务端会按 TLS 规范重组；只按 record 或固定窗口解析的 DPI 看不到完整域名。

2. **ClientHello 填充（策略 8，RFC 7685）**
   在 SNI 扩展之前插入 4KB（可调）padding，把域名推到 DPI 的检查窗口之外。部分 DPI 只解析 ClientHello 前 N 字节，这种策略对它们有效，且完全合法。

3. **失败自动升级 + 策略记忆**
   当前策略被重置时，自动依次尝试 TinyRecords、Padding；成功后按域名记住，后续连接直接用。全部失败才回退到不分片，并写入 10 分钟跳过缓存。

4. **Hugging Face IPv6 兜底**
   增加 CloudFront IPv6 预置地址（`2600:9000:2751:...`），同时写入 AAAA 响应，避免继续使用被污染的 Facebook IPv6。若 IPv6 也不可达，连接竞速会自动退回 IPv4。

5. **DoH 默认改为 doh.pub**
   AliDNS 在用户网络下对 HF 返回污染结果；doh.pub 的 JSON/wire 接口都返回真实 CloudFront 地址。迁移版本 3 只替换仍是旧默认值的 DoH 地址，不覆盖用户自定义。

6. **持久 UDP flow（QUIC/HTTP3）**
   UDP ASSOCIATE 从“每个数据报新建 socket、等 3 秒”改为按目标端点维护长连接和接收循环，空闲 90 秒回收，最多 128 条 flow。这样 QUIC 握手和后续流才可能完成。QUIC 的 SNI 在 TLS 1.3 握手中加密，绕过的是只看 TCP ClientHello 的 DPI；前提是运营商不阻断 UDP/443。

7. **证书模式完善**
   - Android 不再调用 Titanium 的 Windows 证书存储 API，避免 `Access is denied`。
   - 新增 Android `TrustRootCertificate` 实现，打开内置 `GuideCACertActivity`（导出 .cer + 系统安全设置）。
   - 实验设置页增加“证书模式（MITM）”卡片和安装引导。
   - 说明限制：Chrome/Firefox 一般信任用户 CA；Android 7+ 普通应用默认不信任用户 CA。
   - 这是复刻 DevSidecar `sni: huggingface.cn + verifyHost` 的唯一可靠方式。

8. **实验室增加 HF 专项**
   - 同一 IP 分别用 `cloudfront.net` 和 `huggingface.co` 做 SNI，判断阻断依据是 SNI 还是 IP/路由。
   - 直接测试 CloudFront IPv6。
   - 分片策略矩阵加入 TinyRecords / Padding，可一键比较成功率。

### 仍未解决

- 如果 DPI 完整重组 TCP + TLS record，并且对 ClientHello 做全文匹配，免证书模式下任何分片/填充都无效；只能靠证书模式 MITM、上游中继或 IPv6/QUIC 绕路。
- Android 13 的普通应用不信任用户 CA，证书模式主要对浏览器生效。
- raw socket 级方案（伪造包、TTL、TCP 序列重叠、OOB）需要 root/VpnService 之外的底层能力，当前用户态实现无法使用。

## 14. 依赖漏洞扫描（2026-11-19）

使用 `dotnet list tests/ST.Client.UnitTest/ST.Client.UnitTest.csproj package --vulnerable --include-transitive` 扫描 net6.0 依赖图。

已升级：

| 包 | 原版本 | 新版本 | 说明 |
|---|---|---|---|
| System.Text.Json | 6.0.2 | 6.0.10 | 修复反序列化 DoS 等公告 |
| Microsoft.Extensions.Caching.Memory | 6.0.1 | 6.0.2 | 修复 DoS 公告 |
| System.Drawing.Common | 4.7.0（传递） | 6.0.1 | CVE-2021-24112（Critical，GDI+ RCE）；测试项目显式覆盖 |
| MessagePack | 2.4.59 | 2.5.303 | 修复 13 条 DoS/递归公告 |
| SkiaSharp / NativeAssets.Linux | 2.88.3 | 2.88.9 | 修复 libwebp CVE-2023-4863 对应公告 |
| SharpZipLib | 1.4.1 | 1.4.2 | 最新稳定版 |
| SQLitePCLRaw.bundle_green | 2.1.3 | 2.1.11 | 当前最新；GHSA-2m69-gcr7-jv3q 尚无修复版本 |

仍存在、已评估：

- **SQLitePCLRaw.lib.e_sqlite3 2.1.11（High）**：上游 SQLite 漏洞，2.1.11 已是当前最新，暂无修复版本。仅影响本地 SQLite 数据库文件解析，不处理网络输入。
- **AutoMapper 12.0.0（High）**：公告为不受控递归 DoS，仅在映射恶意构造的对象图时触发；升级到 15.x 需要同时迁移 `AutoMapper.Extensions.Microsoft.DependencyInjection`，风险高于收益，暂缓。
- **AngleSharp 0.17.1（Moderate）**：来自 ArchiSteamFarm（`EXCLUDE_ASF`，Android 包不包含），仅桌面 ASF 使用；升级到 1.5.0 会破坏 `AngleSharp.XPath 2.0.1`。

## 15. 启动闪退与 Android 13 证书安装（2026-11-20）

### 启动闪退

上一版 APK 是 `Debug` 构建。.NET Android 在 Debug 下默认启用 Fast Deployment，
程序集不嵌进 APK，而是由 IDE 通过 `adb` 推送。直接 sideload 时 APK 里没有程序集，
启动就会立刻闪退。

修复：

- `ST.Client.Android.App.Modern.csproj` 固定 `EmbedAssembliesIntoApk=true` 和
  `AndroidFastDeploymentType=None`。
- 新增 `AndroidCrashLogger`，未处理异常写入：
  `Android/data/net.steampp.app/files/last-crash.txt`，同时写 `logcat` tag `SteamToolsCrash`。
- 设置页“VPN 与诊断日志”里新增“上次崩溃日志”入口。
- GitHub Actions 只构建 Release APK，避免再次产出 Debug Fast Deployment 包。

### Android 13 安装证书的可行路径

| 方式 | 权限要求 | 证书位置 | Chrome | 普通 App（targetSdk 24+） |
|---|---|---|---|---|
| 系统设置手动导入 | 无 | 用户 CA | 信任 | 默认不信任 |
| `KeyChain` 安装 Intent | 无（需用户确认） | 用户 CA | 信任 | 默认不信任 |
| 设备所有者 + `DevicePolicyManager.installCaCert` | Shizuku/ADB 执行 `dpm set-device-owner` | 用户 CA | 信任 | 默认不信任 |
| 写入 `/system/etc/security/cacerts` | root（remount /system） | 系统 CA | 信任 | 信任 |

关键结论：

- **Shizuku 只有 shell UID，不是 root**。Android 10+ 的 `/system` 是只读 + dm-verity，
  `mount -o rw,remount /system` 和 `adb remount` 都需要 root 或关闭验证启动，
  Shizuku 无法完成系统 CA 写入。
- 设备所有者可以**静默安装用户 CA**，不需要用户点确认，但仍不是系统 CA。
  设置设备所有者要求设备上没有账号，且取消通常需要恢复出厂设置，风险较高。
- 应用已内置 `SteamToolsDeviceAdminReceiver` 和“复制 Shizuku 命令”按钮：
  `rish -c "dpm set-device-owner net.steampp.app/.SteamToolsDeviceAdminReceiver"`。
  设置成功后，证书页面会显示“设备所有者: 是”，可直接静默安装用户 CA。
- 如果目标 App 使用 `networkSecurityConfig` 且没有 `<certificates src="user"/>`，
  用户 CA 不会被信任；这需要改目标 App 或 root 装系统 CA，VPN 层无法绕过。

### 其他开源项目调研

| 项目 | 平台 | 是否需要 root | 可借鉴点 |
|---|---|---|---|
| ByeDPI / ByeDPIAndroid | 桌面/Android | 否（Android 走 VPN + 原生 ciadpi） | TCP split、disorder、OOB、fake、TTL；比 C# 分片更底层 |
| GoodbyeDPI | Windows | 否 | TCP 分片、Host 头混淆、TTL 伪装 |
| Zapret 2 | Linux | 通常需要 NFQUEUE/root | multisplit、seqovl、fake、TTL |
| SpoofDPI / GreenTunnel | 桌面 | 否 | 首字节拆分、TLS record 拆分 |
| hf-mirror | Web | 否 | Hugging Face 镜像，适合下载模型，不是透明代理 |

本轮已把 ByeDPIAndroid 使用的 `libbyedpi.so` 作为可选 sidecar 接入，详见下一节。
仍未直接使用原版 ciadpi 源码自行交叉编译；当前使用的是 ByeDPIAndroid 官方 release
内的预编译二进制（MIT），并在启动失败时自动回退。

## 16. ByeDPI 原生内核接入（2026-11-21）

C# 的 TLS record/TinyRecords/Padding 都只能改“已经进入 .NET 的字节流”。如果 DPI 完整重组
TCP + TLS，C# 层没有更多手段。本轮把 ByeDPI（MIT）作为最后一层回退接入：

- 内置 `libbyedpi.so`（arm64-v8a / armeabi-v7a / x86_64，来自 ByeDPIAndroid v1.2.0 官方 release，
  上游 https://github.com/hufrea/byedpi，MIT）。
- 通过 `AndroidNativeLibrary` 打包，`android:extractNativeLibs="true"` 确保运行时能从
  `ApplicationInfo.NativeLibraryDir` 执行。
- 只在 `huggingface.co / *.huggingface.co / hf.co / *.hf.co` 等配置域名上启用，
  并且仅在 TinyRecords、Padding 都被重置后才启动，避免影响其它站点。
- 启动后监听 `127.0.0.1:<8871+>`；C# sidecar 用 SOCKS5 把目标 IP 和 ClientHello 交给它，
  ByeDPI 负责 disorder/tlsrec/fake/oob/split/TTL 等原生去同步。
- 预设：
  - Disorder + TLS record：`--disorder 1 --tlsrec 1+s`
  - Fake SNI + TTL：`--fake -1 --ttl 8 --tls-sni www.iana.org`
  - OOB：`--oob 1+s`
  - Split：`--split 1+s`
  - Auto：`--auto torst --tlsrec 1+s`
  - 自定义
- 启动失败、端口被占用、二进制缺失时返回 false，自动继续原来的“不分片重试”，不会阻断网络。
- 实验室新增“ByeDPI 内核”检查，显示是否运行、端口和生效域名；日志 tag 为 `ByeDPI`。

安全边界：只监听 127.0.0.1，不接受外部连接；不修改系统设置；不请求 root。
ByeDPI 的 `--fake`/TTL 等参数在不同运营商效果不同，需要配合实验室逐项尝试。

## 17. VPN 出口重构与卡死修复（2026-11-21 第四轮日志）

11:19 日志暴露了两个独立问题：

1. **证书模式把全部 VPN 流量交给了 Titanium**：Titanium 的 SOCKS5 只解析端口和目标
   ClientHello，非 TLS/二进制/UDP 流量会进入 HTTP 解析器，产生大量
   `Invalid HTTP request line`。客户端反复重连后形成正反馈，CPU、线程池和日志 IO
   一起被打满，表现为“开始时卡死、实验室点不动、返回键无响应”。
2. **停止代理时同步阻塞 UI 线程**：`ProxyService` 的启动/停止在 MainThreadScheduler 上
   同步执行，Titanium 清理会话、等待上游 DNS 时会把主线程卡住；日志里“已停止”之后
   10 秒仍在处理旧会话。

本轮改法：

- VPN 出口固定为本地 SNI sidecar（它本来就支持非 TLS 原样转发和 UDP ASSOCIATE）。
- 证书模式下，sidecar 只把 `DomainRequiresMitm` 或 Hugging Face 域名通过 SOCKS5
  转发给 Titanium；其余流量继续走分片直连。Titanium 不再接触二进制/UDP。
- 启动/停止 Titanium 用 `Task.Run` 移出 UI 线程。
- sidecar 的每个连接统一捕获异常；Titanium 的客户端异常日志按 10 秒窗口限流
  （最多 20 条），避免 `File.AppendAllText` 级联拖慢。
- sidecar 的“识别域名/直连”日志只对分片域名输出，普通网页不再逐连接落盘。
- 实验室的分片策略对比进入 `BenchmarkMode`：禁用学习策略、回退缓存和自动升级，
  每个策略都是独立测试，结束后按成功率和延迟排序。
- 实验室新增“证书模式链路”：显示证书文件、强制模式、Titanium SOCKS5 是否监听，
  并通过 Titanium 对 `huggingface.co` 做一次 TLS 握手，报告 MITM 证书 issuer。

## 18. 参考资料
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
- GreenTunnel（TCP split 与 `--tls-records` 记录拆分）：<https://www.npmjs.com/package/green-tunnel>
- Zapret 2 去同步文档（multisplit、seqovl、fake、TTL）：<https://wiki.zapret.moe/Zapret2/desync/>
- SpoofDPI（首字节拆分实践）：<https://salehgnutux.github.io/GT-NEWSTECH/en/foss/spoofdpi-anti-censorship-tool/>
- ECH 与 SNI 阻断 2026 指南：<https://vpn.how/en/pages/ech-and-sni-blocking-in-2026-the-complete-guide-to-setup-and-dpi-circumvention.html>
- Android 17 平台 ECH 支持：<https://www.engadget.com/2245189/google-deploys-support-encrypted-client-hello-on-android-17/>
