# 加速器技术路线（自建包 / Linux）

## 1. 背景

上游 Watt Toolkit 的加速链路是：

```text
应用/浏览器 -> 系统代理 -> Steam++.Accelerator（本地反代进程）
            -> YARP + 本地根证书 MITM
            -> 按加速项目（AccelerateProjectDTO）决定出口
```

加速项目由服务端 `Accelerate.All()` 下发，客户端只负责执行。因此自建包一旦拿不到服务端数据，加速页就是空的——这是本分支要解决的核心问题，而不是“再写一个 Linux 版”。

## 2. 加速项目的语义

现代版使用 `ProxyType`（`BD.WTTS.Primitives/Enums/Accelerator/ProxyType.cs`）：

| ProxyType | 行为 | SNI | 需要证书 |
|---|---|---|---|
| `Local` | 连接原站或 `ForwardDomainNames` 指定的 IP/主机 | 可被 `FakeServerName` 伪装 | 是（MITM） |
| `Redirect` | 把请求改写到 `ForwardDomainNames`（镜像） | 跟随镜像 | 是 |
| `ServerAccelerate` | 转到 `ForwardDomainNames` 指定的反代服务 | 可伪装 | 是 |
| `DirectSuccess` / `DirectFailure` | 直接成功/失败（拦截） | — | 是 |

关键字段：

- `MatchDomainNames`：匹配域名，分号分隔。
- `ForwardDomainNames`：转发目标；`Local` 下可以是 IP，也可以是主机名。
- `FakeServerName`：映射到 YARP 的 `TlsSniPattern`，即“伪装 SNI”。
- `IgnoreSSLCertVerification`：映射到 `TlsIgnoreNameMismatch`，关闭**上游**证书域名校验。
- `ListenDomainNames`：监听域名（Hosts 语义）。

结论：**SNI 篡改（伪装）不需要新协议栈，YARP 已经支持**，只要在加速项目里填 `FakeServerName`。

## 3. 两条 SNI 相关路径

### 3.1 增强路径：MITM + SNI 伪装（本次使用）

```text
客户端 --TLS(证书=本地CA签发的 github.com)--> 本地反代
本地反代 --TLS(SNI=baidu.com, Host=github.com)--> GitHub
```

- 客户端看到的是本地根证书签发的真实域名证书，所以浏览器/信任用户 CA 的应用不会报错。
- 上游用伪装 SNI，绕过只看 SNI 的 DPI。
- `IgnoreSSLCertVerification = true` 是必要的：上游证书域名与伪装 SNI 不一致。
- 私有仓库的 `Authorization` / Cookie 由本地反代转发给真实 GitHub，不经过任何镜像。

### 3.2 兼容路径：免证书（Android sidecar，不在本仓库）

免证书时无法做 MITM，只能：

- **SNI 分片**：不改 SNI，把 ClientHello 拆成多个 TCP 段，绕过只看首包的 DPI（ByeDPI / GoodbyeDPI 思路）。
- **DoH/DoT**：只解决 DNS 污染，不解决 IP 黑洞 / SNI 阻断。
- **可信中继**：TCP 层转发，TLS 端到端，仍不需要证书。
- **直接改写 SNI**：只有源站忽略 SNI、或仍返回原域名证书时才成立，不能通用。

这部分实现在老的 Android 分支（`experiment/android-certless-ip`），本 Linux 桌面分支不包含，也不应该被混入。桌面版的“免证书”等价物是关闭 MITM、只走系统代理隧道。

## 4. DevSidecar 规则映射

DevSidecar 的默认配置：`https://ds-official-config.bestar.de5.net/remote_config.json5`

结构（简化）：

```json5
server: {
  preSetIpList: { "github.com": ["140.82.121.4", "..."] },
  intercepts: {
    "github.com": {
      ".*": { "sni": "baidu.com" }
    },
    "*.huggingface.co": {
      ".*": { "sni": "huggingface.cn", "verifyHost": "huggingface.cn" }
    }
  }
}
```

转换规则：

| DevSidecar | 本项目 | 说明 |
|---|---|---|
| `sni` | `FakeServerName` | 直接映射 |
| `verifyHost` | 无 | YARP 没有等价字段；上游校验统一用 `IgnoreSSLCertVerification` |
| `proxy` | `ProxyType.ServerAccelerate` + `ForwardDomainNames` | 只接受 HTTPS |
| `preSetIpList` | `Local` + 第一个可用 IP | 只取第一条，未做多 IP 竞速 |
| `proxy.excludeIpList` | 未转换 | 需要按请求域名跳过，属于后续工作 |
| 路径级 `redirect` | **不转换** | 整域重定向会把私有仓库送去镜像 |
| 正则域名 | **跳过** | YARP 域名匹配不支持正则 |
| `overwall` 中继 | 不转换 | 第三方中继默认不启用 |
| 脚本注入 / 请求响应替换 | 不转换 | 与加速链路无关 |

## 5. 安全模型

1. **凭证不出站到第三方**：本分支不启用任何整域镜像或路径镜像，GitHub/HF 只做 SNI 伪装，流量终点仍是原站。
2. **远端配置是信任边界**：只允许 HTTPS；失败回退本地缓存；正则/路径规则直接跳过；不自动启用第三方中继。
3. **MITM 的固有风险**：本地反代能看到明文，这是装证书的代价。只对信任用户 CA 的应用有效；证书固定的应用无法 MITM。
4. **上游证书校验被关闭的范围**：仅限显式配置了 `IgnoreSSLCertVerification` 的加速项；其余域名仍然正常校验。
5. **许可证**：DevSidecar 为 MPL-2.0。本项目只消费它的配置数据并独立实现解析逻辑，不复制其源码文件。

## 6. 已知限制

- 没有多 IP 竞速：`preSetIpList` 只取第一条可用 IP。
- 没有 DoH/DoT 解析器。
- 没有 UDP/QUIC 处理：走 SOCKS5 UDP 或阻断 UDP 443 迫使回退 TCP（尚未实现）。
- 没有按应用分流（Linux 无 VpnService 概念）。
- 路径级镜像未实现；需要时应在反代里按“无凭证 + 具体路径”判断，而不是在域名规则里。
- Linux 上 DNS 拦截/WinDivert 不参与，只走系统代理。
- 本次改动未在当前环境编译验证。

## 7. 验证清单

1. 断网/改 hosts 让服务端接口失败，启动加速页 —— 应仍显示“GitHub（内置 SNI 加速）”和“Hugging Face（内置 SNI 加速）”。
2. 勾选 GitHub 组并启动加速 —— 浏览器访问 `https://github.com`，证书应为本地根证书签发，页面正常。
3. 访问私有仓库 —— 应正常登录/克隆，反代日志里不应出现镜像域名。
4. `git clone https://github.com/<public>/<repo>` —— 走 SNI 伪装直连。
5. 开启 DevSidecar 规则并刷新 —— 出现“DevSidecar 规则（远程同步）”组；断网后仍能从缓存加载。
6. 启动过程不再出现“非官方渠道”弹窗；通知列表里的同类公告不弹窗。
7. 关闭“启用内置加速组”后刷新 —— 内置组消失；重新开启后恢复。

## 8. 参考资料

- YARP（本项目反代实现）：<https://github.com/microsoft/reverse-proxy>
- FastGithub：<https://github.com/dotnetcore/FastGithub>
- DevSidecar：<https://github.com/docmirror/dev-sidecar>
- DevSidecar 内核：<https://github.com/Blue-Frontier/ds-core>
- RFC 6066（TLS SNI）：<https://www.rfc-editor.org/rfc/rfc6066>
- RFC 8484（DoH）：<https://www.rfc-editor.org/rfc/rfc8484>
- ByeDPI（SNI 分片参考）：<https://github.com/hufrea/byedpi>
