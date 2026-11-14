# NetAccel

从 SteamTools / Watt Toolkit 中抽离出来的**独立网络加速器**。只保留「代理 + 网络加速」这一块能力，去掉了 Steam 相关功能、账号体系、云服务与大量平台依赖，目标是做成一个可以直接运行、方便在 Linux 上构建和调试的桌面边车（sidecar）。

设计口径与 [`doc/experimental/android-accelerator-feasibility.md`](../doc/experimental/android-accelerator-feasibility.md) 保持一致：复用 DevSidecar 的声明式规则，在**不安装根证书**的前提下通过 SNI 分片、预置 IP、DoH 和上游 SOCKS5 中继完成加速。当前版本不包含 MITM/证书安装，因此不会执行镜像重定向和请求头改写，但会完整解析这些字段，避免规则“看起来启用了却完全不生效”。

## 功能

- **本地 SOCKS5 + HTTP 代理**：默认 `127.0.0.1:8868` / `127.0.0.1:8869`，支持 CONNECT 隧道与普通 HTTP 转发，附带 `/pac`。
- **DevSidecar 规则兼容**：JSON5 解析（注释、单引号、未加引号键、尾随逗号）、域名/路径匹配、规则组合并、排除列表、预置 IP。
- **规则组**：GitHub、Hugging Face、Pixiv、Google、YouTube、Wikipedia、Docker、Reddit、Steam、其它；未勾选的组不参与匹配。
- **自定义规则**：与远程规则合并且优先匹配；文本编辑器 + 快速添加（SNI 伪装 / 移除 SNI / 阻断 / 预置 IP / 直连排除）。
- **内置加速数据**：不依赖远程配置也会给 GitHub / Pixiv 使用常用预置 IP。
- **六种 SNI 分片策略**：固定大小、SNI 边界、TLS 记录头、SNI 多段、TLS record 拆分、随机分片；支持分片间隔、随机抖动、失败自动回退与域名缓存。
- **DoH**：JSON 接口（默认阿里 DoH），失败可回退系统 DNS；DoH 请求强制绕过系统代理，避免递归。
- **上游 SOCKS5 中继**：支持无认证与用户名/密码认证，可按域名限制生效范围。
- **加速实验室**：规则 / 设置 / 端口 / 系统 DNS / DoH / TCP / 直连 TLS / 代理 TLS / HTTP 代理 / UDP 环境检查，支持六种策略矩阵、复制与导出报告。
- **诊断日志**：按天归档、单文件上限、敏感参数脱敏、可隐藏主机名，不记录 Cookie / Authorization / 请求体。
- **系统代理**：Windows 注册表、GNOME gsettings、KDE、macOS networksetup；开启前保存原值，关闭应用时尽量恢复。

## 快速开始

需要 [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)。

```bash
cd NetAccel

# 1. 端到端自检（不依赖外网，验证 SOCKS5 / HTTP CONNECT 隧道）
dotnet run --project src/NetAccel.Cli -- selftest

# 2. 命令行启动代理
dotnet run --project src/NetAccel.Cli -- run

# 3. 桌面界面
dotnet run --project src/NetAccel.App

# 4. 运行测试
dotnet test tests/NetAccel.Core.Tests
```

命令行示例：

```bash
# 指定端口与分片策略
netaccel run --socks-port 7891 --http-port 7892 --strategy record-split

# 只测某个域名并输出实验室报告
netaccel check --host github.com

# 同步远程 DevSidecar 规则
netaccel sync

# 查看数据目录与当前设置
netaccel info
```

数据目录：

- Windows：`%APPDATA%\NetAccel`
- Linux：`~/.config/NetAccel`（可用 `NETACCEL_HOME` 或 `--data-dir` 覆盖）
- macOS：`~/Library/Application Support/NetAccel`

## 构建与打包（Linux 上完成）

```bash
cd NetAccel
chmod +x packaging/build.sh
./packaging/build.sh
```

脚本会依次：跑测试 → 发布 `linux-x64` 与 `win-x64` 的自包含版本 → 用发布后的 CLI 跑一遍自检 → 生成 `artifacts/*.tar.gz` 和 `artifacts/*.zip`。

也可以只构建一个目标：

```bash
TARGETS=linux-x64 ./packaging/build.sh
TARGETS=win-x64 VERSION=1.0.0 ./packaging/build.sh
```

> 发布方式刻意选择**非单文件、非裁剪**（`PublishSingleFile=false`、`PublishTrimmed=false`）。Avalonia 依赖 SkiaSharp/HarfBuzz 等原生库，单文件解压或裁剪是“双击就闪退”的常见原因。
>
> Windows 产物解压后直接运行 `NetAccel.exe`，无需安装 .NET 运行时，也不需要管理员权限（系统代理写入 HKCU）。

### 无显示器环境检查界面

```bash
dotnet run --project tools/NetAccel.UiPreview -- ./ui-preview
```

使用 `Avalonia.Headless + Skia` 真实渲染窗口，逐页输出截图并检查关键控件尺寸，不需要安装 Xvfb，适合 CI 和远程沙箱。

## 使用方式

1. 启动界面中的「加速」。
2. 让应用走代理：
   - 浏览器 / Git / 下载工具：SOCKS5 `127.0.0.1:8868` 或 HTTP `127.0.0.1:8869`。
   - 浏览器自动配置：`http://127.0.0.1:8869/pac`。
   - 系统代理：在设置中勾选「启动加速时自动设置系统代理」，关闭加速或退出应用会恢复原设置。
3. 在「规则」里选择站点组，或添加自定义规则。
4. 网络环境复杂时，打开「实验室」先看直连 / 代理 TLS 是否成功，再跑策略矩阵比较六种分片策略。

## 规则

支持与 DevSidecar 相同的 `intercepts` / `preSetIpList` / `excludeIpList` 结构，可以省略 `server` 包装：

```json5
{
  // 自定义规则优先于远程规则
  intercepts: {
    "example.com": {
      ".*": { sni: "baidu.com", desc: "SNI 伪装" },
    },
    // sni: "none" 表示移除 SNI 扩展
    "remove-sni.example.com": {
      ".*": { sni: "none" },
    },
    // abort 会在本地代理直接拒绝连接
    "ads.example.com": {
      ".*": { abort: true },
    },
  },
  preSetIpList: {
    "example.com": ["1.2.3.4", "5.6.7.8"],
  },
  excludeIpList: {
    "*.local": true,
  },
}
```

合并顺序（与文档一致）：

1. 自定义规则优先，远程规则按组过滤后补充；
2. 同一域名多条规则会合并，而不是只取第一条；
3. 排除列表取并集，预置 IP 同键时自定义覆盖远程；
4. 未选中的规则组及其预置 IP 不参与匹配；
5. 远程配置只接受 HTTPS，下载失败回退本地缓存。

免证书模式限制：

- `sni` / `sni: "none"` 会直接作用于 ClientHello；
- `preSetIpList`、`excludeIpList` 正常生效；
- `redirect`、`proxy`、`backup`、`requestReplace`、`responseReplace` 需要 MITM，本版本只解析不执行，也不会把请求交给第三方镜像。

## SNI 分片策略

| 策略 | 行为 | 说明 |
|---|---|---|
| 固定大小 | 每 N 字节一个 TCP 段 | 兼容选项，段数多 |
| SNI 边界 | 在 SNI 首字节处拆三段 | 默认，通用 |
| TLS 记录头 | 拆 record header / handshake header | 强度较弱 |
| SNI 多段 | 把域名拆成 2~8 段 | 长域名更稳 |
| TLS record 拆分 | 重新封装成多个合法 TLS record，让 SNI 跨 record | 最强，可过逐 record 检查 |
| 随机分片 | 随机大小 TCP 段 | 降低固定长度指纹 |

按文档中的模拟结果：TCP 分段只能对抗首包 DPI；TLS record 拆分能通过 first / tcp / record 三类检查；会重组 handshake 的 DPI 只能依赖上游中继。分片间隔调到 200ms 可跨过 150ms 的重组窗口，但握手延迟明显增加，默认仍为 10ms。

## 安全模型

- 不安装根证书、不终止 TLS；中继和加速链路都保持端到端加密。
- 不自动启用第三方镜像或 `overwall` 中继；中继必须由用户显式填写。
- 远程规则只接受 HTTPS；本地缓存失败不会阻塞代理启动。
- 日志默认不记录 Cookie / Authorization / 请求体，并对 `token/sig/jwt/password/key` 等查询参数脱敏。
- 默认只监听 `127.0.0.1`；改为 `0.0.0.0` 时界面与日志都会提示局域网风险。
- 本机与内网地址默认始终直连，避免把局域网设备绕进代理。

## 目录结构

```text
NetAccel/
├── src/
│   ├── NetAccel.Core/       规则、TLS、DNS、代理服务、系统代理、实验室
│   ├── NetAccel.App/        Avalonia 桌面界面
│   └── NetAccel.Cli/        命令行与服务端自检
├── tests/NetAccel.Core.Tests/
├── tools/NetAccel.UiPreview/ 无显示器界面截图与布局冒烟测试
└── packaging/build.sh
```

## 关于“打包后打开就闪退”

原 SteamTools 的 Avalonia 应用启动链路很长（DI、云服务、AppCenter、平台服务、WebView 等），任何一个环节失败都会在窗口出现前退出。NetAccel 是独立进程，启动时**不访问网络、不初始化数据库、不依赖云服务**，并额外做了这些防护：

- `AppDomain.UnhandledException`、`TaskScheduler.UnobservedTaskException` 和 `Main` 全部捕获异常，写入 `数据目录/crash.log`；
- XAML 加载失败时用纯代码构建一个错误窗口，保证能看到失败原因；
- 设置文件损坏时自动回退到 `.bak` 或默认值；
- 端口被占用、监听地址非法、系统代理设置失败都会以状态栏文案说明，而不是抛异常退出；
- 发布时关闭裁剪与单文件解压，避免原生库缺失；
- 启动不自动开启系统代理，只有用户显式勾选才修改系统设置；
- 退出时先停止代理并恢复系统代理，再关闭窗口。

如果 Windows 上仍然闪退，先看 `%APPDATA%\NetAccel\crash.log`；如果 Linux 上没有窗口，确认已安装 `libx11-6 libice6 libsm6 libfontconfig1`（或对应的发行版包名）。

## 已知限制

- 不包含 MITM，因此镜像重定向、请求/响应头替换、`verifyHost` 不会执行。
- 不对 UDP/QUIC 做代理；SOCKS5 的 UDP ASSOCIATE 会明确拒绝。
- 不处理证书固定（pinning）的应用。
- 不会自动启用 DevSidecar 的 `overwall` 中继。
- 不含 Android/iOS 工程；本仓库聚焦桌面端独立应用。
- 分片能否绕过 DPI 取决于具体网络，必须结合实验室与真实环境验证。

## 与原项目的关系

- 规则解析、TLS ClientHello 处理、预置 IP 选路、DoH、诊断日志等逻辑迁移自 `src/ST.Client`，并按独立应用的需要做了边界检查、并发与启动稳定性修复。
- 原项目仍保留完整功能（含 MITM、Steam 工具、移动端）。
- 协议与策略取舍参考 `doc/experimental/android-accelerator-feasibility.md`。
