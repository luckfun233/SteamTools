# 加速器实验分支（Linux 自建包）说明

> 适用仓库：`luckfun233/SteamTools` 的 `trae/agent-*` 分支
> 上游：`BeyondDimension/SteamTools`（Watt Toolkit / 原 Steam++）

## 1. 这个分支要做什么

上游的加速功能依赖官方服务端下发的加速项目（`IMicroServiceClient.Accelerate.All()`），并且客户端会做官方渠道校验。这带来两个问题：

1. 自建包 / 离线环境 / 服务端拒绝非官方客户端时，加速页的“加速服务组”是**空的**，功能等于不可用。
2. 启动会弹“当前运行程序不为官方渠道包”一类提示，对自建包没有意义。

本分支的目标：

- 加速组**不依赖服务端**也能显示并工作（内置规则兜底）。
- 复用 **DevSidecar** 的 `remote_config.json5` 规则，减少自己维护域名列表。
- 在加速设置页提供可配置的“实验性加速”区域，而不是写死。
- 自建包不再被官方渠道提示打扰。
- 保持私有仓库安全：带凭证的请求不能进公共镜像。

**注意：这里不是 Android 工程。** 这是 Avalonia 桌面版，可在 Linux 上打包；老的 2.8.x Android（Xamarin）实验代码在另一个分支，不要往这里塞 Android 逻辑。

## 2. 已实现内容（对应代码）

| 功能 | 文件 |
|---|---|
| 内置 GitHub / Hugging Face 加速组（服务端不可用时兜底） | `src/BD.WTTS.Client.Plugins.Accelerator/Services.Implementation/BuiltInAccelerateGroups.cs` |
| DevSidecar 配置解析并转换为加速组 | `src/BD.WTTS.Client.Plugins.Accelerator/Services.Implementation/DevSidecarRuleGroups.cs` |
| 实验性设置的持久化 | `src/BD.WTTS.Client.Plugins.Accelerator/Settings/ExperimentalAcceleratorSettings.cs` |
| 设置页 UI（“实验性加速”区域） | `src/BD.WTTS.Client.Plugins.Accelerator/UI/Views/Pages/ProxySettingsPage.axaml` |
| 设置 ViewModel | `src/BD.WTTS.Client.Plugins.Accelerator/UI/ViewModels/ExperimentalAcceleratorViewModel.cs` |
| 加速组合并入口 | `src/BD.WTTS.Client.Plugins.Accelerator/Services/Mvvm/ProxyService.cs`（`MergeBuiltInAccelerateAsync`） |
| 非官方渠道提示抑制 | `src/BD.WTTS.Client/Extensions/ApiRspImplHandleUIExtensions.cs`、`src/BD.WTTS.Client/Services/Mvvm/NoticeService.cs`、`src/Directory.Build.props`（`SELF_BUILT_BUILD`） |

## 3. 内置加速组

内置组使用与上游加速项目相同的 `AccelerateProjectDTO`：

- `ProxyType = Local`：仍然连接真实域名，只在 MITM 后伪装上游 TLS 的 SNI。
- `FakeServerName = baidu.com`（GitHub）/ `huggingface.cn`（Hugging Face）：绕过基于 SNI 的阻断。
- `IgnoreSSLCertVerification = true`：伪装 SNI 后上游证书域名必然不匹配，必须忽略上游校验；客户端侧仍由本地根证书按真实域名签发，安全性不变。

内置组只是**兜底**：组名带“（内置 SNI 加速）”后缀，正常不会与服务端下发的组重名；如果重名，以本地内置组为准。

## 4. DevSidecar 兼容规则

开启后从 `https://ds-official-config.bestar.de5.net/remote_config.json5` 拉取配置，失败时回退本地缓存：

- 只转换能安全表达的域名级规则：`sni`、`proxy`、`preSetIpList`。
- **路径级规则不会启用**。DevSidecar 只把 release/archive 路径重定向到 `ghp.ci`，而这里的域名规则是整域生效；直接套用会把私有仓库请求也送到镜像站，属于凭据泄露风险。
- 含正则元字符的域名（如 `^.*(wikipedia|wikimedia).org$`）会被跳过，因为 YARP 的域名匹配不支持正则。
- 非 HTTPS 的 `proxy` 目标会被忽略。
- 配置同步地址只允许 HTTPS。

生成一个名为“DevSidecar 规则（远程同步）”的加速组，默认不勾选，需要手动启用。

## 5. 官方渠道提示

`src/Directory.Build.props` 定义了 `SELF_BUILT_BUILD`：

- `ApiRspCode.IsNotOfficialChannelPackage` 不再弹 Toast，只写日志。
- 公告中带“官方渠道 / 非官方”的推送不再弹窗，但仍保留在通知列表里。

如果你要把仓库合并回上游，删掉这个常量定义即可恢复原行为。

## 6. 构建（Linux）

```bash
git clone -b <你的分支> https://github.com/luckfun233/SteamTools.git
cd SteamTools
git submodule update --init --recursive

dotnet restore WattToolkit.slnx
dotnet build src/BD.WTTS.Client.Avalonia.App/BD.WTTS.Client.Avalonia.App.csproj -c Release
```

打包脚本在 `build/` 与 `packaging/` 目录，按上游 `doc/publish.md` 的 Linux 部分执行。需要 .NET 11 SDK（以 `src/Directory.Build.props` 的 `DotNet_Version` 为准）。

> 本次改动没有在当前沙箱内编译验证（沙箱没有 .NET SDK）。如果构建失败，优先检查新增文件的命名空间与 `ExperimentalAcceleratorViewModel` 的绑定类型。

## 7. 常见问题

**Q：加速页还是一个组都没有？**
1. 打开 加速设置 → 实验性加速 → 确认“启用内置加速组”是开的。
2. 点“重新加载加速组”。
3. 若仍为空，看日志中是否有 `MergeBuiltInAccelerateAsync` 的异常；内置组合并发生在服务端请求之后，不应受网络失败影响。

**Q：设置页没有“实验性加速”？**
该区域在“加速设置”页最下方，需要加速插件处于启用状态。上游的通用设置页不是它的位置。

**Q：启动还提示非官方渠道？**
确认构建时 `SELF_BUILT_BUILD` 生效（`src/Directory.Build.props`）。若提示来自网页/公告正文而不是通知弹窗，需要检查 `NoticeService` 的过滤关键字。

**Q：私有仓库会不会被送去镜像？**
不会。本分支没有启用 DevSidecar 的路径级重定向，也没有配置任何整域镜像；GitHub/HF 的内置规则只做 SNI 伪装，流量仍然到原站。

**Q：加速对 Linux 有效吗？**
反代进程（`Steam++.Accelerator`）在 Linux 上使用系统代理模式，MITM + SNI 伪装可用；Windows 专属的 DNS/WinDivert 拦截在 Linux 不参与。

## 8. 相关文档

- [technical-route.md](technical-route.md)：技术路线、规则映射、安全模型、限制与路线图
- DevSidecar：<https://github.com/docmirror/dev-sidecar>
- DevSidecar 内核：<https://github.com/Blue-Frontier/ds-core>
- FastGithub：<https://github.com/dotnetcore/FastGithub>
