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

已在本仓库用 `.NET SDK 11.0.100` 实测通过（linux-x64）。

```bash
git clone -b <你的分支> https://github.com/luckfun233/SteamTools.git
cd SteamTools
git submodule update --init --recursive

# 一键构建便携包
./build/publish_linux_selfbuilt.sh linux-x64
```

脚本会做四件事：

1. 发布主程序（自包含运行时，不需要用户装 .NET）。
2. 发布 5 个插件，只把插件 DLL 放进 `modules/<Name>/`，依赖合并到主目录。
3. 发布 `Steam++.Accelerator` 反代子进程（自包含单文件，放在 `modules/Accelerator/`）。
4. 复制图标 / 安装脚本 / 说明，打包成 `artifacts/WattToolkit_linux-x64_selfbuilt_<日期>.tar.zst` 并生成 sha256。

注意事项：

- `Splat 19.3.1` 的 NuGet 作者证书已被吊销，`dotnet restore` 会报 `NU3012`。脚本里设置了
  `DOTNET_NUGET_SIGNATURE_VERIFICATION=false` 绕过；这是构建环境的证书链问题，与包内容无关。
- 反代子进程必须**自包含**。官方流程是单文件 + 依赖主进程的 `DOTNET_ROOT`，
  便携包直接跑很容易出现找不到运行时，脚本改为自包含单文件。
- 插件目录名必须是 `modules/<短名>`，且目录内 DLL 必须叫
  `BD.WTTS.Client.Plugins.<短名>.dll`，否则 `PluginsCore` 不会加载。

### 已构建的产物

- 下载（gofile，暂存）：<https://gofile.io/d/zpqNQ1ty>
- 文件名：`WattToolkit_linux_x64_selfbuilt_20261114.tar.zst`（约 121 MB）
- SHA256：`3ae21ee46df861df829ed30e99f7e862b776c656fb9c178935e4fa13f6dd6387`

上传的是匿名临时空间，链接可能过期；过期后按上面的脚本自行构建即可。


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
