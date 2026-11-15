<h1 align="center">Watt Toolkit 🧰 (原名 Steam++)</h1>

<div align="center">

[English](./README.en.md) | 简体中文

「Watt Toolkit」是一个开源跨平台的多功能游戏工具箱，此工具的大部分功能都是需要您下载安装 Steam 才能使用。

![Release Download](https://img.shields.io/github/downloads/BeyondDimension/SteamTools/total?style=flat-square)
[![Release Version](https://img.shields.io/github/v/release/BeyondDimension/SteamTools?style=flat-square)](https://github.com/BeyondDimension/SteamTools/releases/latest)
[![GitHub license](https://img.shields.io/github/license/BeyondDimension/SteamTools?style=flat-square)](LICENSE)
[![GitHub Star](https://img.shields.io/github/stars/BeyondDimension/SteamTools?style=flat-square)](https://github.com/BeyondDimension/SteamTools/stargazers)
[![GitHub Fork](https://img.shields.io/github/forks/BeyondDimension/SteamTools?style=flat-square)](https://github.com/BeyondDimension/SteamTools/network/members)
![GitHub Repo size](https://img.shields.io/github/repo-size/BeyondDimension/SteamTools?style=flat-square&color=3cb371)
[![GitHub Repo Languages](https://img.shields.io/github/languages/top/BeyondDimension/SteamTools?style=flat-square)](https://github.com/BeyondDimension/SteamTools/search?l=c%23)
[![NET 6.0](https://img.shields.io/badge/dotnet-6.0-purple.svg?style=flat-square&color=512bd4)](https://docs.microsoft.com/zh-cn/dotnet/core/whats-new/dotnet-6)
[![C# 10.0](https://img.shields.io/badge/c%23-10.0-brightgreen.svg?style=flat-square&color=6da86a)](https://docs.microsoft.com/zh-cn/dotnet/csharp/whats-new/csharp-10)

[![Desktop UI](https://img.shields.io/badge/ui@desktop-AvaloniaUI-purple.svg?style=flat-square&color=8c45ab)](https://github.com/AvaloniaUI/Avalonia)
[![Mobile GUI](https://img.shields.io/badge/gui@mobile-Xamarin.Forms-blue.svg?style=flat-square&color=3498db)](https://github.com/xamarin/Xamarin.Forms)
[![Official WebSite](https://img.shields.io/badge/website@official-Ant%20Design%20of%20React-blue.svg?style=flat-square&color=61dafb)](https://github.com/ant-design/ant-design)
[![BackManage WebSite](https://img.shields.io/badge/website@back_manage-Ant%20Design%20of%20Blazor-purple.svg?style=flat-square&color=512bd4)](https://github.com/ant-design-blazor/ant-design-blazor)

[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FSteamTools-Team%2FSteamTools%2Fbadge%3Fref%3Ddevelop&style=flat-square)](https://actions-badge.atrox.dev/BeyondDimension/SteamTools/goto?ref=develop)
[![GitHub Star](https://img.shields.io/github/stars/BeyondDimension/SteamTools.svg?logo=github)](https://github.com/BeyondDimension/SteamTools)
[![Gitee Star](https://gitee.com/rmbgame/SteamTools/badge/star.svg)](https://gitee.com/rmbgame/SteamTools)

[![爱发电](https://img.shields.io/badge/爱发电-软妹币玩家-blue.svg?style=flat-square&color=ea4aaa&logo=github-sponsors)](https://afdian.net/@rmbgame)
[![Kofi](https://img.shields.io/badge/Kofi-RMBGAME-orange.svg?style=flat-square&logo=kofi)](https://ko-fi.com/rmbgame)
[![Patreon](https://img.shields.io/badge/Patreon-RMBGAME-red.svg?style=flat-square&logo=patreon)](https://www.patreon.com/rmbgame)
[![Bilibili](https://img.shields.io/badge/bilibili-软妹币玩家-blue.svg?style=flat-square&logo=bilibili)](https://space.bilibili.com/797215)
[![QQ群](https://img.shields.io/badge/QQ群-960746023-blue.svg?style=flat-square&color=12b7f5&logo=qq)](https://jq.qq.com/?_wv=1027&k=3JKPt4xC)

<img src="./resources/screenshot-1.webp" width="800" />
<br/>
<br/>
<img src="./resources/screenshot-android.png" width="800" />
</div>

---

## 📱 分支说明：Android 手机端（`trae/android-linux-build`）

> **本分支服务于 Android 手机版（Watt Toolkit 2.8.3），不是 Linux 桌面版分支。**
> 分支名里的“linux”指“把 Android 工程迁移为可以在 Linux 上构建 APK 的 `net6.0-android` 工程”，与 Linux 桌面端无关；桌面版（Avalonia）代码不在本分支的改造范围内。

本分支的主要改动：

- **内置加速组**：GitHub、Hugging Face、Pixiv 组不再依赖服务端接口，即使接口失败（网络不可达 / 非官方渠道被拒绝）也能显示并启用。
- **DevSidecar 兼容层**：解析 DevSidecar 的远程配置与规则格式（域名 / 路径 / SNI / redirect / proxy / 中继），并提供本地规则引擎。
- **实验性加速能力**：SNI 改写、SNI 分片、DoH、可信中继等多条绕过路径，均可在设置中单独开关。
- **设置入口**：设置页新增「加速（实验性）」分组，包含实验性加速设置、自定义代理规则、加速实验室。
- **自建包处理**：构建时定义 `SELF_BUILT_BUILD`，跳过官方渠道校验与“非官方渠道”提示，并使用生产 API。

构建方式见 [Android 构建说明](./src/ST.Client.Android.App.Modern/README.md)，技术路线与可行性分析见 [可行性文档](./doc/experimental/android-accelerator-feasibility.md)。

## 🚀 下载渠道
- [GitHub Releases](https://github.com/BeyondDimension/SteamTools/releases)
- [Gitee Releases](https://gitee.com/rmbgame/SteamTools/releases)
- [Official WebSite](https://steampp.net)
- [![Microsoft Store](./resources/MSStore_English.png)](https://www.microsoft.com/store/apps/9MTCFHS560NG)
- [AUR](https://aur.archlinux.org/packages/watt-toolkit-bin)(官方 Release 构建)
- [AUR dev](https://aur.archlinux.org/packages/watt-toolkit-git)(拉取最新源代码从本地构建，不保证可用性，构建也许会出现失败问题)

## ✨ 功能
1. 网络加速 <img src="./resources/windows-brands.svg" width="16" height="16" /> <img src="./resources/linux-brands.svg" width="16" height="16" /> <img src="./resources/apple-brands.svg" width="16" height="16" /> <img src="./resources/android-brands.svg" width="16" height="16" /> 
    - ~~使用 [Titanium-Web-Proxy](https://github.com/justcoding121/Titanium-Web-Proxy) 开源项目进行本地反代来支持更快的访问游戏网站。~~
	- 使用 [YARP.ReverseProxy](https://github.com/microsoft/reverse-proxy) 开源项目进行本地反代来支持更快的访问游戏网站。
2. 脚本配置 <img src="./resources/windows-brands.svg" width="16" height="16" /> <img src="./resources/linux-brands.svg" width="16" height="16" /> <img src="./resources/apple-brands.svg" width="16" height="16" />
	- 通过加速服务拦截网络请求将一些 JS 脚本注入在网页中，提供类似网页插件的功能。
3. 账号切换 <img src="./resources/windows-brands.svg" width="16" height="16" /> <img src="./resources/linux-brands.svg" width="16" height="16" /> <img src="./resources/apple-brands.svg" width="16" height="16" />
	- 一键切换已在当前 PC 上登录过的 Steam 账号，与管理家庭共享库排序及禁用等功能。
4. 库存管理 <img src="./resources/windows-brands.svg" width="16" height="16" /> <img src="./resources/linux-brands.svg" width="16" height="16" /> <img src="./resources/apple-brands.svg" width="16" height="16" />
	- 让您直接管理 Steam 游戏库存，可以编辑游戏名称和[自定义封面](https://www.steamgriddb.com/)，也能解锁以及反解锁 Steam 游戏成就。
	- 监控 Steam 游戏下载进度实现 Steam 游戏下载完成定时关机功能。
	- 模拟运行 Steam 游戏，让您不用安装和下载对应的游戏也能挂游玩时间和 Steam 卡片
	- 自助管理 Steam 游戏云存档，随时删除和上传自定义的存档文件至 Steam 云
5. 本地令牌 <img src="./resources/windows-brands.svg" width="16" height="16" /> <img src="./resources/linux-brands.svg" width="16" height="16" /> <img src="./resources/apple-brands.svg" width="16" height="16" /> <img src="./resources/android-brands.svg" width="16" height="16" /> 
	- 让您的手机令牌统一保存在电脑中，目前仅支持 Steam 令牌，后续会开发支持更多的令牌种类与云同步令牌。
6. 自动挂卡 <img src="./resources/windows-brands.svg" width="16" height="16" /> <img src="./resources/linux-brands.svg" width="16" height="16" /> <img src="./resources/apple-brands.svg" width="16" height="16" /> <img src="./resources/android-brands.svg" width="16" height="16" /> 
	- 集成 [ArchiSteamFarm](https://github.com/JustArchiNET/ArchiSteamFarm) 在应用内提供 挂机掉落 Steam 集换式卡牌 等功能。
7. 游戏工具 <img src="./resources/windows-brands.svg" width="16" height="16" />
	- 强制游戏窗口使用无边框窗口化、更多功能待开发。

<!--发布配置SelfContained=true时会自动打包VC++相关程序集-->
<!--先决条件 Microsoft Visual C++ 2015-2019 Redistributable [64 位](https://aka.ms/vs/16/release/vc_redist.x64.exe) / [32 位](https://aka.ms/vs/16/release/vc_redist.x86.exe)-->
## 🖥 系统要求
### Windows

OS                                    | Version                    | Architectures   | Lifecycle
--------------------------------------|----------------------------|-----------------|----------
[Windows Client][Windows-client]      | 7 SP1(**\***), 8.1(**\***) | x64             | [Windows][Windows-lifecycle]
[Windows 10 Client][Windows-client]   | Version 1607+(**\***)      | x64             | [Windows][Windows-lifecycle]
[Windows 11][Windows-client]          | Version 22000+             | x64,            | [Windows][Windows-lifecycle]
[Windows Server][Windows-Server]      | 2008 R2 SP1(**\***), 2012+ | x64             | [Windows Server][Windows-Server-lifecycle]

**\*** Windows 7 SP1 必须安装 [扩展安全更新 (ESU)](https://docs.microsoft.com/troubleshoot/windows-client/windows-7-eos-faq/windows-7-extended-security-updates-faq) 且将在不再支持 **2022/11** 后发布的版本。  
**\*** Windows 8.1 将在不再支持 **2022/11** 后发布的版本。  
**\*** Windows Server 2008 R2 SP1 必须安装 [扩展安全更新 (ESU)](https://docs.microsoft.com/zh-cn/lifecycle/faq/extended-security-updates) 且将在不再支持 **2022/11** 后发布的版本。  
**\*** Microsoft Store(Desktop Bridge) Version 1809+  

[Windows-client]: https://www.microsoft.com/windows/
[Windows-lifecycle]: https://support.microsoft.com/help/13853/windows-lifecycle-fact-sheet
[win-client-docker]: https://hub.docker.com/_/microsoft-windows
[Windows-Server-lifecycle]: https://docs.microsoft.com/windows-server/get-started/windows-server-release-info
[Nano-Server]: https://docs.microsoft.com/windows-server/get-started/getting-started-with-nano-server
[Windows-Server]: https://docs.microsoft.com/windows-server/

### Linux

OS                                    | Version               | Architectures     | Lifecycle
--------------------------------------|-----------------------|-------------------|----------
[Alpine Linux][Alpine]                | 3.13+                 | x64, Arm64        | [Alpine][Alpine-lifecycle]
[CentOS][CentOS]                      | 7+                    | x64               | [CentOS][CentOS-lifecycle]
[Debian][Debian]                      | 10+                   | x64, Arm64        | [Debian][Debian-lifecycle]
[Fedora][Fedora]                      | 33+                   | x64               | [Fedora][Fedora-lifecycle]
[openSUSE][OpenSUSE]                  | 15+                   | x64               | [OpenSUSE][OpenSUSE-lifecycle]
[Red Hat Enterprise Linux][RHEL]      | 7+                    | x64, Arm64        | [Red Hat][RHEL-lifecycle]
[SUSE Enterprise Linux (SLES)][SLES]  | 12 SP2+               | x64               | [SUSE][SLES-lifecycle]
[Ubuntu][Ubuntu]                      | 16.04, 18.04, 20.04+  | x64, Arm64        | [Ubuntu][Ubuntu-lifecycle]
[Deepin / UOS][Deepin]                | 20+                   | x64               | [Deepin][Deepin-lifecycle]
[Arch Linux][Arch]                    |                       | x64，Arm64        | 

[Alpine]: https://alpinelinux.org/
[Alpine-lifecycle]: https://wiki.alpinelinux.org/wiki/Alpine_Linux:Releases
[CentOS]: https://www.centos.org/
[CentOS-lifecycle]:https://wiki.centos.org/FAQ/General
[CentOS-docker]: https://hub.docker.com/_/centos
[CentOS-pm]: https://docs.microsoft.com/dotnet/core/install/linux-package-manager-centos8
[Debian]: https://www.debian.org/
[Debian-lifecycle]: https://wiki.debian.org/DebianReleases
[Debian-pm]: https://docs.microsoft.com/dotnet/core/install/linux-package-manager-debian10
[Fedora]: https://getfedora.org/
[Fedora-lifecycle]: https://fedoraproject.org/wiki/End_of_life
[Fedora-docker]: https://hub.docker.com/_/fedora
[Fedora-msft-pm]: https://docs.microsoft.com/dotnet/core/install/linux-package-manager-fedora32
[Fedora-pm]: https://fedoraproject.org/wiki/DotNet
[OpenSUSE]: https://opensuse.org/
[OpenSUSE-lifecycle]: https://en.opensuse.org/Lifetime
[OpenSUSE-docker]: https://hub.docker.com/r/opensuse/leap
[OpenSUSE-pm]: https://docs.microsoft.com/dotnet/core/install/linux-package-manager-opensuse15
[RHEL]: https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux
[RHEL-lifecycle]: https://access.redhat.com/support/policy/updates/errata/
[RHEL-msft-pm]: https://docs.microsoft.com/dotnet/core/install/linux-package-manager-rhel8
[RHEL-pm]: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/developing_.net_applications_in_rhel_8/using-net-core-on-rhel_gsg#installing-net-core_gsg
[SLES]: https://www.suse.com/products/server/
[SLES-lifecycle]: https://www.suse.com/lifecycle/
[SLES-pm]: https://docs.microsoft.com/dotnet/core/install/linux-package-manager-sles15
[Ubuntu]: https://ubuntu.com/
[Ubuntu-lifecycle]: https://wiki.ubuntu.com/Releases
[Ubuntu-pm]: https://docs.microsoft.com/dotnet/core/install/linux-package-manager-ubuntu-2004
[Deepin]: https://www.deepin.org/
[Deepin-lifecycle]: https://www.deepin.org/release-notes
[Arch]: https://archlinux.org/

### macOS

OS                            | Version                   | Architectures     |
------------------------------|---------------------------|-------------------|
[macOS][macOS]                | 10.15+                    | x64, Arm64        |

[macOS]: https://support.apple.com/macos

### Android

OS                            | Version                 | Architectures                                                      |
------------------------------|-------------------------|--------------------------------------------------------------------|
[Android][Android]            | 5.0(API 21)+            | [x64][Android-x64], [Arm64][Android-Arm64], [Arm32][Android-Arm32] |

[Android]: https://support.google.com/android
[Android-x64]: https://developer.android.google.cn/ndk/guides/abis?hl=zh_cn#86-64
[Android-Arm32]: https://developer.android.google.cn/ndk/guides/abis?hl=zh_cn#v7a
[Android-Arm64]: https://developer.android.google.cn/ndk/guides/abis?hl=zh_cn#arm64-v8a

### ~~iOS / iPadOS~~

OS                            | Version                 | Architectures     |
------------------------------|-------------------------|-------------------|
[iOS][iOS]                    | 10.0+                   | x64, Arm32, Arm64 |

[iOS]: https://support.apple.com/ios

## ⛔ 不受支持的操作系统
- Windows 8
	- [由于微软官方对该产品的支持已结束](https://docs.microsoft.com/zh-cn/lifecycle/products/windows-8)，故本程序无法在此操作系统上运行，[建议升级到 Windows 8.1](https://support.microsoft.com/zh-cn/windows/%E4%BB%8E-windows-8-%E6%9B%B4%E6%96%B0%E5%88%B0-windows-8-1-17fc54a7-a465-6b5a-c1a0-34140afd0669)
- 无桌面 GUI 的 Windows Server / Linux 版本
- Xbox or Windows Mobile / Phone

## 🌏 路线图
查看这个 [milestones](https://github.com/BeyondDimension/SteamTools/milestones) 来了解我们下一步的开发计划，并随时提出问题。

## ⌨️ 开发环境
[Visual Studio 2022](https://visualstudio.microsoft.com/zh-hans/vs/)   
[JetBrains Rider](https://www.jetbrains.com/rider/)  
~~[Visual Studio 2022 for Mac](https://visualstudio.microsoft.com/zh-hans/vs/mac/)~~  
~~[Visual Studio Code](https://code.visualstudio.com/)~~
- 系统要求
	- [Windows 10 版本 2004 或更高版本：家庭版、专业版、教育版和企业版（不支持 LTSC 和 Windows 10 S，在较早的操作系统上可能不受支持）](https://docs.microsoft.com/zh-cn/visualstudio/releases/2019/system-requirements)
	- [macOS 10.14 Mojave 或更高版本](https://docs.microsoft.com/zh-cn/visualstudio/productinfo/vs2019-system-requirements-mac)
- 工作负荷
	- Web 和云
		- ASP.NET 和 Web 开发
	- 桌面应用和移动应用
		- 使用 .NET 的移动开发 / .NET Multi-platform App UI 开发
		- .NET 桌面开发
		- 通用 Windows 平台开发
- 单个组件
	- GitHub Extension for Visual Studio(可选)
	- Windows 10 SDK (10.0.19041.0)
- [Visual Studio Marketplace](https://marketplace.visualstudio.com/)
	- [Avalonia for Visual Studio(可选)](https://marketplace.visualstudio.com/items?itemName=AvaloniaTeam.AvaloniaforVisualStudio)
	- [NUnit VS Templates(可选)](https://marketplace.visualstudio.com/items?itemName=NUnitDevelopers.NUnitTemplatesforVisualStudio)

[OpenJDK 11](https://docs.microsoft.com/zh-cn/java/openjdk/download#openjdk-11)  
[Android Studio 2021.1.1 或更高版本](https://developer.android.google.cn/studio/)  
[Xcode 13 或更高版本](https://developer.apple.com/xcode/)

## 🏗️ [项目结构](./src/README.md)
详见 [./src/README.md](./src/README.md)  

<!--
* [LibVLCSharp](https://github.com/videolan/libvlcsharp)
* [Chromium Embedded Framework (CEF)](https://github.com/chromiumembedded/cef)
* [CefNet](https://github.com/CefNet/CefNet)
* [CefSharp](https://github.com/cefsharp/CefSharp)
* [ZXing.Net.Mobile](https://github.com/Redth/ZXing.Net.Mobile)
* [Floating Action Button Speed Dial](https://github.com/leinardi/FloatingActionButtonSpeedDial)
-->
<!--👇图标如果发生更改，还需更改 Tools.OpenSourceLibraryList(Program.OpenSourceLibraryListEmoji) -->
## 📄 感谢以下开源项目
* [Newtonsoft.Json](https://github.com/JamesNK/Newtonsoft.Json)
* [MetroRadiance](https://github.com/Grabacr07/MetroRadiance)
* [MetroTrilithon](https://github.com/Grabacr07/MetroTrilithon)
* [Livet](https://github.com/runceel/Livet)
* [StatefulModel](https://github.com/ugaya40/StatefulModel)
* [Hardcodet.NotifyIcon](https://github.com/HavenDV/Hardcodet.NotifyIcon.Wpf.NetCore)
* [System.Reactive](https://github.com/dotnet/reactive)
* [Titanium-Web-Proxy](https://github.com/justcoding121/Titanium-Web-Proxy)
* [YARP](https://github.com/microsoft/reverse-proxy)
* [FastGithub](https://github.com/dotnetcore/FastGithub)
* [Portable.BouncyCastle](https://github.com/novotnyllc/bc-csharp)
* [Ninject](https://github.com/ninject/Ninject)
* [log4net](https://github.com/apache/logging-log4net)
* [SteamAchievementManager](https://github.com/gibbed/SteamAchievementManager)
* [ArchiSteamFarm](https://github.com/JustArchiNET/ArchiSteamFarm)
* [Steam4NET](https://github.com/SteamRE/Steam4NET)
* [WinAuth](https://github.com/winauth/winauth)
* [SteamDesktopAuthenticator](https://github.com/Jessecar96/SteamDesktopAuthenticator)
* [Gameloop.Vdf](https://github.com/shravan2x/Gameloop.Vdf)
* [DnsClient.NET](https://github.com/MichaCo/DnsClient.NET)
* [Costura.Fody](https://github.com/Fody/Costura)
* [MessagePack-CSharp](https://github.com/neuecc/MessagePack-CSharp)
* [CSharpVitamins.ShortGuid](https://github.com/AigioL/CSharpVitamins.ShortGuid)
* [Nito.Comparers](https://github.com/StephenCleary/Comparers)
* [Nito.Disposables](https://github.com/StephenCleary/Disposables)
* [Crc32.NET](https://github.com/force-net/Crc32.NET)
* [gfoidl.Base64](https://github.com/gfoidl/Base64)
* [sqlite-net-pcl](https://github.com/praeclarum/sqlite-net)
* [AutoMapper](https://github.com/AutoMapper/AutoMapper)
* [Polly](https://github.com/App-vNext/Polly)
* [TaskScheduler](https://github.com/dahall/taskscheduler)
* [SharpZipLib](https://github.com/icsharpcode/SharpZipLib)
* [SevenZipSharp](https://github.com/squid-box/SevenZipSharp)
* [ZstdNet](https://github.com/skbkontur/ZstdNet)
* [Depressurizer](https://github.com/Depressurizer/Depressurizer)
* [NLog](https://github.com/nlog/NLog)
* [NUnit](https://github.com/nunit/nunit)
* [ReactiveUI](https://github.com/reactiveui/reactiveui)
* [MessageBox.Avalonia](https://github.com/AvaloniaUtils/MessageBox.Avalonia)
* [AvaloniaUI](https://github.com/AvaloniaUI/Avalonia)
* [AvaloniaGif](https://github.com/jmacato/AvaloniaGif)
* [Avalonia XAML Behaviors](https://github.com/wieslawsoltes/AvaloniaBehaviors)
* [FluentAvalonia](https://github.com/amwx/FluentAvalonia)
* [APNG.NET](https://github.com/jz5/APNG.NET)
* [Moq](https://github.com/moq/moq4)
* [NPOI](https://github.com/nissl-lab/npoi)
* [Fleck](https://github.com/statianzo/Fleck)
* [Swashbuckle.AspNetCore](https://github.com/domaindrivendev/Swashbuckle.AspNetCore)
* [AspNet.Security.OpenId.Providers](https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers)
* [AspNet.Security.OAuth.Providers](https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers)
* [ZXing.Net](https://github.com/micjahn/ZXing.Net)
* [QRCoder](https://github.com/codebude/QRCoder)
* [QR Code Generator for .NET](https://github.com/manuelbl/QrCodeGenerator)
* [TinyPinyin](https://github.com/promeG/TinyPinyin)
* [TinyPinyin.Net](https://github.com/hueifeng/TinyPinyin.Net)
* [Packaging utilities for .NET Core](https://github.com/qmfrederik/dotnet-packaging)
* [React](https://github.com/facebook/react)
* [Ant Design](https://github.com/ant-design/ant-design)
* [Ant Design Blazor](https://github.com/ant-design-blazor/ant-design-blazor)
* [Toast messages for Xamarin.iOS](https://github.com/andrius-k/Toast)
* [ImageCirclePlugin](https://github.com/jamesmontemagno/ImageCirclePlugin)
* [Visual Studio App Center SDK for .NET](https://github.com/microsoft/appcenter-sdk-dotnet)
* [AppCenter-XMac](https://github.com/nor0x/AppCenter-XMac)
* [MSBuild.Sdk.Extras](https://github.com/novotnyllc/MSBuildSdkExtras)
* [Xamarin.Essentials](https://github.com/xamarin/essentials)
* [Xamarin.Forms](https://github.com/xamarin/Xamarin.Forms)
* [Open Source Components for Xamarin](https://github.com/xamarin/XamarinComponents)
* [Google Play Services / Firebase / ML Kit for Xamarin.Android](https://github.com/xamarin/GooglePlayServicesComponents)
* [Picasso](https://github.com/square/picasso)
* [OkHttp](https://github.com/square/okhttp)
* [Material Components for Android](https://github.com/material-components/material-components-android)
* [AndroidX for Xamarin.Android](https://github.com/xamarin/AndroidX)
* [Android Jetpack](https://github.com/androidx/androidx)
* [ConstraintLayout](https://github.com/androidx/constraintlayout)
* [Entity Framework Core](https://github.com/dotnet/efcore)
* [ASP.NET Core](https://github.com/dotnet/aspnetcore)
* [Windows Forms](https://github.com/dotnet/winforms)
* [Windows Presentation Foundation (WPF)](https://github.com/dotnet/wpf)
* [C#/WinRT](https://github.com/microsoft/CsWinRT)
* [command-line-api](https://github.com/dotnet/command-line-api)
* [.NET Runtime](https://github.com/dotnet/runtime)
* [Fluent UI System Icons](https://github.com/microsoft/fluentui-system-icons)
* [Material design icons](https://github.com/google/material-design-icons)
