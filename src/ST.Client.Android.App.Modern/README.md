# net6-android Start project

本工程是 Android 手机版的构建入口（`net6.0-android`）。它编译 `../ST.Client.Android` 下的 Android 代码，并链接 `../ST.Client.Mobile.Droid.Design/ui` 下的 Android 资源，因此可以在 Linux（无 Visual Studio）环境下直接产出 APK。

> 注意：本工程只面向 **Android 手机端**。`trae/android-linux-build` 分支名中的 linux 指“可在 Linux 上构建 APK”，与 Linux 桌面版无关。

## 在 Linux 上构建 APK

### 前置环境

| 依赖 | 版本 |
| --- | --- |
| .NET SDK | 6.0.4xx（如 6.0.428） |
| .NET Android workload | `dotnet workload install android`（验证版本 32.0.509） |
| JDK | 11 |
| Android SDK | `platform-tools`、`platforms;android-31`、`build-tools;32.0.0` |

### 初始化子模块

`ST.Client` 与 `ST.Client.ReverseProxy.Titanium` 会引用两个子模块工程，缺一不可：

```bash
git submodule update --init references/ArchiSteamFarm references/Titanium-Web-Proxy
```

### 发布

```bash
export DOTNET_ROOT=<dotnet-6-sdk-dir>
export PATH="$DOTNET_ROOT:$PATH"
export JAVA_HOME=<jdk-11-dir>
export ANDROID_HOME=<android-sdk-dir>
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export DOTNET_NUGET_SIGNATURE_VERIFICATION=false   # 规避旧包签名证书吊销导致的 NU3012

dotnet publish src/ST.Client.Android.App.Modern/ST.Client.Android.App.Modern.csproj \
  -c Release -f net6.0-android \
  -p:AndroidSdkDirectory="$ANDROID_HOME" \
  -p:JavaSdkDirectory="$JAVA_HOME" \
  -p:AndroidPackageFormat=apk
```

产物位于 `src/ST.Client.Android.App.Modern/bin/Release/net6.0-android/publish/`（默认生成包含 arm64-v8a / armeabi-v7a / x86_64 的 universal APK）。

### 签名

Release 包若未配置签名，会使用本机调试证书；需要固定签名时可用 `apksigner` 重新签名：

```bash
apksigner sign --ks <your.keystore> --ks-key-alias <alias> \
  --out WattToolkit_Android_signed.apk <publish-output>.apk
apksigner verify --print-certs WattToolkit_Android_signed.apk
```

## 已知构建注意点

- `Directory.Build.props` 中定义了 `SELF_BUILT_BUILD`：自建包按官方渠道处理，跳过“非官方渠道”校验与提示；合并回上游时删除该定义即可。
- `ST.Client/ST.Client.csproj` 无条件引用 `references/ArchiSteamFarm`，因此即使只想构建 Android，也必须先初始化该子模块。
- 若 NuGet 恢复失败，检查 `NuGet.Config` 是否包含 `nuget.org` 源。

## [Android Studio Project](../ST.Client.Mobile.Droid.Design/README.md)

## [Xamarin.Android Project](../ST.Client.Android/README.md)
