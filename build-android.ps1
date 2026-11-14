# 本机 Android(.NET 6 for Android / SDK-style) 构建入口
# 依赖：.NET SDK 6.0.428 + android workload、JDK 11、Android SDK(platform 31 + build-tools 31)
# 迁移后使用仓库自带的 SDK-style app 项目，Windows / Linux 均可构建
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$LibraryOnly
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot

$env:ANDROID_HOME = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { 'G:\Android\AndroidSDK' }
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
$env:JAVA_HOME = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { 'G:\Java\jdk-11.0.25+9' }
$env:NUGET_PACKAGES = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { 'G:\nuget-packages' }
$env:MSBUILDDISABLENODEREUSE = '1'

$app = "$repo\src\ST.Client.Android.App.Modern\ST.Client.Android.App.Modern.csproj"
$common = @(
    '-f', 'net6.0-android'
    '-c', $Configuration
    '-m:1'
    '-nodeReuse:false'
    '-v:m'
    "-p:AndroidSdkDirectory=$env:ANDROID_HOME"
    "-p:JavaSdkDirectory=$env:JAVA_HOME"
    '-p:JavaMaximumHeapSize=768M'
)

Write-Host '== 还原 NuGet ==' -ForegroundColor Cyan
dotnet restore $app @common
if ($LASTEXITCODE -ne 0) { throw "restore 失败 ($LASTEXITCODE)" }

if ($LibraryOnly) {
    Write-Host '== 编译（跳过 APK 打包）==' -ForegroundColor Cyan
    dotnet build $app --no-restore -t:Compile @common
} else {
    Write-Host '== 构建 APK ==' -ForegroundColor Cyan
    dotnet build $app --no-restore @common
}
if ($LASTEXITCODE -ne 0) { throw "build 失败 ($LASTEXITCODE)" }

$apkDir = "$repo\src\ST.Client.Android.App.Modern\bin\$Configuration\net6.0-android"
Get-ChildItem $apkDir -Filter '*.apk' -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host ("APK: {0} ({1:N1} MB)" -f $_.FullName, ($_.Length / 1MB)) -ForegroundColor Green }
