# 本机 Android(Xamarin MonoAndroid12.0) 构建入口
# 依赖：VS2022 Build Tools + XamarinBuildTools 工作负载、JDK 11、Android SDK(platform 30/31 + build-tools 30/31)
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$LibraryOnly
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot

$env:ANDROID_HOME = 'G:\Android\AndroidSDK'
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
$env:JAVA_HOME = 'G:\Java\jdk-11.0.25+9'
$env:NUGET_PACKAGES = 'G:\nuget-packages'
$env:MSBUILDDISABLENODEREUSE = '1'

$msbuild = 'G:\VS2022\MSBuild\Current\Bin\MSBuild.exe'
if (-not (Test-Path $msbuild)) { throw "找不到 msbuild：$msbuild（需先安装 VS2022 Build Tools）" }

$common = @(
    "/p:Configuration=$Configuration"
    "/p:AndroidSdkDirectory=$env:ANDROID_HOME"
    "/p:JavaSdkDirectory=$env:JAVA_HOME"
    '/p:JavaMaximumHeapSize=768M'
    '/nodeReuse:false'
    '/m:1'
    '/v:m'
)

Write-Host '== 构建 ST.Client.Android ==' -ForegroundColor Cyan
& $msbuild "$repo\src\ST.Client.Android\ST.Client.Android.csproj" /t:Restore @common
& $msbuild "$repo\src\ST.Client.Android\ST.Client.Android.csproj" /t:Build @common

if (-not $LibraryOnly) {
    Write-Host '== 构建 APK ==' -ForegroundColor Cyan
    & $msbuild "$repo\src\ST.Client.Mobile.Droid.App\ST.Client.Android.App.csproj" /t:Restore @common
    & $msbuild "$repo\src\ST.Client.Mobile.Droid.App\ST.Client.Android.App.csproj" /t:Build @common
}
