#!/usr/bin/env bash
# 构建 Linux 自建便携包（自包含运行时 + 插件模块）
#
# 用法：
#   ./build/publish_linux_selfbuilt.sh [linux-x64]
#
# 前置：
#   - .NET 11 SDK（见 global.json）
#   - git submodule update --init --recursive
#
# 产物：
#   artifacts/Steam++_linux_x64/            解压即用的目录
#   artifacts/Steam++_linux_x64_*.tar.zst   压缩包
#   artifacts/*.sha256                      校验文件
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RID="${1:-linux-x64}"
TFM="net11.0"
VERSION="$(date +%Y%m%d)"
OUT="$ROOT/artifacts/Steam++_$RID"
PLUGINS=(Accelerator GameAccount GameList Authenticator SteamIdleCard)

cd "$ROOT"

export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
# Splat 19.3.1 的作者证书已被吊销，restore 会报 NU3012；构建产物不受影响。
export DOTNET_NUGET_SIGNATURE_VERIFICATION=false

echo "==> 清理输出目录"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> 发布主程序（自包含，$RID）"
dotnet publish src/BD.WTTS.Client.Avalonia.App/BD.WTTS.Client.Avalonia.App.csproj \
  -c Release -f "$TFM" -r "$RID" --self-contained true \
  -p:PublishTrimmed=false -p:PublishAot=false -p:PublishReadyToRun=false \
  -o "$OUT" --nologo

echo "==> 发布插件"
TMP_PLUGINS="$(mktemp -d)"
trap 'rm -rf "$TMP_PLUGINS"' EXIT

for plugin in "${PLUGINS[@]}"; do
  echo "    - $plugin"
  dotnet publish "src/BD.WTTS.Client.Plugins.$plugin/BD.WTTS.Client.Plugins.$plugin.csproj" \
    -c Release -f "$TFM" -r "$RID" --self-contained false \
    -p:PublishTrimmed=false -o "$TMP_PLUGINS/$plugin" --nologo
  mkdir -p "$OUT/modules/$plugin"
  cp "$TMP_PLUGINS/$plugin/BD.WTTS.Client.Plugins.$plugin.dll" "$OUT/modules/$plugin/"
done

echo "==> 合并插件依赖到主目录（不覆盖主程序文件）"
for dir in "$TMP_PLUGINS"/*; do
  cp -n "$dir"/*.dll "$OUT/" 2>/dev/null || true
done

echo "==> 发布加速反代子进程（自包含单文件）"
dotnet publish src/BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/BD.WTTS.Client.Plugins.Accelerator.ReverseProxy.csproj \
  -c Release -f "$TFM" -r "$RID" --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false \
  -o "$OUT/modules/Accelerator" --nologo

echo "==> 复制图标 / 安装脚本 / 说明"
cp "$ROOT/res/icons/app/v3/Logo_256.png" "$OUT/steampp.png"
cp "$ROOT/LICENSE" "$OUT/LICENSE"
cp "$ROOT/build/linux/install.sh" "$OUT/install.sh"
cp "$ROOT/build/linux/README-便携版.txt" "$OUT/README-便携版.txt"
chmod +x "$OUT/install.sh" "$OUT/modules/Accelerator/Steam++.Accelerator"

echo "==> 打包"
cd "$ROOT/artifacts"
ARCHIVE="WattToolkit_${RID}_selfbuilt_${VERSION}.tar.zst"
tar --zstd -cf "$ARCHIVE" "Steam++_$RID"
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

echo
echo "完成："
echo "  目录  $OUT"
echo "  压缩  $ROOT/artifacts/$ARCHIVE"
du -sh "$OUT" "$ARCHIVE"
