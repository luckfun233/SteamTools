#!/usr/bin/env bash
# 在 Linux 上构建并打包 NetAccel（CLI + Avalonia 界面）。
# 默认同时产出 linux-x64 与 win-x64；可用 TARGETS 环境变量只构建其中之一。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${CONFIG:-Release}"
VERSION="${VERSION:-1.0.0}"
TARGETS="${TARGETS:-linux-x64 win-x64}"
ARTIFACTS="$ROOT/artifacts"
DOTNET="${DOTNET:-dotnet}"

export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

echo "== NetAccel 打包 =="
echo "版本: $VERSION"
echo "目标: $TARGETS"
echo "输出: $ARTIFACTS"
echo

echo "== 1/4 运行测试 =="
"$DOTNET" test "$ROOT/tests/NetAccel.Core.Tests/NetAccel.Core.Tests.csproj" -c "$CONFIG" --nologo

publish() {
  local project="$1"
  local rid="$2"
  local out="$3"

  echo "--> publish $(basename "$project") $rid"
  rm -rf "$out"
  "$DOTNET" publish "$project" \
    -c "$CONFIG" \
    -r "$rid" \
    --self-contained true \
    -p:PublishSingleFile=false \
    -p:PublishTrimmed=false \
    -p:DebugType=none \
    -o "$out"
}

mkdir -p "$ARTIFACTS"

for rid in $TARGETS; do
  echo
  echo "== 2/4 发布 $rid =="
  publish "$ROOT/src/NetAccel.Cli/NetAccel.Cli.csproj" "$rid" "$ARTIFACTS/netaccel-cli-$rid"
  publish "$ROOT/src/NetAccel.App/NetAccel.App.csproj" "$rid" "$ARTIFACTS/netaccel-app-$rid"
done

if [[ " $TARGETS " == *" linux-x64 "* ]]; then
  echo
  echo "== 3/4 发布产物自检 =="
  "$ARTIFACTS/netaccel-cli-linux-x64/netaccel" selftest \
    --data-dir "$ARTIFACTS/selftest-data" --verbose
fi

echo
echo "== 4/4 归档 =="
python3 - "$ARTIFACTS" "$VERSION" $TARGETS <<'PY'
import os
import sys
import tarfile
import zipfile

artifacts, version = sys.argv[1], sys.argv[2]
targets = sys.argv[3:]

for rid in targets:
    folders = [f for f in (f"netaccel-cli-{rid}", f"netaccel-app-{rid}")
               if os.path.isdir(os.path.join(artifacts, f))]
    if not folders:
        continue

    if rid.startswith("linux"):
        archive = os.path.join(artifacts, f"netaccel-{rid}-{version}.tar.gz")
        with tarfile.open(archive, "w:gz") as tar:
            for folder in folders:
                tar.add(os.path.join(artifacts, folder), arcname=folder)
    else:
        archive = os.path.join(artifacts, f"netaccel-{rid}-{version}.zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for folder in folders:
                base = os.path.join(artifacts, folder)
                for root, _, files in os.walk(base):
                    for name in files:
                        full = os.path.join(root, name)
                        zf.write(full, os.path.relpath(full, artifacts))

    print("归档:", archive, f"({os.path.getsize(archive) / 1024 / 1024:.1f} MB)")
PY

echo
echo "完成。产物位于: $ARTIFACTS"
