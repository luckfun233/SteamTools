#!/usr/bin/env bash
# 构建 Android APK（arm64，自包含，免安装 .NET 运行时）。
# 需要 JDK 17、Android SDK（platform 34 / build-tools 34）与 dotnet android workload。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${CONFIG:-Release}"
VERSION="${VERSION:-1.0.0}"
ARTIFACTS="$ROOT/artifacts"
DOTNET="${DOTNET:-dotnet}"

JAVA_HOME="${JAVA_HOME:-}"
ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"

if [[ -z "$JAVA_HOME" || ! -x "$JAVA_HOME/bin/java" ]]; then
  echo "请设置 JAVA_HOME 指向 JDK 17（当前: ${JAVA_HOME:-未设置}）" >&2
  exit 1
fi

if [[ -z "$ANDROID_HOME" || ! -d "$ANDROID_HOME/platforms/android-34" ]]; then
  echo "请设置 ANDROID_HOME，并安装 platforms;android-34" >&2
  exit 1
fi

KEYSTORE="${KEYSTORE:-/tmp/netaccel-release.keystore}"
KEY_ALIAS="${KEY_ALIAS:-netaccel}"
KEY_PASS="${KEY_PASS:-netaccel123}"

if [[ ! -f "$KEYSTORE" ]]; then
  echo "生成演示签名证书: $KEYSTORE"
  "$JAVA_HOME/bin/keytool" -genkeypair \
    -keystore "$KEYSTORE" \
    -alias "$KEY_ALIAS" \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$KEY_PASS" -keypass "$KEY_PASS" \
    -dname "CN=NetAccel,O=NetAccel,C=CN" -noprompt >/dev/null
fi

mkdir -p "$ARTIFACTS/android"
echo "== 发布 Android APK =="
"$DOTNET" publish "$ROOT/src/NetAccel.Android/NetAccel.Android.csproj" \
  -c "$CONFIG" \
  -f net8.0-android \
  -p:AndroidSdkDirectory="$ANDROID_HOME" \
  -p:JavaSdkDirectory="$JAVA_HOME" \
  -p:AndroidPackageFormats=apk \
  -p:AndroidKeyStore=true \
  -p:AndroidSigningKeyStore="$KEYSTORE" \
  -p:AndroidSigningKeyAlias="$KEY_ALIAS" \
  -p:AndroidSigningKeyPass="$KEY_PASS" \
  -p:AndroidSigningStorePass="$KEY_PASS" \
  -o "$ARTIFACTS/android"

SIGNED="$ARTIFACTS/android/com.netaccel.android-Signed.apk"
if [[ ! -f "$SIGNED" ]]; then
  echo "没有找到签名 APK: $SIGNED" >&2
  exit 1
fi

TARGET="$ARTIFACTS/NetAccel-android-arm64-$VERSION.apk"
cp "$SIGNED" "$TARGET"

echo
echo "APK: $TARGET"
ls -lh "$TARGET"
if command -v sha256sum >/dev/null; then
  sha256sum "$TARGET"
fi

if [[ -x "$ANDROID_HOME/build-tools/34.0.0/apksigner" ]]; then
  "$ANDROID_HOME/build-tools/34.0.0/apksigner" verify --print-certs "$TARGET" 2>/dev/null | head -5
fi
