# ByeDPI native binaries

- Upstream: https://github.com/hufrea/byedpi (MIT License)
- Android build source: https://github.com/dovecoteescapee/ByeDPIAndroid (release v1.2.0)
- Files: `libbyedpi.so` for arm64-v8a / armeabi-v7a / x86_64
- Purpose: optional local SOCKS5 desync sidecar. It is started as a separate
  process from the app's native library directory and only accepts connections
  from 127.0.0.1. The app falls back to the C# SNI fragmenter if it fails to start.

The binaries are unmodified copies extracted from the official ByeDPIAndroid
release APK. See `LICENSE` for the full MIT license text.
