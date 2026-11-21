using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Application.ProxyRules;
using System.Application.Settings;
using AndroidApplication = Android.App.Application;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 运行 APK 内置的 ByeDPI（libbyedpi.so）作为本地 SOCKS5 sidecar。
    /// 只在 C# 分片全部失败时按域名按需启动；启动失败会自动退回原路径。
    /// </summary>
    public static class ByedpiService
    {
        const string TAG = "ByeDPI";

        static readonly object sync = new();
        static Process? process;
        static int port;
        static bool startFailed;

        public static bool IsRunning
        {
            get
            {
                lock (sync)
                {
                    return process != null && !process.HasExited;
                }
            }
        }

        public static int Port
        {
            get
            {
                lock (sync) return port;
            }
        }

        public static void InstallRuntimeHooks()
        {
            ByedpiRuntime.EnsureStarted = EnsureStarted;
            ByedpiRuntime.Stop = Stop;
            ByedpiRuntime.IsRunning = () => IsRunning;
            ByedpiRuntime.GetPort = () => Port;
            ByedpiRuntime.ShouldUse = ShouldUse;
            ByedpiRuntime.ResetFailure = ResetFailure;
        }

        public static bool ShouldUse(string host)
        {
            if (!ProxySettings.EnableByedpi.Value) return false;
            if (string.IsNullOrWhiteSpace(host)) return false;

            foreach (var pattern in ProxySettings.ByedpiDomains.Value
                         .Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (DomainPatternMatcher.IsMatch(host, pattern.Trim())) return true;
            }
            return false;
        }

        public static bool EnsureStarted()
        {
            if (!ProxySettings.EnableByedpi.Value) return false;

            lock (sync)
            {
                if (process != null && !process.HasExited) return true;
                if (startFailed) return false;
                DisposeProcess();

                var executable = GetExecutablePath();
                if (executable == null)
                {
                    startFailed = true;
                    ProxyDiagnostics.Warn(TAG, "找不到 libciadpi.so / libbyedpi.so，已退回 C# 分片");
                    return false;
                }

                var startPort = Math.Max(1024, Math.Min(65535, ProxySettings.ByedpiPortId.Value));
                for (var i = 0; i < 30; i++)
                {
                    var candidate = startPort + i;
                    if (candidate > 65535) break;
                    if (IsPortInUse(candidate)) continue;

                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = executable,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true,
                        };
                        foreach (var arg in BuildArgs(candidate))
                        {
                            psi.ArgumentList.Add(arg);
                        }

                        var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
                        p.OutputDataReceived += (_, e) => LogLine(e.Data);
                        p.ErrorDataReceived += (_, e) => LogLine(e.Data);
                        p.Exited += (_, _) => OnExited(p);

                        if (!p.Start())
                        {
                            p.Dispose();
                            continue;
                        }

                        p.BeginOutputReadLine();
                        p.BeginErrorReadLine();
                        process = p;
                        port = candidate;

                        if (WaitForPort(candidate, 1500))
                        {
                            startFailed = false;
                            ProxyDiagnostics.Info(TAG, $"已启动 127.0.0.1:{candidate}，参数: {string.Join(" ", BuildArgs(candidate))}");
                            return true;
                        }

                        ProxyDiagnostics.Warn(TAG, $"启动后端口 {candidate} 未监听，已停止");
                        try { p.Kill(); } catch { }
                        p.Dispose();
                        process = null;
                        port = 0;
                        break;
                    }
                    catch (Exception ex)
                    {
                        ProxyDiagnostics.Warn(TAG, $"启动失败: {ex.Message}");
                    }
                }

                // 只尝试一次；避免每个连接都等 1.5 秒。用户改设置或重启应用后会重试。
                startFailed = true;
                ProxyDiagnostics.Warn(TAG, "ByeDPI 无法启动，本次进程内不再重试");
                return false;
            }
        }

        public static void ResetFailure()
        {
            startFailed = false;
        }

        public static void Stop()
        {
            lock (sync)
            {
                DisposeProcess();
            }
        }

        static void DisposeProcess()
        {
            var p = process;
            process = null;
            port = 0;
            if (p == null) return;

            try
            {
                if (!p.HasExited) p.Kill();
            }
            catch
            {
                // ignore
            }
            finally
            {
                try { p.Dispose(); } catch { }
            }
        }

        static void OnExited(Process p)
        {
            lock (sync)
            {
                if (ReferenceEquals(process, p))
                {
                    process = null;
                    port = 0;
                }
            }
            ProxyDiagnostics.Warn(TAG, "ByeDPI 进程已退出");
        }

        static string? GetExecutablePath()
        {
            try
            {
                var dir = AndroidApplication.Context.ApplicationInfo?.NativeLibraryDir;
                if (string.IsNullOrEmpty(dir)) return null;

                // 优先使用从 ByeDPI 源码编译的独立 ciadpi；JNI 版 libbyedpi.so 仅作兜底。
                foreach (var name in new[] { "libciadpi.so", "libbyedpi.so" })
                {
                    var path = Path.Combine(dir, name);
                    if (File.Exists(path)) return path;
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        static IEnumerable<string> BuildArgs(int listenPort)
        {
            var args = new List<string>
            {
                "-i", "127.0.0.1",
                "-p", listenPort.ToString(),
                "-x", "1",
                "-c", "256",
                "-K", "t",
            };

            switch (ProxySettings.ByedpiPreset.Value)
            {
                case 1:
                    args.AddRange(new[] { "--fake", "-1", "--ttl", "8", "--tls-sni", "www.iana.org" });
                    break;
                case 2:
                    args.AddRange(new[] { "--oob", "1+s" });
                    break;
                case 3:
                    args.AddRange(new[] { "--split", "1+s" });
                    break;
                case 4:
                    args.AddRange(new[] { "--auto", "torst", "--tlsrec", "1+s" });
                    break;
                case 5:
                    args.Clear();
                    args.AddRange(new[] { "-i", "127.0.0.1", "-p", listenPort.ToString(), "-x", "1", "-c", "256" });
                    args.AddRange(SplitArguments(ProxySettings.ByedpiCustomArgs.Value));
                    break;
                default:
                    args.AddRange(new[] { "--disorder", "1", "--tlsrec", "1+s" });
                    break;
            }

            return args;
        }

        static IEnumerable<string> SplitArguments(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return Array.Empty<string>();

            var result = new List<string>();
            var current = new StringBuilder();
            var quote = '\0';

            foreach (var c in value)
            {
                if (quote != '\0')
                {
                    if (c == quote) quote = '\0';
                    else current.Append(c);
                }
                else if (c == '"' || c == '\'')
                {
                    quote = c;
                }
                else if (char.IsWhiteSpace(c))
                {
                    if (current.Length > 0)
                    {
                        result.Add(current.ToString());
                        current.Clear();
                    }
                }
                else
                {
                    current.Append(c);
                }
            }

            if (current.Length > 0) result.Add(current.ToString());
            return result;
        }

        static bool WaitForPort(int value, int timeoutMilliseconds)
        {
            var deadline = Environment.TickCount64 + timeoutMilliseconds;
            while (Environment.TickCount64 < deadline)
            {
                if (CanConnect(value)) return true;
                Thread.Sleep(100);
            }
            return false;
        }

        static bool CanConnect(int value)
        {
            try
            {
                using var client = new TcpClient();
                var task = client.ConnectAsync(IPAddress.Loopback, value);
                if (!task.Wait(200)) return false;
                return client.Connected;
            }
            catch
            {
                return false;
            }
        }

        static bool IsPortInUse(int value)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Loopback, value);
                listener.Start();
                listener.Stop();
                return false;
            }
            catch
            {
                return true;
            }
        }

        static void LogLine(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            if (ProxySettings.EnableProxyDiagnostics.Value)
            {
                ProxyDiagnostics.Info(TAG, line!);
            }
        }
    }
}
