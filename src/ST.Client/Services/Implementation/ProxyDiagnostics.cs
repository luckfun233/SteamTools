using System;
using System.Application.Settings;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 代理诊断日志：按天写文件、限制单文件大小、按天清理，并对查询参数做脱敏。
    /// 不记录 Authorization/Cookie/请求体。
    /// </summary>
    public static class ProxyDiagnostics
    {
        static readonly object sync = new();
        static string? currentFilePath;
        static long currentSize;
        static DateTime currentDate;

        static readonly Regex sensitiveQueryRegex = new(
            @"(?i)(token|sig|signature|jwt|password|passwd|secret|key)=([^&]+)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        static readonly Regex hostRegex = new(
            @"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static string LogDirectory => Path.Combine(IOPath.AppDataDirectory, "ProxyLogs");

        public static void Initialize()
        {
            if (!ProxySettings.EnableProxyDiagnostics.Value) return;
            try
            {
                Directory.CreateDirectory(LogDirectory);
                Cleanup();
            }
            catch (Exception ex)
            {
                Log.Warn("ProxyDiagnostics", ex, "初始化代理日志失败");
            }
        }

        public static void Info(string tag, string message) => Write("INFO", tag, message);

        public static void Warn(string tag, string message) => Write("WARN", tag, message);

        public static void Error(string tag, string message) => Write("ERROR", tag, message);

        public static void Clear()
        {
            try
            {
                if (!Directory.Exists(LogDirectory)) return;
                lock (sync)
                {
                    foreach (var file in Directory.GetFiles(LogDirectory, "proxy-*.log"))
                    {
                        File.Delete(file);
                    }
                    currentFilePath = null;
                    currentSize = 0;
                }
            }
            catch
            {
                // ignore
            }
        }

        public static void Write(string level, string tag, string message)
        {
            if (!ProxySettings.EnableProxyDiagnostics.Value) return;
            if (!ShouldWrite(level)) return;
            try
            {
                var now = DateTime.Now;
                var text = Sanitize(message);
                if (!ProxySettings.ProxyDiagnosticsIncludeHost.Value)
                {
                    text = hostRegex.Replace(text, "***");
                }
                var line = $"{now:yyyy-MM-dd HH:mm:ss.fff} [{level}] [{tag}] {text}{Environment.NewLine}";
                lock (sync)
                {
                    EnsureFile(now);
                    if (currentFilePath == null) return;
                    File.AppendAllText(currentFilePath, line, Encoding.UTF8);
                    currentSize += Encoding.UTF8.GetByteCount(line);
                }
            }
            catch
            {
                // 日志失败不能影响代理主流程
            }
        }

        static bool ShouldWrite(string level)
        {
            var min = Math.Max(0, Math.Min(2, ProxySettings.ProxyDiagnosticsMinimumLevel.Value));
            if (min == 0) return true;
            if (min == 1) return !string.Equals(level, "INFO", StringComparison.OrdinalIgnoreCase);
            return string.Equals(level, "ERROR", StringComparison.OrdinalIgnoreCase);
        }

        static void EnsureFile(DateTime now)
        {
            var maxBytes = Math.Max(64, ProxySettings.ProxyDiagnosticsMaxFileSizeKB.Value) * 1024L;
            if (currentFilePath != null && currentDate.Date == now.Date && currentSize < maxBytes)
            {
                return;
            }

            Directory.CreateDirectory(LogDirectory);
            currentDate = now.Date;
            var file = Path.Combine(LogDirectory, $"proxy-{now:yyyy-MM-dd}.log");
            if (File.Exists(file) && new FileInfo(file).Length >= maxBytes)
            {
                file = Path.Combine(LogDirectory, $"proxy-{now:yyyy-MM-dd-HHmmss}.log");
            }
            currentFilePath = file;
            currentSize = File.Exists(file) ? new FileInfo(file).Length : 0;
        }

        static void Cleanup()
        {
            var days = Math.Max(1, ProxySettings.ProxyDiagnosticsRetentionDays.Value);
            var threshold = DateTime.Now.AddDays(-days);
            foreach (var file in Directory.GetFiles(LogDirectory, "proxy-*.log"))
            {
                try
                {
                    if (File.GetLastWriteTime(file) < threshold) File.Delete(file);
                }
                catch
                {
                    // ignore
                }
            }
        }

        public static string Sanitize(string message)
        {
            if (string.IsNullOrEmpty(message)) return string.Empty;
            return sensitiveQueryRegex.Replace(message, "$1=***");
        }

        /// <summary>
        /// 读取最近的诊断日志，用于实验室导出。
        /// </summary>
        public static string GetRecentLogText(int maxLines = 400)
        {
            try
            {
                if (!Directory.Exists(LogDirectory)) return string.Empty;

                var files = Directory.GetFiles(LogDirectory, "proxy-*.log");
                if (files.Length == 0) return string.Empty;

                Array.Sort(files, (a, b) => File.GetLastWriteTime(b).CompareTo(File.GetLastWriteTime(a)));

                var remaining = Math.Max(20, maxLines);
                var blocks = new List<string>();

                foreach (var file in files)
                {
                    if (remaining <= 0) break;

                    try
                    {
                        var lines = new List<string>();
                        foreach (var line in File.ReadLines(file)) lines.Add(line);
                        if (lines.Count == 0) continue;

                        var take = Math.Min(remaining, lines.Count);
                        var start = lines.Count - take;
                        var block = new StringBuilder();
                        block.AppendLine($"--- {Path.GetFileName(file)} ---");
                        for (var i = start; i < lines.Count; i++) block.AppendLine(lines[i]);
                        blocks.Add(block.ToString());
                        remaining -= take;
                    }
                    catch
                    {
                        // 单个文件读取失败时继续尝试其它文件
                    }
                }

                blocks.Reverse();
                return string.Join(Environment.NewLine, blocks);
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
