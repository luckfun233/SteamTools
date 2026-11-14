using System.Text;
using System.Text.RegularExpressions;
using NetAccel.Core.Models;

namespace NetAccel.Core.Logging;

public interface IAccelLogger
{
    void Info(string tag, string message);
    void Warn(string tag, string message);
    void Error(string tag, string message, Exception? exception = null);
}

public sealed class NullLogger : IAccelLogger
{
    public static readonly NullLogger Instance = new();
    public void Info(string tag, string message) { }
    public void Warn(string tag, string message) { }
    public void Error(string tag, string message, Exception? exception = null) { }
}

/// <summary>
/// 轻量文件日志：按天归档、单文件大小限制、敏感查询参数脱敏、可隐藏主机名。
/// 写日志永远不能影响代理主流程，所有 IO 异常都会被吞掉。
/// </summary>
public sealed class FileLogger : IAccelLogger, IDisposable
{
    readonly object sync = new();
    readonly string directory;
    readonly Func<bool> enabled;
    readonly Func<int> minimumLevel;
    readonly Func<bool> includeHost;
    readonly Func<int> retentionDays;
    readonly Func<int> maxFileSizeKB;
    readonly Action<string>? mirror;

    string? currentFile;
    long currentSize;
    DateTime currentDate;

    static readonly Regex sensitiveQueryRegex = new(
        @"(?i)(token|sig|signature|jwt|password|passwd|secret|key|auth)=([^&\s]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    static readonly Regex hostRegex = new(
        @"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public FileLogger(
        string directory,
        Func<bool>? enabled = null,
        Func<int>? minimumLevel = null,
        Func<bool>? includeHost = null,
        Func<int>? retentionDays = null,
        Func<int>? maxFileSizeKB = null,
        Action<string>? mirror = null)
    {
        this.directory = directory;
        this.enabled = enabled ?? (() => true);
        this.minimumLevel = minimumLevel ?? (() => 0);
        this.includeHost = includeHost ?? (() => true);
        this.retentionDays = retentionDays ?? (() => 7);
        this.maxFileSizeKB = maxFileSizeKB ?? (() => 4096);
        this.mirror = mirror;
        TryCleanup();
    }

    public string Directory => directory;

    public void Info(string tag, string message) => Write(0, "INFO", tag, message, null);

    public void Warn(string tag, string message) => Write(1, "WARN", tag, message, null);

    public void Error(string tag, string message, Exception? exception = null)
        => Write(2, "ERROR", tag, message, exception);

    void Write(int level, string levelText, string tag, string message, Exception? exception)
    {
        try
        {
            if (!enabled()) return;
            if (level < Math.Clamp(minimumLevel(), 0, 2)) return;

            var text = Sanitize(message);
            if (!includeHost()) text = hostRegex.Replace(text, "***");
            if (exception != null)
            {
                text += " | " + exception.GetType().Name + ": " + Sanitize(exception.Message);
            }

            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{levelText}] [{tag}] {text}";
            mirror?.Invoke(line);

            lock (sync)
            {
                EnsureFile();
                if (currentFile == null) return;
                var block = line + Environment.NewLine;
                File.AppendAllText(currentFile, block, Encoding.UTF8);
                currentSize += Encoding.UTF8.GetByteCount(block);
            }
        }
        catch
        {
            // 日志失败不能影响代理主流程
        }
    }

    void EnsureFile()
    {
        var now = DateTime.Now;
        var maxBytes = Math.Max(64, maxFileSizeKB()) * 1024L;
        if (currentFile != null && currentDate.Date == now.Date && currentSize < maxBytes) return;

        System.IO.Directory.CreateDirectory(directory);
        currentDate = now.Date;
        var file = Path.Combine(directory, $"netaccel-{now:yyyy-MM-dd}.log");
        if (File.Exists(file) && new FileInfo(file).Length >= maxBytes)
        {
            file = Path.Combine(directory, $"netaccel-{now:yyyy-MM-dd-HHmmss}.log");
        }
        currentFile = file;
        currentSize = File.Exists(file) ? new FileInfo(file).Length : 0;
    }

    void TryCleanup()
    {
        try
        {
            if (!System.IO.Directory.Exists(directory)) return;
            var threshold = DateTime.Now.AddDays(-Math.Max(1, retentionDays()));
            foreach (var file in System.IO.Directory.GetFiles(directory, "netaccel-*.log"))
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
        catch
        {
            // ignore
        }
    }

    public static string Sanitize(string message)
    {
        if (string.IsNullOrEmpty(message)) return string.Empty;
        return sensitiveQueryRegex.Replace(message, "$1=***");
    }

    /// <summary>
    /// 读取最近的日志，供实验室报告使用。
    /// </summary>
    public string ReadRecent(int maxLines = 300)
    {
        try
        {
            if (!System.IO.Directory.Exists(directory)) return string.Empty;
            var files = System.IO.Directory.GetFiles(directory, "netaccel-*.log");
            if (files.Length == 0) return string.Empty;
            Array.Sort(files, (a, b) => File.GetLastWriteTime(b).CompareTo(File.GetLastWriteTime(a)));

            var remaining = Math.Max(20, maxLines);
            var blocks = new List<string>();
            foreach (var file in files)
            {
                if (remaining <= 0) break;
                try
                {
                    var lines = File.ReadAllLines(file);
                    if (lines.Length == 0) continue;
                    var take = Math.Min(remaining, lines.Length);
                    var start = lines.Length - take;
                    var sb = new StringBuilder();
                    sb.AppendLine($"--- {Path.GetFileName(file)} ---");
                    for (var i = start; i < lines.Length; i++) sb.AppendLine(lines[i]);
                    blocks.Add(sb.ToString());
                    remaining -= take;
                }
                catch
                {
                    // 单个文件失败时继续
                }
            }
            blocks.Reverse();
            return string.Join(Environment.NewLine, blocks).Trim();
        }
        catch
        {
            return string.Empty;
        }
    }

    public void Dispose()
    {
        // 无占用中的文件句柄，这里只做兼容实现。
    }
}

/// <summary>
/// 同时写文件与推送到界面日志面板。
/// </summary>
public sealed class CompositeLogger : IAccelLogger
{
    readonly IAccelLogger primary;
    readonly IAccelLogger secondary;

    public CompositeLogger(IAccelLogger primary, IAccelLogger secondary)
    {
        this.primary = primary;
        this.secondary = secondary;
    }

    public void Info(string tag, string message)
    {
        primary.Info(tag, message);
        secondary.Info(tag, message);
    }

    public void Warn(string tag, string message)
    {
        primary.Warn(tag, message);
        secondary.Warn(tag, message);
    }

    public void Error(string tag, string message, Exception? exception = null)
    {
        primary.Error(tag, message, exception);
        secondary.Error(tag, message, exception);
    }
}

/// <summary>
/// 只把最近 500 行保存在内存里，供 UI 日志面板读取。
/// </summary>
public sealed class MemoryLogger : IAccelLogger
{
    readonly object sync = new();
    readonly Queue<string> lines = new();
    readonly int capacity;

    public MemoryLogger(int capacity = 500)
    {
        this.capacity = Math.Max(50, capacity);
    }

    public event Action? Changed;

    public IReadOnlyList<string> Lines
    {
        get
        {
            lock (sync) return lines.ToArray();
        }
    }

    public void Info(string tag, string message) => Add("INFO", tag, message);

    public void Warn(string tag, string message) => Add("WARN", tag, message);

    public void Error(string tag, string message, Exception? exception = null)
        => Add("ERROR", tag, exception == null ? message : $"{message} | {exception.GetType().Name}: {exception.Message}");

    void Add(string level, string tag, string message)
    {
        var line = $"{DateTime.Now:HH:mm:ss} [{level}] [{tag}] {FileLogger.Sanitize(message)}";
        lock (sync)
        {
            lines.Enqueue(line);
            while (lines.Count > capacity) lines.Dequeue();
        }
        Changed?.Invoke();
    }

    public void Clear()
    {
        lock (sync) lines.Clear();
        Changed?.Invoke();
    }
}
