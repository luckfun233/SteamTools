using System.Collections.Concurrent;

namespace NetAccel.Core.Stats;

/// <summary>代理运行统计。全部使用 Interlocked，连接线程并发更新无锁。</summary>
public sealed class ProxyStats
{
    long connections;
    long activeConnections;
    long fragmented;
    long rewritten;
    long presetIp;
    long relayed;
    long failures;
    long fallbacks;
    long reconnects;
    long bytesUp;
    long bytesDown;

    readonly ConcurrentDictionary<string, long> strategyCounts = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<string, long> hostFallbacks = new(StringComparer.OrdinalIgnoreCase);

    public long Connections => Interlocked.Read(ref connections);
    public long ActiveConnections => Interlocked.Read(ref activeConnections);
    public long Fragmented => Interlocked.Read(ref fragmented);
    public long Rewritten => Interlocked.Read(ref rewritten);
    public long PresetIp => Interlocked.Read(ref presetIp);
    public long Relayed => Interlocked.Read(ref relayed);
    public long Failures => Interlocked.Read(ref failures);
    public long Fallbacks => Interlocked.Read(ref fallbacks);
    public long Reconnects => Interlocked.Read(ref reconnects);
    public long BytesUp => Interlocked.Read(ref bytesUp);
    public long BytesDown => Interlocked.Read(ref bytesDown);

    public void OnConnection() => Interlocked.Increment(ref connections);

    public void OnFragment(string strategy)
    {
        Interlocked.Increment(ref fragmented);
        strategyCounts.AddOrUpdate(strategy, 1, (_, value) => value + 1);
    }

    public void OnRewrite() => Interlocked.Increment(ref rewritten);
    public void OnPresetIp() => Interlocked.Increment(ref presetIp);
    public void OnRelay() => Interlocked.Increment(ref relayed);
    public void OnFailure() => Interlocked.Increment(ref failures);
    public void OnFallback() => Interlocked.Increment(ref fallbacks);
    public void OnReconnect() => Interlocked.Increment(ref reconnects);
    public void OnBytesUp(long value) => Interlocked.Add(ref bytesUp, value);
    public void OnBytesDown(long value) => Interlocked.Add(ref bytesDown, value);
    public void OnActive() => Interlocked.Increment(ref activeConnections);
    public void OnActiveClosed() => Interlocked.Decrement(ref activeConnections);

    public void OnHostFallback(string host)
    {
        if (string.IsNullOrEmpty(host)) return;
        hostFallbacks.AddOrUpdate(host, 1, (_, value) => value + 1);
    }

    public string GetStrategySummary()
    {
        if (strategyCounts.IsEmpty) return "无";
        return string.Join(", ", strategyCounts.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}"));
    }

    public string GetHostFallbackSummary()
    {
        if (hostFallbacks.IsEmpty) return "无";
        return string.Join(", ", hostFallbacks.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}"));
    }

    public Snapshot GetSnapshot() => new(
        Connections,
        ActiveConnections,
        Fragmented,
        Rewritten,
        PresetIp,
        Relayed,
        Failures,
        Fallbacks,
        Reconnects,
        BytesUp,
        BytesDown,
        GetStrategySummary(),
        GetHostFallbackSummary());

    public void Reset()
    {
        Interlocked.Exchange(ref connections, 0);
        Interlocked.Exchange(ref fragmented, 0);
        Interlocked.Exchange(ref rewritten, 0);
        Interlocked.Exchange(ref presetIp, 0);
        Interlocked.Exchange(ref relayed, 0);
        Interlocked.Exchange(ref failures, 0);
        Interlocked.Exchange(ref fallbacks, 0);
        Interlocked.Exchange(ref reconnects, 0);
        Interlocked.Exchange(ref bytesUp, 0);
        Interlocked.Exchange(ref bytesDown, 0);
        strategyCounts.Clear();
        hostFallbacks.Clear();
    }

    public sealed record Snapshot(
        long Connections,
        long ActiveConnections,
        long Fragmented,
        long Rewritten,
        long PresetIp,
        long Relayed,
        long Failures,
        long Fallbacks,
        long Reconnects,
        long BytesUp,
        long BytesDown,
        string StrategySummary,
        string HostFallbackSummary);
}

/// <summary>
/// 记录“分片后立刻被重置”的域名，短时间内改用不分片，避免每次连接都先失败一次。
/// </summary>
public sealed class FragmentFallbackCache
{
    readonly Dictionary<string, DateTimeOffset> cache = new(StringComparer.OrdinalIgnoreCase);
    readonly object sync = new();

    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(10);

    public bool ShouldSkip(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        lock (sync)
        {
            if (!cache.TryGetValue(host, out var expireAt)) return false;
            if (expireAt > DateTimeOffset.UtcNow) return true;
            cache.Remove(host);
            return false;
        }
    }

    public void MarkFailure(string host, TimeSpan? duration = null)
    {
        if (string.IsNullOrEmpty(host)) return;
        lock (sync)
        {
            if (cache.Count > 2048) cache.Clear();
            cache[host] = DateTimeOffset.UtcNow.Add(duration ?? Duration);
        }
    }

    public void Clear()
    {
        lock (sync) cache.Clear();
    }

    public int Count
    {
        get
        {
            lock (sync) return cache.Count;
        }
    }
}
