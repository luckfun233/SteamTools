using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetAccel.Core.Logging;

namespace NetAccel.Core.Net;

/// <summary>
/// 从规则里的预置 IP 列表中并行探测，选出当前可连且延迟最低的一个。
/// 结果按 “IP 列表 + 端口” 缓存，失败结果只缓存很短时间。
/// </summary>
public sealed class PresetIpSelector
{
    readonly IAccelLogger log;
    readonly Dictionary<string, CacheItem> cache = new(StringComparer.OrdinalIgnoreCase);
    readonly object sync = new();

    public PresetIpSelector(IAccelLogger? logger = null)
    {
        log = logger ?? NullLogger.Instance;
    }

    public async Task<IPAddress?> PickAsync(
        IReadOnlyList<string> ips,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (ips == null || ips.Count == 0) return null;

        var key = string.Join(",", ips) + ":" + port;
        lock (sync)
        {
            if (cache.TryGetValue(key, out var cached) && cached.ExpireAt > DateTime.UtcNow)
            {
                return IPAddress.TryParse(cached.Ip, out var cachedIp) ? cachedIp : null;
            }
        }

        var candidates = new List<IPAddress>();
        foreach (var value in ips)
        {
            if (IPAddress.TryParse(value, out var ip)) candidates.Add(ip);
        }

        if (candidates.Count == 0) return null;
        if (candidates.Count == 1)
        {
            Store(key, candidates[0], TimeSpan.FromMinutes(5));
            return candidates[0];
        }

        var timeoutMs = Math.Max(200, (int)timeout.TotalMilliseconds);
        using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var probes = candidates.Select(ip => ProbeAsync(ip, port, timeoutMs, probeCts.Token)).ToArray();
        var results = await Task.WhenAll(probes).ConfigureAwait(false);

        var bestIndex = -1;
        var bestMs = long.MaxValue;
        for (var i = 0; i < results.Length; i++)
        {
            if (results[i].HasValue && results[i]!.Value < bestMs)
            {
                bestMs = results[i]!.Value;
                bestIndex = i;
            }
        }

        if (bestIndex < 0)
        {
            log.Warn("IPSelector", $"预置 IP 全部不可用: {key}");
            return null;
        }

        var selected = candidates[bestIndex];
        Store(key, selected, TimeSpan.FromMinutes(5));
        log.Info("IPSelector", $"选择 {selected} ({bestMs}ms): {key}");
        return selected;
    }

    static async Task<long?> ProbeAsync(IPAddress ip, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);
            await client.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
            return sw.ElapsedMilliseconds;
        }
        catch
        {
            return null;
        }
    }

    void Store(string key, IPAddress ip, TimeSpan ttl)
    {
        lock (sync)
        {
            if (cache.Count > 2048) cache.Clear();
            cache[key] = new CacheItem(ip.ToString(), DateTime.UtcNow.Add(ttl));
        }
    }

    public void Clear()
    {
        lock (sync) cache.Clear();
    }

    sealed class CacheItem
    {
        public CacheItem(string ip, DateTime expireAt)
        {
            Ip = ip;
            ExpireAt = expireAt;
        }

        public string Ip { get; }
        public DateTime ExpireAt { get; }
    }
}
