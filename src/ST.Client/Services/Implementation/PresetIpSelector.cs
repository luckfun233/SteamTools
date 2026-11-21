using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 从 DevSidecar 的 preSetIpList 里选一个当前可连、延迟最低的 IP。
    /// 结果缓存 5 分钟，避免每个请求都探测。
    /// </summary>
    public static class PresetIpSelector
    {
        static readonly ConcurrentDictionary<string, CacheItem> cache = new();

        public static async Task<IPAddress?> PickAsync(
            IReadOnlyList<string> ips,
            int port,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            if (ips == null || ips.Count == 0) return null;

            var key = string.Join(",", ips) + ":" + port;
            if (cache.TryGetValue(key, out var cached) && cached.ExpireAt > DateTime.UtcNow)
            {
                return IPAddress.TryParse(cached.Ip, out var cachedIp) ? cachedIp : null;
            }

            var candidates = new List<IPAddress>();
            foreach (var value in ips)
            {
                if (IPAddress.TryParse(value, out var ip)) candidates.Add(ip);
            }
            if (candidates.Count == 0) return null;

            var timeoutMs = Math.Max(200, (int)timeout.TotalMilliseconds);
            if (candidates.Count == 1)
            {
                // 只有一条预置 IP 时也要探测：远程配置里的 IP 可能已经过期，
                // 直接使用会让整个规则组一直连不上（例如 startpage）。
                var single = await ProbeAsync(candidates[0], port, timeoutMs, cancellationToken).ConfigureAwait(false);
                if (single.HasValue)
                {
                    Cache(key, candidates[0]);
                    return candidates[0];
                }

                ProxyDiagnostics.Warn("IPSelector", $"唯一预置 IP 不可用，回退 DNS: {key}");
                return null;
            }

            var probes = candidates.Select(ip => ProbeAsync(ip, port, timeoutMs, cancellationToken)).ToArray();
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
                ProxyDiagnostics.Warn("IPSelector", $"预置 IP 全部不可用: {key}");
                return null;
            }

            var selected = candidates[bestIndex];
            Cache(key, selected);
            ProxyDiagnostics.Info("IPSelector", $"选择 {selected} ({bestMs}ms): {key}");
            return selected;
        }

        static async Task<long?> ProbeAsync(IPAddress ip, int port, int timeoutMs, CancellationToken cancellationToken)
        {
            using var client = new TcpClient();
            var sw = Stopwatch.StartNew();
            try
            {
                var connectTask = client.ConnectAsync(ip, port);
                var delayTask = Task.Delay(timeoutMs, cancellationToken);
                var completed = await Task.WhenAny(connectTask, delayTask).ConfigureAwait(false);
                if (completed != connectTask)
                {
                    // 取消/超时后必须回收 ConnectAsync，否则它稍后的异常会成为
                    // TaskScheduler.UnobservedTaskException，大量堆积会拖死 UI 线程。
                    client.Dispose();
                    try { await connectTask.ConfigureAwait(false); } catch { }
                    return null;
                }
                await connectTask.ConfigureAwait(false);
                return sw.ElapsedMilliseconds;
            }
            catch (Exception) when (cancellationToken.IsCancellationRequested)
            {
                return null;
            }
            catch
            {
                return null;
            }
        }

        static void Cache(string key, IPAddress ip)
        {
            cache[key] = new CacheItem
            {
                Ip = ip.ToString(),
                ExpireAt = DateTime.UtcNow.AddMinutes(5),
            };
        }

        sealed class CacheItem
        {
            public string Ip { get; init; } = string.Empty;

            public DateTime ExpireAt { get; init; }
        }
    }
}
