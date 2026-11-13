using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// SNI sidecar 运行统计，供设置页和实验室展示。
    /// </summary>
    public static class SniSidecarStats
    {
        static long connections;
        static long fragmented;
        static long rewritten;
        static long presetIp;
        static long relayed;
        static long failures;
        static long fallbacks;
        static long reconnects;
        static long bytesUp;
        static long bytesDown;

        static readonly ConcurrentDictionary<string, long> strategyCounts = new(StringComparer.OrdinalIgnoreCase);
        static readonly ConcurrentDictionary<string, long> hostFallbacks = new(StringComparer.OrdinalIgnoreCase);

        public static long Connections => Interlocked.Read(ref connections);
        public static long Fragmented => Interlocked.Read(ref fragmented);
        public static long Rewritten => Interlocked.Read(ref rewritten);
        public static long PresetIp => Interlocked.Read(ref presetIp);
        public static long Relayed => Interlocked.Read(ref relayed);
        public static long Failures => Interlocked.Read(ref failures);
        public static long Fallbacks => Interlocked.Read(ref fallbacks);
        public static long Reconnects => Interlocked.Read(ref reconnects);
        public static long BytesUp => Interlocked.Read(ref bytesUp);
        public static long BytesDown => Interlocked.Read(ref bytesDown);

        public static void OnConnection() => Interlocked.Increment(ref connections);
        public static void OnFragment() => Interlocked.Increment(ref fragmented);

        public static void OnFragment(TlsFragmentStrategy strategy)
        {
            Interlocked.Increment(ref fragmented);
            strategyCounts.AddOrUpdate(strategy.ToString(), 1, (_, value) => value + 1);
        }

        public static void OnRewrite() => Interlocked.Increment(ref rewritten);
        public static void OnPresetIp() => Interlocked.Increment(ref presetIp);
        public static void OnRelay() => Interlocked.Increment(ref relayed);
        public static void OnFailure() => Interlocked.Increment(ref failures);
        public static void OnFallback() => Interlocked.Increment(ref fallbacks);
        public static void OnReconnect() => Interlocked.Increment(ref reconnects);
        public static void OnBytesUp(long value) => Interlocked.Add(ref bytesUp, value);
        public static void OnBytesDown(long value) => Interlocked.Add(ref bytesDown, value);

        public static void OnHostFallback(string host)
        {
            if (string.IsNullOrEmpty(host)) return;
            hostFallbacks.AddOrUpdate(host, 1, (_, value) => value + 1);
        }

        public static void Reset()
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
            FragmentFallbackCache.Clear();
        }

        public static string GetStrategySummary()
        {
            if (strategyCounts.IsEmpty) return "无";
            var sb = new StringBuilder();
            foreach (var item in strategyCounts)
            {
                if (sb.Length > 0) sb.Append(", ");
                sb.Append(item.Key).Append('=').Append(item.Value);
            }
            return sb.ToString();
        }

        public static string GetHostFallbackSummary()
        {
            if (hostFallbacks.IsEmpty) return "无";
            var sb = new StringBuilder();
            foreach (var item in hostFallbacks)
            {
                if (sb.Length > 0) sb.Append(", ");
                sb.Append(item.Key).Append('=').Append(item.Value);
            }
            return sb.ToString();
        }

        public static string ToDisplayString()
            => $"连接 {Connections} / 分片 {Fragmented} / 改写 {Rewritten} / 预置IP {PresetIp} / 中继 {Relayed} / 回退 {Fallbacks} / 重连 {Reconnects} / 失败 {Failures}";
    }

    /// <summary>
    /// 记录“分片后立刻被重置”的域名，短时间内改用不分片。
    /// 避免每次连接都先失败一次，提升整体稳定性。
    /// </summary>
    public static class FragmentFallbackCache
    {
        static readonly ConcurrentDictionary<string, DateTimeOffset> cache = new(StringComparer.OrdinalIgnoreCase);
        static TimeSpan duration = TimeSpan.FromMinutes(10);

        public static TimeSpan Duration
        {
            get => duration;
            set => duration = value <= TimeSpan.Zero ? TimeSpan.FromMinutes(10) : value;
        }

        public static bool ShouldSkip(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            if (!cache.TryGetValue(host, out var expireAt)) return false;
            if (expireAt > DateTimeOffset.UtcNow) return true;
            cache.TryRemove(host, out _);
            return false;
        }

        public static void MarkFailure(string host)
        {
            if (string.IsNullOrEmpty(host)) return;
            cache[host] = DateTimeOffset.UtcNow.Add(duration);
            SniSidecarStats.OnHostFallback(host);
        }

        public static void Clear() => cache.Clear();

        public static int Count => cache.Count;
    }
}
