using System;
using System.Application.Settings;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Application.ProxyRules;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 本地 UDP DNS 代理。VPN 通过 tun2socks 的 --dnsgw 把 UDP:53 直接送到这里，
    /// 代理优先用 DoH（wire format）解析，避免 DNS 污染；DoH 不可用时按设置回退到公共 DNS。
    ///
    /// 这是免证书/有证书两种模式共用的基础能力：
    /// tun2socks 的 SOCKS5 UDP ASSOCIATE 不是所有上游都支持，把 DNS 单独走本地代理最稳定。
    /// </summary>
    public sealed class DnsProxyServer : IDisposable
    {
        const int MaxQueryLength = 4096;
        const int MaxCacheEntries = 512;

        readonly int port;
        readonly UdpClient udp;
        readonly CancellationTokenSource cts = new();
        readonly SemaphoreSlim concurrency = new(32, 32);
        Task? loopTask;

        static readonly ConcurrentDictionary<string, CacheItem> cache = new(StringComparer.Ordinal);
        static long totalQueries;
        static long dohQueries;
        static long dohSuccesses;
        static long cacheHits;
        static long fallbackQueries;
        static long failures;
        static long presetOverrides;
        static long bytesUp;
        static long bytesDown;

        public DnsProxyServer(int port)
        {
            this.port = port;
            udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        }

        public int Port => port;

        public void Start()
        {
            loopTask = LoopAsync();
            ProxyDiagnostics.Info("DnsProxy", $"本地 DNS 代理已启动 127.0.0.1:{port}");
        }

        async Task LoopAsync()
        {
            while (!cts.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    result = await udp.ReceiveAsync().ConfigureAwait(false);
                }
                catch (Exception) when (cts.IsCancellationRequested)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    ProxyDiagnostics.Warn("DnsProxy", $"接收 DNS 查询失败: {ex.Message}");
                    continue;
                }

                _ = HandleAsync(result);
            }
        }

        async Task HandleAsync(UdpReceiveResult result)
        {
            var query = result.Buffer;
            if (query == null || query.Length < 12 || query.Length > MaxQueryLength) return;

            var acquired = false;
            try
            {
                await concurrency.WaitAsync(cts.Token).ConfigureAwait(false);
                acquired = true;

                Interlocked.Increment(ref totalQueries);
                Interlocked.Add(ref bytesUp, query.Length);

                // DevSidecar dns.mapping：按域名选择配置里指定的 DoH provider。
                var hasQueryInfo = TryGetQueryInfo(query, out var queryHost, out var queryType);
                var endpoint = string.IsNullOrEmpty(queryHost)
                    ? null
                    : ProxyRuleEngine.Current.GetDohEndpoint(queryHost!);

                var cacheKey = GetCacheKey(query, endpoint);
                if (TryGetCache(cacheKey, query, out var cached))
                {
                    Interlocked.Increment(ref cacheHits);
                    await SendAsync(result.RemoteEndPoint, cached).ConfigureAwait(false);
                    return;
                }

                byte[]? response = null;
                if (ProxySettings.EnableDoh.Value)
                {
                    Interlocked.Increment(ref dohQueries);
                    response = await DohWireResolver.QueryAsync(query, endpoint, cts.Token).ConfigureAwait(false);
                }

                if (response == null && ProxySettings.DohFallbackToSystem.Value)
                {
                    Interlocked.Increment(ref fallbackQueries);
                    response = await QueryFallbackDnsAsync(query, cts.Token).ConfigureAwait(false);
                }

                if (response != null && hasQueryInfo && ProxySettings.EnableDnsPresetIp.Value)
                {
                    var rewritten = ApplyPresetIps(query, queryHost!, queryType);
                    if (rewritten != null)
                    {
                        response = rewritten;
                        Interlocked.Increment(ref presetOverrides);
                    }
                }

                if (response == null)
                {
                    Interlocked.Increment(ref failures);
                    response = BuildErrorResponse(query, 2); // SERVFAIL
                }
                else if (response.Length >= 12)
                {
                    SetCache(cacheKey, response);
                }

                await SendAsync(result.RemoteEndPoint, response).ConfigureAwait(false);
            }
            catch (Exception ex) when (!cts.IsCancellationRequested)
            {
                Interlocked.Increment(ref failures);
                ProxyDiagnostics.Warn("DnsProxy", $"处理 DNS 查询失败: {ex.Message}");
                try
                {
                    await SendAsync(result.RemoteEndPoint, BuildErrorResponse(query, 2)).ConfigureAwait(false);
                }
                catch
                {
                    // 客户端可能已经断开
                }
            }
            finally
            {
                if (acquired) concurrency.Release();
            }
        }

        async Task SendAsync(IPEndPoint client, byte[] response)
        {
            if (response.Length == 0) return;
            try
            {
                await udp.SendAsync(response, response.Length, client).ConfigureAwait(false);
                Interlocked.Add(ref bytesDown, response.Length);
            }
            catch (Exception ex)
            {
                ProxyDiagnostics.Warn("DnsProxy", $"发送 DNS 响应失败: {ex.Message}");
            }
        }

        static async Task<byte[]?> QueryFallbackDnsAsync(byte[] query, CancellationToken cancellationToken)
        {
            foreach (var server in ProxySettings.GetDnsFallbackServers())
            {
                try
                {
                    using var client = new UdpClient(server.AddressFamily);
                    client.Connect(server);
                    await client.SendAsync(query, query.Length).ConfigureAwait(false);

                    var receiveTask = client.ReceiveAsync();
                    var completed = await Task.WhenAny(
                        receiveTask,
                        Task.Delay(TimeSpan.FromSeconds(3), cancellationToken)).ConfigureAwait(false);
                    if (completed != receiveTask) continue;

                    var response = receiveTask.Result.Buffer;
                    if (response != null && response.Length >= 12)
                    {
                        // 修正 ID，部分运营商会改写
                        response[0] = query[0];
                        response[1] = query[1];
                        return response;
                    }
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    ProxyDiagnostics.Warn("DnsProxy", $"回退 DNS {server} 查询失败: {ex.Message}");
                }
            }
            return null;
        }

        static string GetCacheKey(byte[] query, string? endpoint)
        {
            // 跳过前 2 字节 ID，其余部分（问题、EDNS 等）作为键；不同 DoH provider 分开缓存。
            return (endpoint ?? string.Empty) + "|" + Convert.ToBase64String(query, 2, query.Length - 2);
        }

        /// <summary>
        /// 读取 DNS 查询的 QNAME 和 QTYPE。只处理未压缩的问题名（查询报文不会压缩）。
        /// </summary>
        static bool TryGetQueryInfo(byte[] query, out string name, out ushort qtype)
        {
            name = string.Empty;
            qtype = 0;
            if (query.Length < 17) return false;

            var offset = 12;
            var sb = new StringBuilder();
            while (offset < query.Length)
            {
                var length = query[offset++];
                if (length == 0)
                {
                    if (offset + 4 > query.Length) return false;
                    qtype = (ushort)((query[offset] << 8) | query[offset + 1]);
                    name = sb.ToString();
                    return name.Length > 0;
                }
                if ((length & 0xC0) != 0 || offset + length > query.Length) return false;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(query, offset, length));
                offset += length;
                if (sb.Length > 253) return false;
            }
            return false;
        }

        /// <summary>
        /// 用 DevSidecar preSetIpList 重写 DNS A/AAAA 响应。
        /// VPN/tun2socks 只拿到 IP，只有把预置 IP 直接写进 DNS，免证书模式才能用上它们。
        /// </summary>
        static byte[]? ApplyPresetIps(byte[] query, string host, ushort qtype)
        {
            if (qtype != 1 && qtype != 28) return null;
            if (!ProxyRuleEngine.IsServiceEnabled(host)) return null;

            var candidates = ProxyPresetIpProvider.GetCandidates(host);

            var addresses = new List<IPAddress>();
            foreach (var candidate in candidates)
            {
                if (!IPAddress.TryParse(candidate.Trim(), out var address)) continue;
                var isV6 = address.AddressFamily == AddressFamily.InterNetworkV6;
                if (qtype == 1 && isV6) continue;
                if (qtype == 28 && !isV6) continue;
                if (addresses.Contains(address)) continue;
                addresses.Add(address);
            }

            if (addresses.Count == 0) return null;

            if (TryGetQuestionEnd(query, out var questionEnd))
            {
                var answerBytes = addresses.Sum(x => x.AddressFamily == AddressFamily.InterNetworkV6 ? 28 : 16);
                var response = new byte[questionEnd + answerBytes];
                Buffer.BlockCopy(query, 0, response, 0, questionEnd);
                response[2] = 0x81; // QR + RD
                response[3] = 0x80; // RA, RCODE=0
                response[4] = 0x00; response[5] = 0x01;
                response[6] = (byte)(addresses.Count >> 8); response[7] = (byte)(addresses.Count & 0xFF);
                response[8] = 0; response[9] = 0;
                response[10] = 0; response[11] = 0;

                var offset = questionEnd;
                foreach (var address in addresses)
                {
                    var bytes = address.GetAddressBytes();
                    response[offset++] = 0xC0;
                    response[offset++] = 0x0C;
                    response[offset++] = 0x00;
                    response[offset++] = (byte)(qtype == 1 ? 1 : 28);
                    response[offset++] = 0x00;
                    response[offset++] = 0x01;
                    response[offset++] = 0x00; response[offset++] = 0x00;
                    response[offset++] = 0x00; response[offset++] = 0x3C;
                    response[offset++] = 0x00;
                    response[offset++] = (byte)bytes.Length;
                    bytes.CopyTo(response, offset);
                    offset += bytes.Length;
                }

                ProxyDiagnostics.Info("DnsProxy",
                    $"预置 IP: {host} -> {string.Join(",", addresses.Select(x => x.ToString()))}");
                return response;
            }

            return null;
        }

        static bool TryGetCache(string key, byte[] query, out byte[] response)
        {
            response = Array.Empty<byte>();
            if (!cache.TryGetValue(key, out var item)) return false;
            if (item.ExpireAt <= DateTime.UtcNow)
            {
                cache.TryRemove(key, out _);
                return false;
            }

            response = (byte[])item.Response.Clone();
            response[0] = query[0];
            response[1] = query[1];
            return true;
        }

        static void SetCache(string key, byte[] response)
        {
            if (cache.Count >= MaxCacheEntries)
            {
                // 简单清理：移除已过期项；仍然过多时整体清空，避免无界增长。
                var now = DateTime.UtcNow;
                foreach (var pair in cache)
                {
                    if (pair.Value.ExpireAt <= now) cache.TryRemove(pair.Key, out _);
                }
                if (cache.Count >= MaxCacheEntries) cache.Clear();
            }
            cache[key] = new CacheItem((byte[])response.Clone(), DateTime.UtcNow.AddSeconds(60));
        }

        /// <summary>
        /// 构造最小错误响应。保留原始 Question，避免客户端校验失败。
        /// </summary>
        static byte[] BuildErrorResponse(byte[] query, int rcode)
        {
            var hasQuestion = TryGetQuestionEnd(query, out var end);
            var questionEnd = hasQuestion ? end : Math.Min(12, query.Length);
            var response = new byte[questionEnd];
            Buffer.BlockCopy(query, 0, response, 0, questionEnd);

            response[2] = (byte)(0x80 | (query[2] & 0x01)); // QR=1，保留 RD
            response[3] = (byte)(0x80 | (rcode & 0x0F));    // RA=1 + RCODE
            response[4] = 0; response[5] = hasQuestion ? (byte)1 : (byte)0;
            response[6] = 0; response[7] = 0;               // ANCOUNT
            response[8] = 0; response[9] = 0;               // NSCOUNT
            response[10] = 0; response[11] = 0;             // ARCOUNT
            return response;
        }

        static bool TryGetQuestionEnd(byte[] query, out int end)
        {
            end = 12;
            if (query.Length < 12) return false;

            var position = 12;
            while (position < query.Length)
            {
                var length = query[position];
                if (length == 0)
                {
                    position++;
                    break;
                }
                if ((length & 0xC0) != 0) return false; // 问题段不应出现压缩指针
                position += length + 1;
                if (position >= query.Length) return false;
            }

            if (position + 4 > query.Length) return false;
            end = position + 4; // QTYPE + QCLASS
            return true;
        }

        public void Stop()
        {
            try
            {
                cts.Cancel();
                udp.Dispose();
            }
            catch
            {
                // ignore
            }
            ProxyDiagnostics.Info("DnsProxy", "本地 DNS 代理已停止");
        }

        public void Dispose()
        {
            Stop();
            cts.Dispose();
            concurrency.Dispose();
        }

        internal static void OnDohSuccess() => Interlocked.Increment(ref dohSuccesses);

        public static string GetStats()
        {
            return $"查询 {Interlocked.Read(ref totalQueries)}，缓存 {Interlocked.Read(ref cacheHits)}，" +
                   $"DoH 尝试 {Interlocked.Read(ref dohQueries)} 成功 {Interlocked.Read(ref dohSuccesses)}，" +
                   $"回退 {Interlocked.Read(ref fallbackQueries)}，预置IP改写 {Interlocked.Read(ref presetOverrides)}，" +
                   $"失败 {Interlocked.Read(ref failures)}，上行 {Interlocked.Read(ref bytesUp)}B，下行 {Interlocked.Read(ref bytesDown)}B";
        }

        public static void ResetStats()
        {
            Interlocked.Exchange(ref totalQueries, 0);
            Interlocked.Exchange(ref dohQueries, 0);
            Interlocked.Exchange(ref dohSuccesses, 0);
            Interlocked.Exchange(ref cacheHits, 0);
            Interlocked.Exchange(ref fallbackQueries, 0);
            Interlocked.Exchange(ref failures, 0);
            Interlocked.Exchange(ref presetOverrides, 0);
            Interlocked.Exchange(ref bytesUp, 0);
            Interlocked.Exchange(ref bytesDown, 0);
            cache.Clear();
        }

        sealed class CacheItem
        {
            public CacheItem(byte[] response, DateTime expireAt)
            {
                Response = response;
                ExpireAt = expireAt;
            }

            public byte[] Response { get; }

            public DateTime ExpireAt { get; }
        }
    }

    /// <summary>
    /// 本地 DNS 代理的启动/停止入口。端口被占用时自动向后寻找可用端口。
    /// </summary>
    public static class DnsProxyService
    {
        static readonly object sync = new();
        static DnsProxyServer? server;

        public static bool IsRunning
        {
            get
            {
                lock (sync) return server != null;
            }
        }

        public static int Port => ProxySettings.DnsProxyPortId.Value;

        public static int ActivePort
        {
            get
            {
                lock (sync) return server?.Port ?? Port;
            }
        }

        public static bool Start(bool force = false)
        {
            if (!force && !ProxySettings.EnableDnsProxy.Value) return false;
            lock (sync)
            {
                if (server != null)
                {
                    if (server.Port == Port) return true;
                    server.Dispose();
                    server = null;
                }

                var startPort = Math.Max(1, Math.Min(65535, Port));
                for (var i = 0; i < 30; i++)
                {
                    var candidate = startPort + i;
                    if (candidate > 65535) break;
                    try
                    {
                        var instance = new DnsProxyServer(candidate);
                        instance.Start();
                        server = instance;
                        return true;
                    }
                    catch (SocketException)
                    {
                        // 端口占用，尝试下一个
                    }
                    catch (Exception ex)
                    {
                        Log.Warn("DnsProxy", ex, "启动本地 DNS 代理失败");
                        ProxyDiagnostics.Warn("DnsProxy", $"启动失败: {ex.Message}");
                        break;
                    }
                }

                ProxyDiagnostics.Warn("DnsProxy", $"端口 {startPort} 起连续 30 个端口均不可用");
                return false;
            }
        }

        public static void Stop()
        {
            lock (sync)
            {
                if (server == null) return;
                server.Dispose();
                server = null;
            }
        }

        public static void Restart()
        {
            Stop();
            Start(force: true);
        }
    }
}
