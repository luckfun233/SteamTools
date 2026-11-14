using System.Net.Sockets;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Rules;
using NetAccel.Core.Stats;
using NetAccel.Core.Tls;

namespace NetAccel.Core.Net;

/// <summary>
/// 处理一条已经建立上游连接的隧道：读取首个负载、按规则改写 SNI、分片发送、
/// 探测被重置时自动回退直连重试，最后双向转发。
/// SOCKS5 与 HTTP CONNECT 共用这套逻辑，避免两套实现行为不一致。
/// </summary>
public sealed class TunnelSession
{
    readonly AccelSettings settings;
    readonly RuleEngine rules;
    readonly UpstreamConnector connector;
    readonly ProxyStats stats;
    readonly FragmentFallbackCache fallbackCache;
    readonly IAccelLogger log;

    public TunnelSession(
        AccelSettings settings,
        RuleEngine rules,
        UpstreamConnector connector,
        ProxyStats stats,
        FragmentFallbackCache fallbackCache,
        IAccelLogger logger)
    {
        this.settings = settings;
        this.rules = rules;
        this.connector = connector;
        this.stats = stats;
        this.fallbackCache = fallbackCache;
        log = logger;
    }

    /// <summary>建立上游连接。供 SOCKS5 / HTTP 代理在回复客户端前调用。</summary>
    public Task<UpstreamConnection> ConnectAsync(
        string host,
        int port,
        bool excluded,
        CancellationToken cancellationToken)
        => connector.ConnectAsync(host, port, excluded, cancellationToken);

    /// <summary>规则里标记 abort 的域名直接拒绝。</summary>
    public bool IsBlocked(string host) => rules.Current.Match(host)?.Block == true;

    /// <summary>
    /// 接管连接。<paramref name="upstream"/> 的生命周期由本方法负责，
    /// 调用方在返回后不要再使用或释放它。
    /// </summary>
    public async Task RunAsync(
        NetworkStream client,
        UpstreamConnection upstream,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        var current = upstream;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            var first = await ReadFirstClientPayloadAsync(client, cts.Token).ConfigureAwait(false);

            if (first.Data == null)
            {
                if (!first.TimedOut) return;

                // 服务器先说话的协议（SMTP/IMAP/SSH 等）：不做分片，直接双向转发。
                await PumpBothAsync(client, current.Stream, null, cts.Token).ConfigureAwait(false);
                return;
            }

            var excluded = rules.Current.IsExcluded(host);
            var payload = ApplyRuleSniRewrite(first.Data, host, excluded);
            var attempts = BuildStrategyAttempts(host, payload, excluded);

            var probe = default(ProbeResult);
            var succeeded = false;

            for (var i = 0; i < attempts.Count; i++)
            {
                var attempt = attempts[i];

                if (i > 0)
                {
                    try
                    {
                        current.Client.Dispose();
                        current = await connector.ConnectAsync(host, port, excluded, cts.Token).ConfigureAwait(false);
                        stats.OnReconnect();
                        log.Info("Tunnel", $"换连接重试: {host} 策略={Describe(attempt)}");
                    }
                    catch (Exception ex) when (!cts.IsCancellationRequested)
                    {
                        stats.OnFailure();
                        log.Warn("Tunnel", $"重连失败 {host}: {ex.Message}");
                        return;
                    }
                }

                probe = await SendFirstPayloadAsync(
                    current,
                    payload,
                    attempt.HasValue,
                    attempt ?? settings.FragmentStrategy,
                    host,
                    port,
                    cts.Token).ConfigureAwait(false);

                if (!probe.Closed)
                {
                    succeeded = true;
                    if (settings.FragmentStrategy == TlsFragmentStrategy.Auto)
                    {
                        fallbackCache.RememberStrategy(host, attempt);
                    }
                    if (i > 0)
                    {
                        log.Info("Tunnel", $"回退成功: {host} 策略={Describe(attempt)}");
                    }
                    break;
                }

                // 不分片仍被关闭时，没有更多可尝试的策略。
                if (!attempt.HasValue) break;

                stats.OnFallback();
                stats.OnHostFallback(host);
                log.Warn("Tunnel", $"分片握手被重置: {host} 策略={attempt}");
            }

            if (!succeeded)
            {
                stats.OnFailure();
                fallbackCache.Duration = TimeSpan.FromMinutes(settings.FallbackCacheMinutes);
                fallbackCache.MarkFailure(host);
                if (settings.FragmentStrategy == TlsFragmentStrategy.Auto)
                {
                    fallbackCache.RememberStrategy(host, null);
                }
                log.Warn("Tunnel", $"所有策略均失败: {host}:{port}");
                return;
            }

            await PumpBothAsync(client, current.Stream, probe.Data, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            stats.OnFailure();
            log.Warn("Tunnel", $"连接处理失败 {host}:{port}: {ex.Message}");
        }
        catch (OperationCanceledException)
        {
            // 正常停止
        }
        finally
        {
            current.Client.Dispose();
        }
    }

    /// <summary>
    /// 读取客户端第一个负载。TLS 连接会等 ClientHello 完整到齐，避免分片位置算错。
    /// 超时表示客户端暂时没有发送数据（服务器先说话的协议）。
    /// </summary>
    async Task<(byte[]? Data, bool TimedOut)> ReadFirstClientPayloadAsync(
        NetworkStream client,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[32 * 1024];
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Math.Max(50, settings.FirstPayloadTimeoutMs));

        int read;
        try
        {
            read = await client.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (null, true);
        }

        if (read <= 0) return (null, false);

        var isTls = buffer[0] == 0x16;
        if (!isTls || (!settings.EnableSniFragment && !settings.EnableSniRewrite))
        {
            return (buffer[..read], false);
        }

        return (await PrepareTlsClientHelloAsync(client, buffer, read, cancellationToken).ConfigureAwait(false), false);
    }

    async Task<byte[]> PrepareTlsClientHelloAsync(
        NetworkStream client,
        byte[] buffer,
        int read,
        CancellationToken cancellationToken)
    {
        var maxBytes = Math.Max(1024, settings.MaxClientHelloBytes);
        var timeoutMs = Math.Max(50, settings.FirstPayloadTimeoutMs);

        using var data = new MemoryStream(Math.Min(read, maxBytes));
        data.Write(buffer, 0, Math.Min(read, maxBytes));

        while (data.Length < maxBytes)
        {
            if (data.Length >= 5)
            {
                var expectedLength = ExpectedLength(data);
                if (expectedLength <= 5 || expectedLength > maxBytes) break;
                if (data.Length >= expectedLength) break;
            }

            var expected = ExpectedLength(data);
            var remaining = expected > data.Length
                ? Math.Min(4096, expected - (int)data.Length)
                : 4096;
            if (remaining <= 0) break;

            var extra = new byte[remaining];
            using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readTimeout.CancelAfter(timeoutMs);

            int extraRead;
            try
            {
                extraRead = await client.ReadAsync(extra, readTimeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                break;
            }

            if (extraRead <= 0) break;
            data.Write(extra, 0, extraRead);
        }

        return data.ToArray();
    }

    static int ExpectedLength(MemoryStream data)
    {
        if (data.Length < 5) return 0;
        var buffer = data.GetBuffer();
        if (buffer[0] != 0x16) return 0;
        return 5 + ((buffer[3] << 8) | buffer[4]);
    }

    byte[] ApplyRuleSniRewrite(byte[] payload, string host, bool excluded)
    {
        if (payload.Length == 0 || payload[0] != 0x16) return payload;

        var rule = excluded ? null : rules.Current.Match(host);

        if (rule != null && !string.IsNullOrEmpty(rule.Sni))
        {
            if (rule.RemoveSni)
            {
                if (TlsClientHello.TryRemoveSni(payload, out var removed))
                {
                    stats.OnRewrite();
                    log.Info("Tunnel", $"移除 SNI: {host}");
                    return removed;
                }
                return payload;
            }

            if (TlsClientHello.TryRewriteSni(payload, rule.Sni, out var rewritten))
            {
                stats.OnRewrite();
                log.Info("Tunnel", $"规则 SNI 改写: {host} -> {rule.Sni}");
                return rewritten;
            }
            return payload;
        }

        if (!settings.EnableSniRewrite || excluded) return payload;
        if (!NetUtil.IsDomainAllowed(host, settings.RewriteDomains)) return payload;

        var target = settings.SniRewriteHost?.Trim();
        if (string.IsNullOrEmpty(target)) return payload;

        if (TlsClientHello.TryRewriteSni(payload, target, out var globalRewritten))
        {
            stats.OnRewrite();
            log.Info("Tunnel", $"全局 SNI 改写: {host} -> {target}");
            return globalRewritten;
        }

        return payload;
    }

    bool ShouldFragment(string host, byte[] payload, bool excluded)
    {
        if (!settings.EnableSniFragment) return false;
        if (excluded) return false;
        if (payload.Length == 0) return false;

        var isTls = payload[0] == 0x16;
        if (settings.OnlyFragmentTls && !isTls) return false;
        if (!NetUtil.IsDomainAllowed(host, settings.FragmentDomains)) return false;
        if (fallbackCache.ShouldSkip(host)) return false;

        return true;
    }

    List<TlsFragmentStrategy?> BuildStrategyAttempts(string host, byte[] payload, bool excluded)
    {
        var result = new List<TlsFragmentStrategy?>(4);

        if (!ShouldFragment(host, payload, excluded))
        {
            result.Add(null);
            return result;
        }

        var configured = settings.FragmentStrategy;
        if (configured == TlsFragmentStrategy.Auto)
        {
            if (fallbackCache.TryGetPreferredStrategy(host, out var remembered))
            {
                if (!remembered.HasValue)
                {
                    // 之前验证过该域名不分片可用，直接沿用。
                    result.Add(null);
                    return result;
                }
                result.Add(remembered);
            }
            else
            {
                // 默认先用最强的 TLS record 拆分。
                result.Add(TlsFragmentStrategy.TlsRecordSplit);
            }

            if (settings.EnableFragmentFallback)
            {
                foreach (var fallback in new TlsFragmentStrategy?[]
                         {
                             TlsFragmentStrategy.TlsRecordSplit,
                             TlsFragmentStrategy.SniBoundary,
                             null,
                         })
                {
                    if (!result.Contains(fallback)) result.Add(fallback);
                }
            }

            return result;
        }

        result.Add(configured);
        if (settings.EnableFragmentFallback) result.Add(null);
        return result;
    }

    static string Describe(TlsFragmentStrategy? strategy) => strategy?.ToString() ?? "不分片";

    async Task<ProbeResult> SendFirstPayloadAsync(
        UpstreamConnection upstream,
        byte[] payload,
        bool fragment,
        TlsFragmentStrategy strategy,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        bool fragmented;
        try
        {
            fragmented = await WritePayloadAsync(upstream, payload, fragment, strategy, host, port, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (fragment && IsConnectionReset(ex))
        {
            return new ProbeResult(true, null);
        }

        stats.OnBytesUp(payload.Length);
        if (!fragmented) return new ProbeResult(false, null);

        // 分片后等首字节：上游直接 EOF/RST 说明分片可能被中间设备丢弃，触发回退。
        var probeMs = Math.Max(100, settings.FallbackProbeMs);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(probeMs);

        var buffer = new byte[16 * 1024];
        try
        {
            var read = await upstream.Stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read <= 0) return new ProbeResult(true, null);
            return new ProbeResult(false, buffer[..read]);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // 上游只是慢，没有断开，不触发回退。
            return new ProbeResult(false, null);
        }
        catch (IOException)
        {
            return new ProbeResult(true, null);
        }
        catch (SocketException)
        {
            return new ProbeResult(true, null);
        }
    }

    static bool IsConnectionReset(Exception ex)
        => ex is IOException or SocketException or InvalidOperationException ||
           ex.InnerException is SocketException or InvalidOperationException;

    async Task<bool> WritePayloadAsync(
        UpstreamConnection upstream,
        byte[] payload,
        bool fragment,
        TlsFragmentStrategy strategy,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        var target = upstream.Stream;

        if (!fragment || payload.Length == 0)
        {
            await target.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            return false;
        }

        if (strategy == TlsFragmentStrategy.OobSplit &&
            await TryWriteOobSplitAsync(upstream, payload, host, port, cancellationToken).ConfigureAwait(false))
        {
            return true;
        }

        if (strategy == TlsFragmentStrategy.Auto) strategy = TlsFragmentStrategy.TlsRecordSplit;

        var chunks = TlsClientHello.Fragment(
            payload,
            strategy,
            Math.Max(1, settings.FragmentChunkSize),
            Math.Max(2, settings.SplitPieces));

        if (chunks.Count <= 1)
        {
            await target.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            return false;
        }

        var delay = Math.Max(0, settings.FragmentDelayMs);
        var jitter = Math.Max(0, settings.FragmentJitterMs);
        var random = jitter > 0 ? new Random(Guid.NewGuid().GetHashCode()) : null;

        for (var i = 0; i < chunks.Count; i++)
        {
            var chunk = chunks[i];
            await target.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);

            if (i < chunks.Count - 1)
            {
                var wait = delay + (random == null ? 0 : random.Next(0, jitter + 1));
                if (wait > 0) await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
            }
        }

        stats.OnFragment(strategy.ToString());
        log.Info("Tunnel",
            $"分片: {host}:{port} 策略={strategy} 段数={chunks.Count} 大小={payload.Length} 延迟={delay}ms 抖动={jitter}ms");
        return true;
    }

    /// <summary>
    /// 使用 TCP 带外字节（URG）制造乱序，参考 byedpi 的 --oob。
    /// 发送失败时抛 IOException，让上层换连接重试，避免把半个 ClientHello 留在流里。
    /// </summary>
    async Task<bool> TryWriteOobSplitAsync(
        UpstreamConnection upstream,
        byte[] payload,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        if (payload.Length < 4) return false;

        var split = TlsClientHello.TryGetSniRange(payload, out var offset, out var nameLength) && nameLength > 1
            ? Math.Clamp(offset + 1, 1, payload.Length - 1)
            : Math.Min(3, payload.Length - 1);

        int sent;
        try
        {
            sent = upstream.Client.Client.Send(payload, 0, split + 1, SocketFlags.OutOfBand);
        }
        catch (Exception ex)
        {
            throw new IOException("OOB 分片无法发送", ex);
        }

        if (sent != split + 1)
        {
            throw new IOException("OOB 分片写入不完整");
        }

        var wait = Math.Max(0, settings.FragmentDelayMs);
        if (wait > 0) await Task.Delay(wait, cancellationToken).ConfigureAwait(false);

        await upstream.Stream.WriteAsync(payload.AsMemory(split), cancellationToken).ConfigureAwait(false);

        stats.OnFragment(TlsFragmentStrategy.OobSplit.ToString());
        log.Info("Tunnel", $"OOB 分片: {host}:{port} 位置={split} 大小={payload.Length}");
        return true;
    }

    async Task PumpBothAsync(
        NetworkStream client,
        NetworkStream target,
        byte[]? initialDownstream,
        CancellationToken cancellationToken)
    {
        using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var up = PumpAsync(client, target, pumpCts.Token, countAsUp: true);
        var down = PumpAsync(target, client, pumpCts.Token, countAsUp: false, initialDownstream);

        await Task.WhenAny(up, down).ConfigureAwait(false);
        pumpCts.Cancel();

        // NetworkStream 的取消在部分平台不会立刻打断阻塞读，最多等 2 秒，
        // 之后由调用方释放 socket 让残留任务自然退出。
        await Task.WhenAny(Task.WhenAll(up, down), Task.Delay(2000, CancellationToken.None))
            .ConfigureAwait(false);
    }

    async Task PumpAsync(
        NetworkStream from,
        NetworkStream to,
        CancellationToken cancellationToken,
        bool countAsUp,
        byte[]? initial = null)
    {
        try
        {
            if (initial is { Length: > 0 })
            {
                await to.WriteAsync(initial, cancellationToken).ConfigureAwait(false);
                if (countAsUp) stats.OnBytesUp(initial.Length);
                else stats.OnBytesDown(initial.Length);
            }

            var buffer = new byte[32 * 1024];
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await from.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0) return;

                await to.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                if (countAsUp) stats.OnBytesUp(read);
                else stats.OnBytesDown(read);
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        catch (IOException)
        {
            // 对端关闭
        }
        catch (SocketException)
        {
            // 对端重置
        }
        catch (InvalidOperationException)
        {
            // 套接字已断开 / 已释放，属于正常关闭
        }
    }

    readonly record struct ProbeResult(bool Closed, byte[]? Data);
}
