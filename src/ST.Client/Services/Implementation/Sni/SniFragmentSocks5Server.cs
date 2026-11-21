using System;
using System.Application.ProxyRules;
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

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 免证书 SNI sidecar：本地 SOCKS5，按需做 ClientHello 分片和 SNI 改写。
    /// 只做 TCP 转发，不终止 TLS，因此不需要安装证书。
    /// </summary>
    public sealed class SniFragmentSocks5Server : IDisposable
    {
        readonly int port;
        readonly TcpListener listener;
        readonly CancellationTokenSource cts = new();
        Task? acceptTask;
        static int activeConnections;
        const int MaxConnections = 512;
        const int MaxUdpDatagram = 65507;

        public SniFragmentSocks5Server(int port)
        {
            this.port = port;
            listener = new TcpListener(IPAddress.Loopback, port);
        }

        public int Port => port;

        public void Start()
        {
            listener.Start();
            acceptTask = AcceptLoopAsync();
            ProxyDiagnostics.Info("SniSidecar", $"SOCKS5 已启动 127.0.0.1:{port}");
        }

        public void Stop()
        {
            try
            {
                cts.Cancel();
                listener.Stop();
            }
            catch
            {
                // ignore
            }
            ProxyDiagnostics.Info("SniSidecar", "SOCKS5 已停止");
        }

        async Task AcceptLoopAsync()
        {
            while (!cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                }
                catch (Exception) when (cts.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    ProxyDiagnostics.Warn("SniSidecar", $"accept 失败: {ex.Message}");
                    continue;
                }

                _ = HandleAsync(client);
            }
        }

        async Task HandleAsync(TcpClient client)
        {
            if (Interlocked.Increment(ref activeConnections) > MaxConnections)
            {
                Interlocked.Decrement(ref activeConnections);
                ProxyDiagnostics.Warn("SniSidecar", "并发连接超过上限，已拒绝新连接");
                client.Dispose();
                return;
            }

            SniSidecarStats.OnConnection();
            try
            {
                await HandleCoreAsync(client).ConfigureAwait(false);
            }
            catch (Exception ex) when (!cts.IsCancellationRequested)
            {
                // 每个连接都是 fire-and-forget，异常必须在这里吃掉；
                // 否则会变成 TaskScheduler.UnobservedTaskException 并堆积在终结器线程。
                ProxyDiagnostics.Warn("SniSidecar", $"连接异常: {ex.Message}");
            }
            catch
            {
                // 停止代理时的取消/关闭异常不需要上报
            }
            finally
            {
                Interlocked.Decrement(ref activeConnections);
            }
        }

        async Task HandleCoreAsync(TcpClient client)
        {
            using (client)
            {
                client.NoDelay = true;
                var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                TcpClient? target = null;
                try
                {
                    using var clientStream = client.GetStream();
                    if (!await NegotiateAsync(clientStream).ConfigureAwait(false)) return;

                    var request = await ReadRequestAsync(clientStream).ConfigureAwait(false);
                    if (request == null) return;
                    var req = request.Value;

                    if (req.Command == SocksCommand.UdpAssociate)
                    {
                        await RunUdpAssociateAsync(clientStream, connectionCts.Token).ConfigureAwait(false);
                        return;
                    }

                    if (req.Command != SocksCommand.Connect)
                    {
                        await WriteReplyAsync(clientStream, SocksReply.CommandNotSupported).ConfigureAwait(false);
                        SniSidecarStats.OnFailure();
                        ProxyDiagnostics.Warn("SniSidecar", $"不支持的 SOCKS 命令: {req.Command}");
                        return;
                    }

                    var host = req.HostName ?? req.Address?.ToString() ?? string.Empty;
                    if (string.IsNullOrEmpty(host))
                    {
                        await WriteReplyAsync(clientStream, SocksReply.GeneralFailure).ConfigureAwait(false);
                        SniSidecarStats.OnFailure();
                        return;
                    }

                    var rules = ProxyRuleEngine.Current;
                    var excluded = rules.IsExcluded(host);

                    // 先回 SOCKS 成功，再读 ClientHello、选 IP、连目标。
                    // 否则目标 IP 被黑洞时，tun2socks 会一直等 SOCKS 响应，连 SNI 都拿不到，
                    // 预置 IP / 上游中继也就没有机会生效。
                    await WriteReplyAsync(clientStream, SocksReply.Succeeded).ConfigureAwait(false);

                    var firstPayload = await ReadFirstPayloadAsync(
                        clientStream,
                        Math.Max(100, ProxySettings.SniFragmentReadTimeoutMilliseconds.Value),
                        connectionCts.Token).ConfigureAwait(false);

                    // VPN/tun2socks 只能拿到目标 IP，真正的域名在 ClientHello 的 SNI 里。
                    var effectiveHost = host;
                    if (firstPayload.Data != null &&
                        TlsClientHello.TryGetSni(firstPayload.Data, out var payloadSni) &&
                        !string.IsNullOrWhiteSpace(payloadSni))
                    {
                        effectiveHost = payloadSni!;
                        // VPN 下 SOCKS 目标永远是 IP，这里如果每个连接都写日志会产生大量 IO。
                        // 只记录用户关心的分片域名，普通连接交给统计计数器。
                        if (!string.Equals(effectiveHost, host, StringComparison.OrdinalIgnoreCase) &&
                            IsDomainAllowed(effectiveHost, ProxySettings.SniFragmentDomains.Value))
                        {
                            ProxyDiagnostics.Info("SniSidecar", $"从 ClientHello 识别域名: {host} -> {effectiveHost}");
                        }
                    }

                    var payload = firstPayload.Data == null ? null : MaybeRewriteSni(firstPayload.Data, effectiveHost);
                    var excludedBySni = excluded || rules.IsExcluded(effectiveHost);

                    // 证书模式：只有确实需要 MITM 的域名才转发给 Titanium，
                    // 其余流量（含非 TLS、UDP、普通网页）继续由 sidecar 直连。
                    // 这样 Titanium 不会收到二进制数据，避免大量 "Invalid HTTP request line" 拖死进程。
                    if (payload != null && ShouldRelayToTitanium(effectiveHost, excludedBySni))
                    {
                        try
                        {
                            target = await ConnectViaTitaniumAsync(
                                effectiveHost,
                                req.Port,
                                connectionCts.Token).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            target = null;
                            ProxyDiagnostics.Warn("SniSidecar", $"Titanium MITM 不可用，回退直连: {effectiveHost}: {ex.Message}");
                        }

                        if (target != null)
                        {
                            target.NoDelay = true;
                            var mitmStream = target.GetStream();
                            try
                            {
                                await mitmStream.WriteAsync(payload, 0, payload.Length, connectionCts.Token).ConfigureAwait(false);
                            }
                            catch (Exception ex)
                            {
                                ProxyDiagnostics.Warn("SniSidecar", $"转发 ClientHello 到 Titanium 失败: {ex.Message}");
                                return;
                            }

                            var mitmUp = PumpClientToTargetAsync(clientStream, mitmStream, connectionCts.Token);
                            var mitmDown = PumpAsync(mitmStream, clientStream, connectionCts.Token);
                            await Task.WhenAny(mitmUp, mitmDown).ConfigureAwait(false);
                            connectionCts.Cancel();
                            await AwaitQuietlyAsync(mitmUp).ConfigureAwait(false);
                            await AwaitQuietlyAsync(mitmDown).ConfigureAwait(false);
                            return;
                        }
                    }

                    try
                    {
                        target = await ConnectWithFallbackAsync(
                            host,
                            effectiveHost,
                            req.Port,
                            excludedBySni,
                            connectionCts.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        SniSidecarStats.OnFailure();
                        ProxyDiagnostics.Warn("SniSidecar", $"连接 {effectiveHost}:{req.Port} 失败: {ex.Message}");
                        // SOCKS 成功已经发出，只能关闭连接让客户端尽快重试。
                        return;
                    }

                    target.NoDelay = true;
                    var targetStream = target.GetStream();

                    if (payload == null)
                    {
                        if (!firstPayload.TimedOut) return;

                        // 没有等到客户端数据：按普通 SOCKS5 隧道转发，不尝试分片。
                        var up = PumpClientToTargetAsync(clientStream, targetStream, connectionCts.Token);
                        var down = PumpAsync(targetStream, clientStream, connectionCts.Token);
                        await Task.WhenAny(up, down).ConfigureAwait(false);
                        connectionCts.Cancel();
                        await AwaitQuietlyAsync(up).ConfigureAwait(false);
                        await AwaitQuietlyAsync(down).ConfigureAwait(false);
                        return;
                    }

                    var fragment = ShouldFragment(effectiveHost, payload!, excludedBySni) &&
                                   (SniSidecarService.BenchmarkMode || !FragmentFallbackCache.ShouldSkip(effectiveHost));

                    // 记住上次在这个域名上成功的分片策略，后续连接直接使用。
                    // key 里带上用户当前选择的策略，用户改设置后旧缓存自动失效。
                    var configuredStrategy = (TlsFragmentStrategy)ProxySettings.SniFragmentStrategy.Value;
                    var learnedKey = GetLearnedKey(effectiveHost, configuredStrategy);
                    TlsFragmentStrategy? learnedStrategy = null;
                    if (!SniSidecarService.BenchmarkMode &&
                        fragment &&
                        learnedStrategies.TryGetValue(learnedKey, out var cachedStrategy))
                    {
                        learnedStrategy = cachedStrategy;
                    }

                    var probe = await SendFirstPayloadAsync(
                        targetStream,
                        payload!,
                        fragment,
                        effectiveHost,
                        req.Port,
                        connectionCts.Token,
                        learnedStrategy).ConfigureAwait(false);

                    if (probe.Closed && fragment &&
                        !SniSidecarService.BenchmarkMode &&
                        ProxySettings.EnableSniFragmentFallback.Value)
                    {
                        // 分片被重置：先尝试更强的策略，再回退到不分片。
                        // 很多 DPI 能重组普通 TLS record，但对 Tiny record 脉冲/ClientHello 填充无效。
                        var currentStrategy = learnedStrategy ?? configuredStrategy;
                        if (learnedStrategy != null)
                        {
                            learnedStrategies.TryRemove(learnedKey, out _);
                        }
                        var recovered = false;
                        foreach (var strategy in GetEscalationStrategies(currentStrategy))
                        {
                            target.Dispose();
                            try
                            {
                                target = await ConnectWithFallbackAsync(
                                    host,
                                    effectiveHost,
                                    req.Port,
                                    excludedBySni,
                                    connectionCts.Token).ConfigureAwait(false);
                                target.NoDelay = true;
                                targetStream = target.GetStream();
                                probe = await SendFirstPayloadAsync(
                                    targetStream,
                                    payload!,
                                    fragment: true,
                                    effectiveHost,
                                    req.Port,
                                    connectionCts.Token,
                                    strategy).ConfigureAwait(false);
                                SniSidecarStats.OnReconnect();

                                if (!probe.Closed)
                                {
                                    recovered = true;
                                    learnedStrategies[learnedKey] = strategy;
                                    ProxyDiagnostics.Info("SniSidecar",
                                        $"分片策略升级成功: {effectiveHost} -> {strategy}");
                                    break;
                                }

                                ProxyDiagnostics.Warn("SniSidecar",
                                    $"分片策略升级仍被重置: {effectiveHost} -> {strategy}");
                            }
                            catch (Exception ex)
                            {
                                ProxyDiagnostics.Warn("SniSidecar",
                                    $"分片策略升级失败: {effectiveHost} -> {strategy}: {ex.Message}");
                            }
                        }

                        // C# 分片都不行时，尝试 APK 内置的 ByeDPI 原生内核（仅配置的域名）。
                        if (!recovered &&
                            ByedpiRuntime.ShouldUse?.Invoke(effectiveHost) == true &&
                            ByedpiRuntime.EnsureStarted?.Invoke() == true)
                        {
                            target.Dispose();
                            try
                            {
                                target = await ConnectViaByedpiAsync(
                                    effectiveHost,
                                    host,
                                    req.Port,
                                    excludedBySni,
                                    connectionCts.Token).ConfigureAwait(false);
                                target.NoDelay = true;
                                targetStream = target.GetStream();
                                probe = await SendFirstPayloadAsync(
                                    targetStream,
                                    payload!,
                                    fragment: false,
                                    effectiveHost,
                                    req.Port,
                                    connectionCts.Token).ConfigureAwait(false);
                                SniSidecarStats.OnReconnect();

                                if (!probe.Closed)
                                {
                                    recovered = true;
                                    ProxyDiagnostics.Info("SniSidecar", $"ByeDPI 内核绕过成功: {effectiveHost}");
                                }
                                else
                                {
                                    ProxyDiagnostics.Warn("SniSidecar", $"ByeDPI 内核仍被重置: {effectiveHost}");
                                }
                            }
                            catch (Exception ex)
                            {
                                ProxyDiagnostics.Warn("SniSidecar", $"ByeDPI 内核尝试失败: {effectiveHost}: {ex.Message}");
                            }
                        }

                        if (!recovered)
                        {
                            // 所有分片都失败：记住该域名，换一条连接用不分片方式重试一次。
                            FragmentFallbackCache.Duration = TimeSpan.FromMinutes(
                                Math.Max(1, ProxySettings.SniFragmentFallbackCacheMinutes.Value));
                            FragmentFallbackCache.MarkFailure(effectiveHost);
                            SniSidecarStats.OnFallback();
                            ProxyDiagnostics.Warn("SniSidecar", $"分片握手被重置，回退直连重试: {effectiveHost}");

                            target.Dispose();
                            try
                            {
                                target = await ConnectWithFallbackAsync(
                                    host,
                                    effectiveHost,
                                    req.Port,
                                    excludedBySni,
                                    connectionCts.Token).ConfigureAwait(false);
                                target.NoDelay = true;
                                targetStream = target.GetStream();
                                probe = await SendFirstPayloadAsync(
                                    targetStream,
                                    payload!,
                                    fragment: false,
                                    effectiveHost,
                                    req.Port,
                                    connectionCts.Token).ConfigureAwait(false);
                                SniSidecarStats.OnReconnect();
                            }
                            catch (Exception ex)
                            {
                                SniSidecarStats.OnFailure();
                                ProxyDiagnostics.Warn("SniSidecar", $"回退重试失败: {effectiveHost}: {ex.Message}");
                                return;
                            }
                        }
                    }

                    var upstream = PumpClientToTargetAsync(clientStream, targetStream, connectionCts.Token);
                    var downstream = PumpAsync(targetStream, clientStream, connectionCts.Token, probe.Data);

                    await Task.WhenAny(upstream, downstream).ConfigureAwait(false);
                    connectionCts.Cancel();

                    await AwaitQuietlyAsync(upstream).ConfigureAwait(false);
                    await AwaitQuietlyAsync(downstream).ConfigureAwait(false);
                }
                catch (Exception ex) when (!cts.IsCancellationRequested)
                {
                    SniSidecarStats.OnFailure();
                    ProxyDiagnostics.Warn("SniSidecar", $"连接处理失败: {ex.Message}");
                }
                finally
                {
                    target?.Dispose();
                    connectionCts.Dispose();
                }
            }
        }

        /// <summary>
        /// SOCKS5 UDP ASSOCIATE：tun2socks 的 --enable-udprelay 需要它。
        /// DNS（UDP:53）优先走 DoH，其它 UDP 按目标直接转发。
        /// </summary>
        async Task RunUdpAssociateAsync(NetworkStream control, CancellationToken cancellationToken)
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var bound = (IPEndPoint)udp.Client.LocalEndPoint!;
            await WriteReplyAsync(control, SocksReply.Succeeded, bound).ConfigureAwait(false);
            ProxyDiagnostics.Info("SniSidecar", $"UDP ASSOCIATE 已建立 127.0.0.1:{bound.Port}");

            // QUIC/HTTP3 是长连接：必须按目标端点维护持久 UDP socket 和接收循环，
            // 每个数据报新建 socket 再等 3 秒会导致 QUIC 握手根本走不完。
            var flows = new Dictionary<string, UdpFlow>(StringComparer.OrdinalIgnoreCase);
            var client = new UdpClientState { EndPoint = null };
            var controlMonitor = MonitorControlConnectionAsync(control, cancellationToken);

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var receiveTask = udp.ReceiveAsync();
                    var completed = await Task.WhenAny(
                        receiveTask,
                        controlMonitor,
                        Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)).ConfigureAwait(false);

                    if (completed == controlMonitor) break;
                    if (completed != receiveTask)
                    {
                        CleanupUdpFlows(flows);
                        continue;
                    }

                    var result = receiveTask.Result;
                    client.EndPoint = result.RemoteEndPoint;
                    // 不阻塞后续数据报：QUIC 的握手包可能连续到达。
                    _ = HandleUdpDatagramAsync(udp, client, result.Buffer, flows, cancellationToken);
                }
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                ProxyDiagnostics.Warn("SniSidecar", $"UDP ASSOCIATE 结束: {ex.Message}");
            }
            finally
            {
                lock (flows)
                {
                    foreach (var flow in flows.Values)
                    {
                        flow.Dispose();
                    }
                    flows.Clear();
                }
            }
        }

        const int MaxUdpFlows = 128;
        static readonly TimeSpan UdpFlowIdleTimeout = TimeSpan.FromSeconds(90);

        sealed class UdpClientState
        {
            public volatile IPEndPoint? EndPoint;
        }

        sealed class UdpFlow : IDisposable
        {
            public UdpFlow(IPAddress address, string? host, int port, UdpClient socket)
            {
                Address = address;
                Host = host;
                Port = port;
                Socket = socket;
                Touch();
            }

            public IPAddress Address { get; }

            public string? Host { get; }

            public int Port { get; }

            public UdpClient Socket { get; }

            long lastActiveTicks;

            public void Touch() => Interlocked.Exchange(ref lastActiveTicks, DateTime.UtcNow.Ticks);

            public long IdleMilliseconds
                => (long)(DateTime.UtcNow - new DateTime(Interlocked.Read(ref lastActiveTicks))).TotalMilliseconds;

            public bool IsIdle(TimeSpan timeout)
                => IdleMilliseconds > (long)timeout.TotalMilliseconds;

            public void Dispose()
            {
                try
                {
                    Socket.Dispose();
                }
                catch
                {
                    // ignore
                }
            }
        }

        static void CleanupUdpFlows(Dictionary<string, UdpFlow> flows)
        {
            lock (flows)
            {
                var expired = flows
                    .Where(x => x.Value.IsIdle(UdpFlowIdleTimeout))
                    .Select(x => x.Key)
                    .ToList();
                foreach (var key in expired)
                {
                    if (flows.TryGetValue(key, out var flow))
                    {
                        flows.Remove(key);
                        flow.Dispose();
                    }
                }
            }
        }

        static async Task MonitorControlConnectionAsync(NetworkStream control, CancellationToken cancellationToken)
        {
            var buffer = new byte[64];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var read = await control.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                    if (read <= 0) return;
                }
            }
            catch
            {
                // 控制连接关闭即代表 UDP 关联结束
            }
        }

        async Task HandleUdpDatagramAsync(
            UdpClient udp,
            UdpClientState client,
            byte[]? datagram,
            Dictionary<string, UdpFlow> flows,
            CancellationToken cancellationToken)
        {
            if (datagram == null || datagram.Length < 4 || datagram.Length > MaxUdpDatagram) return;
            if (datagram[2] != 0) return; // 不支持 SOCKS5 UDP 分片

            try
            {
                var offset = 4;
                IPAddress? address = null;
                string? host = null;
                switch (datagram[3])
                {
                    case 0x01:
                        if (datagram.Length < offset + 4 + 2) return;
                        address = new IPAddress(datagram.AsSpan(offset, 4).ToArray());
                        offset += 4;
                        break;
                    case 0x04:
                        if (datagram.Length < offset + 16 + 2) return;
                        address = new IPAddress(datagram.AsSpan(offset, 16).ToArray());
                        offset += 16;
                        break;
                    case 0x03:
                        if (datagram.Length < offset + 1) return;
                        var length = datagram[offset];
                        offset += 1;
                        if (datagram.Length < offset + length + 2) return;
                        host = Encoding.ASCII.GetString(datagram, offset, length);
                        offset += length;
                        break;
                    default:
                        return;
                }

                if (datagram.Length < offset + 2) return;
                var targetPort = (datagram[offset] << 8) | datagram[offset + 1];
                offset += 2;
                if (targetPort <= 0) return;

                var payloadLength = datagram.Length - offset;
                if (payloadLength <= 0) return;
                var payload = new byte[payloadLength];
                Buffer.BlockCopy(datagram, offset, payload, 0, payloadLength);

                byte[]? response = null;
                if (targetPort == 53 && ProxySettings.EnableDoh.Value)
                {
                    response = await DohWireResolver.QueryAsync(payload, cancellationToken).ConfigureAwait(false);
                }

                if (response != null)
                {
                    var responsePacket = BuildUdpResponse(address, host, targetPort, response);
                    if (client.EndPoint != null)
                    {
                        await udp.SendAsync(responsePacket, responsePacket.Length, client.EndPoint).ConfigureAwait(false);
                    }
                    return;
                }

                // 非 DNS 或 DoH 失败：交给持久 flow 转发。
                var flow = await GetOrCreateUdpFlowAsync(
                    udp, client, address, host, targetPort, flows).ConfigureAwait(false);
                if (flow == null) return;

                await flow.Socket.SendAsync(payload, payload.Length).ConfigureAwait(false);
                flow.Touch();
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                ProxyDiagnostics.Warn("SniSidecar", $"UDP 转发失败: {ex.Message}");
            }
        }

        static async Task<UdpFlow?> GetOrCreateUdpFlowAsync(
            UdpClient udp,
            UdpClientState client,
            IPAddress? address,
            string? host,
            int port,
            Dictionary<string, UdpFlow> flows)
        {
            if (address == null && !string.IsNullOrEmpty(host))
            {
                var preset = ProxyPresetIpProvider.GetCandidates(host)
                    .Select(x => IPAddress.TryParse(x, out var ip) ? ip : null)
                    .FirstOrDefault(x => x != null);
                if (preset != null)
                {
                    address = preset;
                }
                else
                {
                    var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                    address = addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork) ??
                              addresses.FirstOrDefault();
                }
            }
            if (address == null) return null;

            var key = $"{address}:{port}";
            lock (flows)
            {
                if (flows.TryGetValue(key, out var existing))
                {
                    existing.Touch();
                    return existing;
                }

                if (flows.Count >= MaxUdpFlows)
                {
                    var oldest = flows.OrderByDescending(x => x.Value.IdleMilliseconds)
                        .Select(x => x.Key)
                        .FirstOrDefault();
                    if (oldest != null && flows.TryGetValue(oldest, out var removed))
                    {
                        flows.Remove(oldest);
                        removed.Dispose();
                    }
                }

                var socket = new UdpClient(address.AddressFamily);
                try
                {
                    socket.Connect(new IPEndPoint(address, port));
                }
                catch
                {
                    socket.Dispose();
                    return null;
                }

                var flow = new UdpFlow(address, host, port, socket);
                flows[key] = flow;
                _ = ReceiveUdpFlowAsync(udp, client, flow);
                return flow;
            }
        }

        static async Task ReceiveUdpFlowAsync(UdpClient udp, UdpClientState client, UdpFlow flow)
        {
            try
            {
                while (true)
                {
                    var result = await flow.Socket.ReceiveAsync().ConfigureAwait(false);
                    if (result.Buffer == null || result.Buffer.Length == 0) continue;
                    flow.Touch();

                    var endPoint = client.EndPoint;
                    if (endPoint == null) continue;

                    var packet = BuildUdpResponse(flow.Address, flow.Host, flow.Port, result.Buffer);
                    await udp.SendAsync(packet, packet.Length, endPoint).ConfigureAwait(false);
                }
            }
            catch (ObjectDisposedException)
            {
                // flow 被回收
            }
            catch (Exception ex)
            {
                ProxyDiagnostics.Warn("SniSidecar",
                    $"UDP flow 接收结束 {flow.Address}:{flow.Port}: {ex.Message}");
            }
        }

        static byte[] BuildUdpResponse(IPAddress? address, string? host, int port, byte[] data)
        {
            byte[] header;
            if (address != null)
            {
                var bytes = address.GetAddressBytes();
                header = new byte[4 + bytes.Length + 2];
                header[3] = address.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
                bytes.CopyTo(header, 4);
                header[^2] = (byte)(port >> 8);
                header[^1] = (byte)(port & 0xFF);
            }
            else
            {
                var name = Encoding.ASCII.GetBytes(host ?? string.Empty);
                header = new byte[4 + 1 + name.Length + 2];
                header[3] = 0x03;
                header[4] = (byte)name.Length;
                name.CopyTo(header, 5);
                header[^2] = (byte)(port >> 8);
                header[^1] = (byte)(port & 0xFF);
            }

            var result = new byte[header.Length + data.Length];
            header.CopyTo(result, 0);
            data.CopyTo(result, header.Length);
            return result;
        }

        async Task<TcpClient> ConnectWithFallbackAsync(
            string requestedHost,
            string effectiveHost,
            int port,
            bool excluded,
            CancellationToken cancellationToken,
            bool preferOriginalFirst = false)
        {
            // 有上游中继时优先走中继，并把真实域名交给中继解析。
            if (!excluded &&
                ProxySettings.EnableSniUpstreamRelay.Value &&
                IsDomainAllowed(effectiveHost, ProxySettings.SniUpstreamRelayDomains.Value) &&
                !IPAddress.TryParse(effectiveHost, out _))
            {
                return await ConnectViaRelayAsync(effectiveHost, port, cancellationToken).ConfigureAwait(false);
            }

            var attempts = new List<string>();
            var presetSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (!excluded)
            {
                var presetIps = ProxyPresetIpProvider.GetCandidates(effectiveHost)
                    .Concat(GetBuiltInPresetIps(effectiveHost))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (presetIps.Count > 0)
                {
                    var selected = await PresetIpSelector.PickAsync(
                        presetIps,
                        port,
                        TimeSpan.FromMilliseconds(600),
                        cancellationToken).ConfigureAwait(false);
                    if (selected != null)
                    {
                        attempts.Add(selected.ToString());
                        presetSet.Add(selected.ToString());
                    }

                    foreach (var ip in presetIps)
                    {
                        if (!attempts.Contains(ip, StringComparer.OrdinalIgnoreCase))
                        {
                            attempts.Add(ip);
                        }
                        presetSet.Add(ip);
                    }
                }
            }

            if (preferOriginalFirst)
            {
                attempts.Insert(0, requestedHost);
            }
            else
            {
                attempts.Add(requestedHost);
            }

            if (!IPAddress.TryParse(effectiveHost, out _) &&
                !attempts.Contains(effectiveHost, StringComparer.OrdinalIgnoreCase))
            {
                attempts.Add(effectiveHost);
            }

            Exception? lastError = null;
            var candidates = attempts
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(8)
                .ToList();

            // 并发连接（happy eyeballs）：预置 IP 可能有好几个，顺序试会太慢。
            // 有预置 IP 时，原始 IP 延迟 500ms 再试，避免被污染的 IP 抢先连上。
            using var raceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var originalDelay = presetSet.Count > 0 && !preferOriginalFirst ? 500 : 0;
            var tasks = candidates
                .Select(candidate => TryConnectAfterAsync(
                    candidate,
                    port,
                    presetSet.Contains(candidate) ? 0 : originalDelay,
                    raceCts.Token))
                .ToList();

            while (tasks.Count > 0)
            {
                var completed = await Task.WhenAny(tasks).ConfigureAwait(false);
                tasks.Remove(completed);
                var result = await completed.ConfigureAwait(false);
                if (result.Client == null)
                {
                    lastError = result.Error ?? lastError;
                    continue;
                }

                raceCts.Cancel();
                foreach (var task in tasks)
                {
                    _ = task.ContinueWith(t =>
                    {
                        if (t.Status == TaskStatus.RanToCompletion && t.Result.Client != null)
                        {
                            t.Result.Client.Dispose();
                        }
                    }, TaskScheduler.Default);
                }

                if (presetSet.Contains(result.Host))
                {
                    SniSidecarStats.OnPresetIp();
                    ProxyDiagnostics.Info("SniSidecar", $"使用预置 IP 连接: {effectiveHost} -> {result.Host}:{port}");
                }
                else
                {
                    // 普通连接不逐个落盘，避免浏览网页时把日志和磁盘 IO 打满。
                    if (IsDomainAllowed(effectiveHost, ProxySettings.SniFragmentDomains.Value))
                    {
                        ProxyDiagnostics.Info("SniSidecar", $"直连: {effectiveHost} -> {result.Host}:{port}");
                    }
                }
                return result.Client;
            }

            throw lastError ?? new IOException($"无法连接 {effectiveHost}:{port}");
        }

        static async Task<(string Host, TcpClient? Client, Exception? Error)> TryConnectAfterAsync(
            string host,
            int port,
            int delayMilliseconds,
            CancellationToken cancellationToken)
        {
            if (delayMilliseconds > 0)
            {
                try
                {
                    await Task.Delay(delayMilliseconds, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return (host, null, null);
                }
            }
            return await TryConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        }

        static async Task<(string Host, TcpClient? Client, Exception? Error)> TryConnectAsync(
            string host,
            int port,
            CancellationToken cancellationToken)
        {
            try
            {
                var client = await ConnectOnceAsync(host, port, cancellationToken).ConfigureAwait(false);
                return (host, client, null);
            }
            catch (Exception ex)
            {
                return (host, null, ex);
            }
        }

        async Task<TcpClient> ConnectViaByedpiAsync(
            string effectiveHost,
            string requestedHost,
            int port,
            bool excluded,
            CancellationToken cancellationToken)
        {
            var getPort = ByedpiRuntime.GetPort;
            if (getPort == null) throw new InvalidOperationException("ByeDPI 未注册端口");

            var targetIp = await ResolveTargetIpAsync(
                effectiveHost, port, excluded, cancellationToken).ConfigureAwait(false);

            var targetHost = targetIp?.ToString();
            if (string.IsNullOrEmpty(targetHost))
            {
                targetHost = IPAddress.TryParse(requestedHost, out var requestedIp)
                    ? requestedIp.ToString()
                    : effectiveHost;
            }

            var relay = new TcpClient { NoDelay = true };
            try
            {
                var connectTask = relay.ConnectAsync(IPAddress.Loopback, getPort());
                var completed = await Task.WhenAny(
                    connectTask,
                    Task.Delay(TimeSpan.FromSeconds(3), cancellationToken)).ConfigureAwait(false);
                if (completed != connectTask)
                {
                    relay.Dispose();
                    try { await connectTask.ConfigureAwait(false); } catch { }
                    throw new TimeoutException("ByeDPI 本地端口连接超时");
                }
                await connectTask.ConfigureAwait(false);

                await NegotiateUpstreamAsync(
                    relay.GetStream(),
                    targetHost!,
                    port,
                    null,
                    null,
                    cancellationToken).ConfigureAwait(false);

                ProxyDiagnostics.Info("SniSidecar", $"经 ByeDPI 内核连接: {effectiveHost} -> {targetHost}:{port}");
                return relay;
            }
            catch
            {
                relay.Dispose();
                throw;
            }
        }

        /// <summary>
        /// 证书模式下，是否应该把这条 TLS 连接交给 Titanium 做 MITM。
        /// 只针对规则要求 MITM 的域名和 HF 兜底域名，避免 Titanium 接触非 TLS/UDP 流量。
        /// </summary>
        static bool ShouldRelayToTitanium(string host, bool excluded)
        {
            if (excluded || string.IsNullOrEmpty(host)) return false;
            if (!SniSidecarService.CertificateMode) return false;

            // GMS / Play / 媒体分发这些域名有证书固定，MITM 只会让系统服务报错，且它们并不需要加速。
            if (IsSystemServiceHost(host)) return false;

            bool socksEnabled;
            try { socksEnabled = IReverseProxyService.Instance.Socks5ProxyEnable; }
            catch { socksEnabled = ProxySettings.Socks5ProxyEnable.Value; }
            if (!socksEnabled) return false;

            var rules = ProxyRuleEngine.Current;
            if (rules.IsExcluded(host)) return false;
            return rules.DomainRequiresMitm(host) || ProxyPresetIpProvider.IsHuggingFaceHost(host);
        }

        static bool IsSystemServiceHost(string host)
            => host.EndsWith(".googleapis.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".gstatic.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".googlevideo.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".gvt1.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".gvt2.com", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("mtalk.google.com", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// 连接到本机 Titanium 的 SOCKS5，并把客户端原始 ClientHello 原样转发过去。
        /// 不使用分片：Titanium 会自己与上游握手。
        /// </summary>
        static async Task<TcpClient> ConnectViaTitaniumAsync(
            string host,
            int port,
            CancellationToken cancellationToken)
        {
            int titaniumPort;
            try { titaniumPort = IReverseProxyService.Instance.Socks5ProxyPortId; }
            catch { titaniumPort = ProxySettings.Socks5ProxyPortId.Value; }

            if (titaniumPort <= 0 || titaniumPort > 65535)
                throw new InvalidOperationException("Titanium SOCKS5 端口无效");
            if (titaniumPort == SniSidecarService.ActivePort || titaniumPort == SniSidecarService.Port)
                throw new InvalidOperationException("Titanium SOCKS5 端口与 sidecar 相同，已跳过以避免回环");

            var client = await ConnectOnceAsync(
                IPAddress.Loopback.ToString(),
                titaniumPort,
                cancellationToken).ConfigureAwait(false);
            try
            {
                await NegotiateUpstreamAsync(
                    client.GetStream(),
                    host,
                    port,
                    null,
                    null,
                    cancellationToken).ConfigureAwait(false);
                ProxyDiagnostics.Info("SniSidecar", $"证书模式转发 Titanium: {host}:{port}");
                return client;
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        async Task<TcpClient> ConnectViaRelayAsync(string host, int port, CancellationToken cancellationToken)
        {
            var relayHost = ProxySettings.SniUpstreamRelayHost.Value?.Trim();
            var relayPort = ProxySettings.SniUpstreamRelayPort.Value;
            if (string.IsNullOrWhiteSpace(relayHost) || relayPort <= 0 || relayPort > 65535)
            {
                throw new InvalidOperationException("上游中继地址无效");
            }

            var relay = new TcpClient { NoDelay = true };
            try
            {
                var connectTask = relay.ConnectAsync(relayHost, relayPort);
                var completed = await Task.WhenAny(
                    connectTask,
                    Task.Delay(TimeSpan.FromSeconds(8), cancellationToken)).ConfigureAwait(false);
                if (completed != connectTask)
                {
                    relay.Dispose();
                    try { await connectTask.ConfigureAwait(false); } catch { }
                    throw new TimeoutException($"中继 {relayHost}:{relayPort} 连接超时");
                }
                await connectTask.ConfigureAwait(false);

                await NegotiateUpstreamAsync(
                    relay.GetStream(),
                    host,
                    port,
                    ProxySettings.SniUpstreamRelayUserName.Value,
                    ProxySettings.SniUpstreamRelayPassword.Value,
                    cancellationToken).ConfigureAwait(false);
                SniSidecarStats.OnRelay();
                ProxyDiagnostics.Info("SniSidecar", $"经中继 {relayHost}:{relayPort} -> {host}:{port}");
                return relay;
            }
            catch
            {
                relay.Dispose();
                throw;
            }
        }

        static async Task<TcpClient> ConnectOnceAsync(string host, int port, CancellationToken cancellationToken)
        {
            var target = new TcpClient { NoDelay = true };
            try
            {
                var connectTask = target.ConnectAsync(host, port);
                var completed = await Task.WhenAny(
                    connectTask,
                    Task.Delay(TimeSpan.FromSeconds(6), cancellationToken)).ConfigureAwait(false);
                if (completed != connectTask)
                {
                    // 必须回收未完成的 ConnectAsync，否则取消后的 SocketException
                    // 会成为未观察任务异常，大量堆积会卡死 UI。
                    target.Dispose();
                    try { await connectTask.ConfigureAwait(false); } catch { }
                    if (cancellationToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancellationToken);
                    }
                    throw new TimeoutException($"连接 {host}:{port} 超时");
                }
                await connectTask.ConfigureAwait(false);
                return target;
            }
            catch
            {
                target.Dispose();
                throw;
            }
        }

        async Task<IPAddress?> ResolveTargetIpAsync(string host, int port, bool excluded, CancellationToken cancellationToken)
        {
            if (excluded) return null;
            if (IPAddress.TryParse(host, out var literal)) return literal;

            var candidates = ProxyPresetIpProvider.GetCandidates(host)
                .Concat(GetBuiltInPresetIps(host))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (candidates.Count > 0)
            {
                var selected = await PresetIpSelector.PickAsync(
                    candidates,
                    port,
                    TimeSpan.FromMilliseconds(800),
                    cancellationToken).ConfigureAwait(false);
                if (selected != null)
                {
                    SniSidecarStats.OnPresetIp();
                    ProxyDiagnostics.Info("SniSidecar", $"预置 IP: {host} -> {selected}");
                    return selected;
                }
            }

            var dohIps = await DohResolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
            if (dohIps.Count == 0)
            {
                if (ProxySettings.EnableDoh.Value && !ProxySettings.DohFallbackToSystem.Value)
                {
                    throw new IOException($"DoH 解析失败且未允许回退系统 DNS: {host}");
                }
                return null;
            }
            if (dohIps.Count == 1) return dohIps[0];

            var dohCandidates = dohIps.Select(x => x.ToString()).ToArray();
            var best = await PresetIpSelector.PickAsync(
                dohCandidates,
                port,
                TimeSpan.FromMilliseconds(800),
                cancellationToken).ConfigureAwait(false);
            return best ?? dohIps[0];
        }

        /// <summary>
        /// 内置加速组里的 ForwardDomainIP 也可以作为免证书模式的预置 IP。
        /// </summary>
        static IReadOnlyList<string> GetBuiltInPresetIps(string host)
        {
            try
            {
                var domains = IReverseProxyService.Instance.ProxyDomains;
                if (domains == null) return Array.Empty<string>();

                var result = new List<string>();
                foreach (var item in domains)
                {
                    if (!item.Enable || string.IsNullOrEmpty(item.ForwardDomainIP)) continue;
                    foreach (var pattern in item.DomainNamesArray)
                    {
                        if (DomainPatternMatcher.IsMatch(host, pattern))
                        {
                            result.Add(item.ForwardDomainIP);
                            break;
                        }
                    }
                }
                return result;
            }
            catch
            {
                return Array.Empty<string>();
            }
        }

        static async Task<bool> NegotiateAsync(NetworkStream stream)
        {
            var header = new byte[2];
            if (!await ReadExactAsync(stream, header, 0, 2).ConfigureAwait(false)) return false;
            if (header[0] != 0x05) return false;

            var methods = new byte[header[1]];
            if (!await ReadExactAsync(stream, methods, 0, methods.Length).ConfigureAwait(false)) return false;
            var hasNoAuth = false;
            foreach (var method in methods)
            {
                if (method == 0x00) { hasNoAuth = true; break; }
            }
            if (!hasNoAuth)
            {
                await stream.WriteAsync(new byte[] { 0x05, 0xFF }, 0, 2).ConfigureAwait(false);
                return false;
            }
            await stream.WriteAsync(new byte[] { 0x05, 0x00 }, 0, 2).ConfigureAwait(false);
            return true;
        }

        static async Task<SocksRequest?> ReadRequestAsync(NetworkStream stream)
        {
            var header = new byte[4];
            if (!await ReadExactAsync(stream, header, 0, 4).ConfigureAwait(false)) return null;
            if (header[0] != 0x05) return null;

            var command = (SocksCommand)header[1];
            string? hostName = null;
            IPAddress? address = null;
            switch (header[3])
            {
                case 0x01:
                    {
                        var buf = new byte[4];
                        if (!await ReadExactAsync(stream, buf, 0, 4).ConfigureAwait(false)) return null;
                        address = new IPAddress(buf);
                        break;
                    }
                case 0x03:
                    {
                        var len = new byte[1];
                        if (!await ReadExactAsync(stream, len, 0, 1).ConfigureAwait(false)) return null;
                        var buf = new byte[len[0]];
                        if (!await ReadExactAsync(stream, buf, 0, buf.Length).ConfigureAwait(false)) return null;
                        hostName = Encoding.ASCII.GetString(buf);
                        break;
                    }
                case 0x04:
                    {
                        var buf = new byte[16];
                        if (!await ReadExactAsync(stream, buf, 0, 16).ConfigureAwait(false)) return null;
                        address = new IPAddress(buf);
                        break;
                    }
                default:
                    return null;
            }

            var portBuf = new byte[2];
            if (!await ReadExactAsync(stream, portBuf, 0, 2).ConfigureAwait(false)) return null;
            var port = (portBuf[0] << 8) | portBuf[1];
            return new SocksRequest(command, hostName, address, port);
        }

        static async Task WriteReplyAsync(NetworkStream stream, SocksReply reply)
        {
            await WriteReplyAsync(stream, reply, null).ConfigureAwait(false);
        }

        static async Task WriteReplyAsync(NetworkStream stream, SocksReply reply, IPEndPoint? bound)
        {
            byte[] buffer;
            if (bound == null)
            {
                buffer = new byte[] { 0x05, (byte)reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
            }
            else if (bound.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var address = bound.Address.GetAddressBytes();
                buffer = new byte[4 + 16 + 2];
                buffer[0] = 0x05;
                buffer[1] = (byte)reply;
                buffer[3] = 0x04;
                address.CopyTo(buffer, 4);
                buffer[^2] = (byte)(bound.Port >> 8);
                buffer[^1] = (byte)(bound.Port & 0xFF);
            }
            else
            {
                var address = bound.Address.GetAddressBytes();
                buffer = new byte[4 + 4 + 2];
                buffer[0] = 0x05;
                buffer[1] = (byte)reply;
                buffer[3] = 0x01;
                address.CopyTo(buffer, 4);
                buffer[^2] = (byte)(bound.Port >> 8);
                buffer[^1] = (byte)(bound.Port & 0xFF);
            }

            try
            {
                await stream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            }
            catch
            {
                // 客户端可能已经断开
            }
        }

        static async Task NegotiateUpstreamAsync(
            NetworkStream stream,
            string host,
            int port,
            string? userName,
            string? password,
            CancellationToken cancellationToken)
        {
            var hasAuth = !string.IsNullOrEmpty(userName);
            var greeting = hasAuth
                ? new byte[] { 0x05, 0x02, 0x00, 0x02 }
                : new byte[] { 0x05, 0x01, 0x00 };
            await stream.WriteAsync(greeting, 0, greeting.Length, cancellationToken).ConfigureAwait(false);

            var response = new byte[2];
            if (!await ReadExactAsync(stream, response, 0, 2, cancellationToken).ConfigureAwait(false))
                throw new IOException("上游 SOCKS5 无响应");
            if (response[0] != 0x05 || response[1] == 0xFF)
                throw new IOException("上游 SOCKS5 拒绝认证方式");

            if (response[1] == 0x02)
            {
                var user = Encoding.UTF8.GetBytes(userName ?? string.Empty);
                var pass = Encoding.UTF8.GetBytes(password ?? string.Empty);
                if (user.Length > 255 || pass.Length > 255)
                    throw new IOException("上游 SOCKS5 用户名或密码过长");

                var auth = new byte[3 + user.Length + pass.Length];
                auth[0] = 0x01;
                auth[1] = (byte)user.Length;
                user.CopyTo(auth, 2);
                auth[2 + user.Length] = (byte)pass.Length;
                pass.CopyTo(auth, 3 + user.Length);
                await stream.WriteAsync(auth, 0, auth.Length, cancellationToken).ConfigureAwait(false);

                var authResponse = new byte[2];
                if (!await ReadExactAsync(stream, authResponse, 0, 2, cancellationToken).ConfigureAwait(false) ||
                    authResponse[0] != 0x01 || authResponse[1] != 0x00)
                {
                    throw new IOException("上游 SOCKS5 认证失败");
                }
            }

            byte[] request;
            if (IPAddress.TryParse(host, out var ip))
            {
                var address = ip.GetAddressBytes();
                request = new byte[4 + address.Length + 2];
                request[0] = 0x05;
                request[1] = 0x01;
                request[2] = 0x00;
                request[3] = ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
                address.CopyTo(request, 4);
                request[^2] = (byte)(port >> 8);
                request[^1] = (byte)(port & 0xFF);
            }
            else
            {
                var hostBytes = Encoding.ASCII.GetBytes(host);
                if (hostBytes.Length > 255) throw new IOException("域名过长");
                request = new byte[5 + hostBytes.Length + 2];
                request[0] = 0x05;
                request[1] = 0x01;
                request[2] = 0x00;
                request[3] = 0x03;
                request[4] = (byte)hostBytes.Length;
                hostBytes.CopyTo(request, 5);
                request[^2] = (byte)(port >> 8);
                request[^1] = (byte)(port & 0xFF);
            }

            await stream.WriteAsync(request, 0, request.Length, cancellationToken).ConfigureAwait(false);
            await ReadSocksReplyAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        static async Task ReadSocksReplyAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var header = new byte[4];
            if (!await ReadExactAsync(stream, header, 0, 4, cancellationToken).ConfigureAwait(false))
                throw new IOException("上游 SOCKS5 响应为空");
            if (header[0] != 0x05 || header[1] != 0x00)
                throw new IOException($"上游 SOCKS5 连接失败: {header[1]}");

            var length = header[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => await ReadOneByteAsync(stream, cancellationToken).ConfigureAwait(false),
                _ => 0,
            };
            var rest = new byte[length + 2];
            if (length + 2 > 0 && !await ReadExactAsync(stream, rest, 0, rest.Length, cancellationToken).ConfigureAwait(false))
                throw new IOException("上游 SOCKS5 响应不完整");
        }

        async Task PumpClientToTargetAsync(
            NetworkStream client,
            NetworkStream target,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[32 * 1024];
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await client.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (read <= 0) return;

                await target.WriteAsync(buffer, 0, read, cancellationToken).ConfigureAwait(false);
                SniSidecarStats.OnBytesUp(read);
            }
        }

        /// <summary>
        /// 读取客户端的第一个有效负载。TLS 连接会等 ClientHello 完整到齐，避免分片位置算错。
        /// 超时表示客户端暂时没有发送数据（例如服务器先说话的协议）。
        /// </summary>
        static async Task<FirstPayloadResult> ReadFirstPayloadAsync(
            NetworkStream client,
            int timeoutMilliseconds,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[32 * 1024];
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Math.Max(50, timeoutMilliseconds));

            int read;
            try
            {
                read = await client.ReadAsync(buffer, 0, buffer.Length, timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new FirstPayloadResult(null, timedOut: true);
            }

            if (read <= 0) return new FirstPayloadResult(null, timedOut: false);

            var payload = await PrepareFirstPayloadAsync(client, buffer, read, cancellationToken).ConfigureAwait(false);
            return new FirstPayloadResult(payload, timedOut: false);
        }

        static async Task<byte[]> PrepareFirstPayloadAsync(
            NetworkStream client,
            byte[] buffer,
            int read,
            CancellationToken cancellationToken)
        {
            var isTls = read > 0 && buffer[0] == 0x16;
            if (!isTls || (!ProxySettings.EnableSniFragment.Value && !ProxySettings.EnableSniRewrite.Value))
            {
                var copy = new byte[read];
                Buffer.BlockCopy(buffer, 0, copy, 0, read);
                return copy;
            }

            var maxBytes = Math.Max(1024, ProxySettings.SniFragmentMaxBufferBytes.Value);
            var timeoutMs = Math.Max(50, ProxySettings.SniFragmentReadTimeoutMilliseconds.Value);
            using var data = new MemoryStream(Math.Min(read, maxBytes));
            data.Write(buffer, 0, Math.Min(read, maxBytes));

            while (data.Length < maxBytes)
            {
                var current = data.ToArray();
                var expectedLength = 0;
                if (current.Length >= 5)
                {
                    if (!TlsClientHello.TryGetRecordLength(current, out expectedLength) ||
                        expectedLength <= 5 ||
                        expectedLength > maxBytes)
                    {
                        break;
                    }
                    if (current.Length >= expectedLength)
                    {
                        break;
                    }
                }

                var want = expectedLength > 0
                    ? Math.Min(4096, expectedLength - (int)data.Length)
                    : 4096;
                if (want <= 0) break;

                var extra = new byte[want];
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(timeoutMs);

                int extraRead;
                try
                {
                    extraRead = await client.ReadAsync(extra, 0, extra.Length, timeoutCts.Token).ConfigureAwait(false);
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

        static bool ShouldFragment(string host, byte[] payload, bool excluded)
        {
            if (excluded || payload.Length == 0) return false;
            if (!ProxySettings.EnableSniFragment.Value) return false;

            var isTls = payload[0] == 0x16;
            if (ProxySettings.SniFragmentOnlyTls.Value && !isTls) return false;

            return IsDomainAllowed(host, ProxySettings.SniFragmentDomains.Value);
        }

        /// <summary>按域名记住当前网络下真正可用的分片策略。</summary>
        static readonly ConcurrentDictionary<string, TlsFragmentStrategy> learnedStrategies =
            new(StringComparer.OrdinalIgnoreCase);

        static string GetLearnedKey(string host, TlsFragmentStrategy configured)
            => host + "|" + (int)configured;

        static IEnumerable<TlsFragmentStrategy> GetEscalationStrategies(TlsFragmentStrategy current)
        {
            if (current != TlsFragmentStrategy.TinyRecords) yield return TlsFragmentStrategy.TinyRecords;
            if (current != TlsFragmentStrategy.Padding) yield return TlsFragmentStrategy.Padding;
        }

        async Task<ProbeResult> SendFirstPayloadAsync(
            NetworkStream target,
            byte[] payload,
            bool fragment,
            string host,
            int port,
            CancellationToken cancellationToken,
            TlsFragmentStrategy? strategyOverride = null)
        {
            bool fragmented;
            try
            {
                fragmented = await WritePayloadAsync(
                    target,
                    payload,
                    fragment,
                    host,
                    port,
                    cancellationToken,
                    strategyOverride).ConfigureAwait(false);
            }
            catch (Exception ex) when (fragment && IsConnectionReset(ex))
            {
                // 写到一半就被重置：把它当作“分片失败”，交给上层回退重试。
                return new ProbeResult(true, null);
            }

            SniSidecarStats.OnBytesUp(payload.Length);

            if (!fragmented) return new ProbeResult(false, null);

            // 分片后等首字节：如果上游直接 EOF/RST，说明分片可能被中间设备丢弃，触发回退。
            var probeMs = Math.Max(100, ProxySettings.SniFragmentFallbackProbeMilliseconds.Value);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(probeMs);

            var buffer = new byte[16 * 1024];
            try
            {
                var read = await target.ReadAsync(buffer, 0, buffer.Length, timeoutCts.Token).ConfigureAwait(false);
                if (read <= 0) return new ProbeResult(true, null);

                var data = new byte[read];
                Buffer.BlockCopy(buffer, 0, data, 0, read);
                return new ProbeResult(false, data);
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
            => ex is IOException || ex is SocketException || ex.InnerException is SocketException;

        byte[] MaybeRewriteSni(byte[] payload, string host)
        {
            if (!ProxySettings.EnableSniRewrite.Value) return payload;
            if (!IsDomainAllowed(host, ProxySettings.SniRewriteDomains.Value)) return payload;
            if (!TlsClientHello.TryGetSni(payload, out var originalSni)) return payload;

            var target = ProxySettings.SniRewriteHost.Value?.Trim();
            if (string.IsNullOrEmpty(target)) return payload;
            if (!TlsClientHello.TryRewriteSni(payload, target, out var rewritten)) return payload;

            SniSidecarStats.OnRewrite();
            ProxyDiagnostics.Info("SniSidecar", $"SNI 改写: {originalSni ?? host} -> {target}");
            return rewritten;
        }

        async Task<bool> WritePayloadAsync(
            NetworkStream target,
            byte[] payload,
            bool fragment,
            string host,
            int port,
            CancellationToken cancellationToken,
            TlsFragmentStrategy? strategyOverride = null)
        {
            if (!fragment || payload.Length == 0)
            {
                await target.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                return false;
            }

            var strategy = strategyOverride ?? (TlsFragmentStrategy)ProxySettings.SniFragmentStrategy.Value;
            var chunkSize = Math.Max(1, ProxySettings.SniFragmentChunkSize.Value);
            var delay = Math.Max(0, ProxySettings.SniFragmentDelayMilliseconds.Value);
            var jitter = Math.Max(0, ProxySettings.SniFragmentJitterMilliseconds.Value);
            var pieces = Math.Max(2, ProxySettings.SniSplitPieces.Value);

            if (strategy == TlsFragmentStrategy.Padding &&
                TlsClientHello.TryPadClientHello(payload, ProxySettings.SniPaddingBytes.Value, out var padded))
            {
                payload = padded;
            }

            // TinyRecords 会产生几十到上百个 record。保留少量间隔，既避免 TCP 合并，
            // 又能在 1 秒左右发完，不至于触发浏览器握手超时。
            if (strategy == TlsFragmentStrategy.TinyRecords)
            {
                delay = delay <= 0 ? 1 : Math.Min(delay, 10);
            }

            var chunks = TlsClientHello.Fragment(payload, strategy, chunkSize, pieces);

            if (chunks.Count <= 1)
            {
                await target.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                return false;
            }

            var random = jitter > 0 ? new Random(Guid.NewGuid().GetHashCode()) : null;
            for (var i = 0; i < chunks.Count; i++)
            {
                var chunk = chunks[i];
                await target.WriteAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);

                if (i < chunks.Count - 1)
                {
                    var wait = delay + (random == null ? 0 : random.Next(0, jitter + 1));
                    if (wait > 0) await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
                }
            }

            SniSidecarStats.OnFragment(strategy);
            ProxyDiagnostics.Info("SniSidecar",
                $"分片: {host}:{port} 策略={strategy} 段数={chunks.Count} 大小={payload.Length} 延迟={delay}ms 抖动={jitter}ms");
            return true;
        }

        static bool IsDomainAllowed(string host, string? patterns)
        {
            if (string.IsNullOrWhiteSpace(patterns)) return true;
            foreach (var pattern in patterns.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (DomainPatternMatcher.IsMatch(host, pattern.Trim())) return true;
            }
            return false;
        }

        static async Task PumpAsync(
            NetworkStream from,
            NetworkStream to,
            CancellationToken cancellationToken,
            byte[]? initial = null)
        {
            if (initial != null && initial.Length > 0)
            {
                await to.WriteAsync(initial, 0, initial.Length, cancellationToken).ConfigureAwait(false);
                SniSidecarStats.OnBytesDown(initial.Length);
            }

            var buffer = new byte[16 * 1024];
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await from.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (read <= 0) return;
                await to.WriteAsync(buffer, 0, read, cancellationToken).ConfigureAwait(false);
                SniSidecarStats.OnBytesDown(read);
            }
        }

        static async Task AwaitQuietlyAsync(Task task)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch
            {
                // 连接关闭时的异常不需要上报
            }
        }

        static async Task<bool> ReadExactAsync(
            NetworkStream stream,
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken = default)
        {
            var total = 0;
            while (total < count)
            {
                var read = await stream.ReadAsync(buffer, offset + total, count - total, cancellationToken).ConfigureAwait(false);
                if (read <= 0) return false;
                total += read;
            }
            return true;
        }

        static async Task<int> ReadOneByteAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var buffer = new byte[1];
            if (!await ReadExactAsync(stream, buffer, 0, 1, cancellationToken).ConfigureAwait(false)) return 0;
            return buffer[0];
        }

        public void Dispose()
        {
            Stop();
            cts.Dispose();
        }

        enum SocksCommand : byte
        {
            Connect = 0x01,
            Bind = 0x02,
            UdpAssociate = 0x03,
        }

        enum SocksReply : byte
        {
            Succeeded = 0x00,
            GeneralFailure = 0x01,
            HostUnreachable = 0x04,
            CommandNotSupported = 0x07,
        }

        readonly struct FirstPayloadResult
        {
            public FirstPayloadResult(byte[]? data, bool timedOut)
            {
                Data = data;
                TimedOut = timedOut;
            }

            public byte[]? Data { get; }

            public bool TimedOut { get; }
        }

        readonly struct ProbeResult
        {
            public ProbeResult(bool closed, byte[]? data)
            {
                Closed = closed;
                Data = data;
            }

            /// <summary>上游在没有返回任何字节的情况下关闭/重置。</summary>
            public bool Closed { get; }

            /// <summary>探测时提前读到的下游数据。</summary>
            public byte[]? Data { get; }
        }

        readonly struct SocksRequest
        {
            public SocksRequest(SocksCommand command, string? hostName, IPAddress? address, int port)
            {
                Command = command;
                HostName = hostName;
                Address = address;
                Port = port;
            }

            public SocksCommand Command { get; }

            public string? HostName { get; }

            public IPAddress? Address { get; }

            public int Port { get; }
        }
    }

    /// <summary>
    /// SNI sidecar 的启动/停止入口。
    /// </summary>
    public static class SniSidecarService
    {
        static readonly object sync = new();
        static SniFragmentSocks5Server? server;

        /// <summary>
        /// 加速实验室的分片对比模式：禁用“学习到的策略/回退缓存/自动升级”，
        /// 保证每个策略都是独立测试，而不是被上一次的结果带偏。
        /// </summary>
        public static bool BenchmarkMode { get; set; }

        /// <summary>
        /// 当前是否处于证书/MITM 模式，由 Titanium 启动时写入。
        /// sidecar 用它判断哪些域名需要转发给 Titanium。
        /// </summary>
        public static bool CertificateMode { get; set; }

        public static bool IsRunning
        {
            get
            {
                lock (sync) return server != null;
            }
        }

        public static int Port => ProxySettings.SniFragmentPortId.Value;

        /// <summary>
        /// 当前实际监听的端口；未运行时返回设置值。
        /// </summary>
        public static int ActivePort
        {
            get
            {
                lock (sync) return server?.Port ?? Port;
            }
        }

        public static bool ShouldStart =>
            ProxySettings.IsCertificateLessMode.Value ||
            ProxySettings.EnableSniFragment.Value ||
            ProxySettings.EnableSniRewrite.Value ||
            ProxySettings.EnableSniUpstreamRelay.Value;

        public static void Start(bool force = false)
        {
            if (!force && !ShouldStart) return;
            ByedpiRuntime.ResetFailure?.Invoke();
            lock (sync)
            {
                if (server != null)
                {
                    if (server.Port == Port) return;
                    // 端口被修改：先停掉旧实例，避免 VPN 仍指向旧端口。
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
                        var instance = new SniFragmentSocks5Server(candidate);
                        instance.Start();
                        server = instance;
                        if (candidate != startPort)
                        {
                            ProxyDiagnostics.Warn("SniSidecar", $"端口 {startPort} 被占用，改用 {candidate}");
                        }
                        return;
                    }
                    catch (SocketException)
                    {
                        // 端口占用，尝试下一个
                    }
                    catch (Exception ex)
                    {
                        Log.Warn("SniSidecar", ex, "启动 SNI sidecar 失败");
                        ProxyDiagnostics.Warn("SniSidecar", $"启动失败: {ex.Message}");
                        break;
                    }
                }

                ProxyDiagnostics.Warn("SniSidecar", $"端口 {startPort} 起连续 30 个端口均不可用");
            }
        }

        public static void Restart()
        {
            Stop();
            Start();
        }

        public static void Stop()
        {
            try
            {
                ByedpiRuntime.Stop?.Invoke();
            }
            catch
            {
                // 原生内核停止失败不影响 sidecar 停止
            }

            lock (sync)
            {
                if (server == null) return;
                server.Dispose();
                server = null;
            }
        }
    }
}
