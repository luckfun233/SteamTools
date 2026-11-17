using System;
using System.Application.ProxyRules;
using System.Application.Settings;
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

                    try
                    {
                        target = await ConnectAsync(host, req.Port, excluded, connectionCts.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        SniSidecarStats.OnFailure();
                        ProxyDiagnostics.Warn("SniSidecar", $"连接 {host}:{req.Port} 失败: {ex.Message}");
                        await WriteReplyAsync(clientStream, SocksReply.HostUnreachable).ConfigureAwait(false);
                        return;
                    }

                    target.NoDelay = true;
                    var targetStream = target.GetStream();
                    await WriteReplyAsync(clientStream, SocksReply.Succeeded).ConfigureAwait(false);

                    // 先拿到客户端的第一个负载；TLS 客户端会立即发送 ClientHello。
                    // 对 SMTP/IMAP 等“服务器先说”的协议，等一小段时间后按普通双向转发处理。
                    var firstPayload = await ReadFirstPayloadAsync(
                        clientStream,
                        Math.Max(100, ProxySettings.SniFragmentReadTimeoutMilliseconds.Value),
                        connectionCts.Token).ConfigureAwait(false);

                    if (firstPayload.Data == null)
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

                    // VPN/tun2socks 只能拿到目标 IP，真正的域名在 ClientHello 的 SNI 里。
                    // 规则匹配、分片白名单和 SNI 改写都必须使用这个域名，否则在 VPN 模式下
                    // 所有域名规则都会因为 host 是 IP 而失效。
                    var effectiveHost = host;
                    if (IPAddress.TryParse(host, out _) &&
                        TlsClientHello.TryGetSni(firstPayload.Data, out var payloadSni) &&
                        !string.IsNullOrWhiteSpace(payloadSni))
                    {
                        effectiveHost = payloadSni!;
                        ProxyDiagnostics.Info("SniSidecar", $"从 ClientHello 识别域名: {host} -> {effectiveHost}");
                    }

                    var payload = MaybeRewriteSni(firstPayload.Data, effectiveHost);
                    var excludedBySni = excluded || rules.IsExcluded(effectiveHost);

                    var fragment = ShouldFragment(effectiveHost, payload, excludedBySni) &&
                                   !FragmentFallbackCache.ShouldSkip(effectiveHost);

                    var probe = await SendFirstPayloadAsync(
                        targetStream,
                        payload,
                        fragment,
                        effectiveHost,
                        req.Port,
                        connectionCts.Token).ConfigureAwait(false);

                    if (probe.Closed && fragment && ProxySettings.EnableSniFragmentFallback.Value)
                    {
                        // 分片被重置：记住该域名，换一条连接用不分片方式重试一次。
                        FragmentFallbackCache.Duration = TimeSpan.FromMinutes(
                            Math.Max(1, ProxySettings.SniFragmentFallbackCacheMinutes.Value));
                        FragmentFallbackCache.MarkFailure(effectiveHost);
                        SniSidecarStats.OnFallback();
                        ProxyDiagnostics.Warn("SniSidecar", $"分片握手被重置，回退直连重试: {effectiveHost}");

                        target.Dispose();
                        try
                        {
                            // VPN 只传 IP 时，优先用 DevSidecar preSetIpList 里延迟最低的 IP 重试，
                            // 避免继续连到被污染/被黑洞的地址。
                            var retryHost = host;
                            var preferredIp = await ResolveFallbackIpAsync(
                                effectiveHost, req.Port, rules, excludedBySni, connectionCts.Token).ConfigureAwait(false);
                            if (preferredIp != null && !string.Equals(preferredIp.ToString(), host, StringComparison.OrdinalIgnoreCase))
                            {
                                retryHost = preferredIp.ToString();
                                ProxyDiagnostics.Info("SniSidecar", $"回退改用预置 IP: {effectiveHost} -> {retryHost}");
                                SniSidecarStats.OnPresetIp();
                            }

                            target = await ConnectAsync(retryHost, req.Port, excludedBySni, connectionCts.Token).ConfigureAwait(false);
                            target.NoDelay = true;
                            targetStream = target.GetStream();
                            probe = await SendFirstPayloadAsync(
                                targetStream,
                                payload,
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

            var concurrency = new SemaphoreSlim(32, 32);
            var controlMonitor = MonitorControlConnectionAsync(control, cancellationToken);
            var lifetime = Task.Delay(TimeSpan.FromMinutes(10), cancellationToken);

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var receiveTask = udp.ReceiveAsync();
                    var completed = await Task.WhenAny(receiveTask, controlMonitor, lifetime).ConfigureAwait(false);
                    if (completed != receiveTask) break;

                    var result = receiveTask.Result;
                    _ = HandleUdpDatagramAsync(udp, result, concurrency, cancellationToken);
                }
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                ProxyDiagnostics.Warn("SniSidecar", $"UDP ASSOCIATE 结束: {ex.Message}");
            }
            finally
            {
                // 不 Dispose：fire-and-forget 的 UDP 处理可能仍在释放信号量。
                // 每个 UDP ASSOCIATE 只创建一次，连接结束后由 GC 回收。
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
            UdpReceiveResult result,
            SemaphoreSlim concurrency,
            CancellationToken cancellationToken)
        {
            var datagram = result.Buffer;
            if (datagram == null || datagram.Length < 4 || datagram.Length > MaxUdpDatagram) return;
            if (datagram[2] != 0) return; // 不支持 SOCKS5 UDP 分片

            var acquired = false;
            try
            {
                await concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquired = true;

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

                if (response == null)
                {
                    response = await ForwardUdpAsync(address, host, targetPort, payload, cancellationToken).ConfigureAwait(false);
                }
                if (response == null) return;

                var responsePacket = BuildUdpResponse(address, host, targetPort, response);
                await udp.SendAsync(responsePacket, responsePacket.Length, result.RemoteEndPoint).ConfigureAwait(false);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                ProxyDiagnostics.Warn("SniSidecar", $"UDP 转发失败: {ex.Message}");
            }
            finally
            {
                if (acquired) concurrency.Release();
            }
        }

        static async Task<byte[]?> ForwardUdpAsync(
            IPAddress? address,
            string? host,
            int port,
            byte[] payload,
            CancellationToken cancellationToken)
        {
            try
            {
                if (address == null && !string.IsNullOrEmpty(host))
                {
                    var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                    address = addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork) ??
                              addresses.FirstOrDefault();
                }
                if (address == null) return null;

                using var client = new UdpClient(address.AddressFamily);
                client.Connect(new IPEndPoint(address, port));
                await client.SendAsync(payload, payload.Length).ConfigureAwait(false);

                var receiveTask = client.ReceiveAsync();
                var completed = await Task.WhenAny(
                    receiveTask,
                    Task.Delay(TimeSpan.FromSeconds(3), cancellationToken)).ConfigureAwait(false);
                if (completed != receiveTask) return null;
                return receiveTask.Result.Buffer;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                ProxyDiagnostics.Warn("SniSidecar", $"UDP 目标 {host ?? address?.ToString()}:{port} 不可达: {ex.Message}");
                return null;
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

        async Task<TcpClient> ConnectAsync(string host, int port, bool excluded, CancellationToken cancellationToken)
        {
            if (ProxySettings.EnableSniUpstreamRelay.Value && !excluded &&
                IsDomainAllowed(host, ProxySettings.SniUpstreamRelayDomains.Value))
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
                    await relay.ConnectAsync(relayHost, relayPort).ConfigureAwait(false);
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

            var target = new TcpClient { NoDelay = true };
            try
            {
                var presetIp = await ResolveTargetIpAsync(host, port, excluded, cancellationToken).ConfigureAwait(false);
                if (presetIp != null)
                {
                    await target.ConnectAsync(new IPEndPoint(presetIp, port)).ConfigureAwait(false);
                }
                else
                {
                    await target.ConnectAsync(host, port).ConfigureAwait(false);
                }
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

            var rules = ProxyRuleEngine.Current;
            var presetIps = rules.GetPresetIps(host);
            var builtInIps = GetBuiltInPresetIps(host);
            if (presetIps.Count > 0 || builtInIps.Count > 0)
            {
                var candidates = presetIps.Concat(builtInIps)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
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
        /// 分片失败、需要换 IP 重试时，从 DevSidecar 预置 IP 里选一个延迟最低的。
        /// </summary>
        static async Task<IPAddress?> ResolveFallbackIpAsync(
            string host,
            int port,
            ProxyRuleSet rules,
            bool excluded,
            CancellationToken cancellationToken)
        {
            if (excluded || IPAddress.TryParse(host, out _)) return null;

            var candidates = rules.GetPresetIps(host)
                .Concat(GetBuiltInPresetIps(host))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (candidates.Count == 0) return null;

            return await PresetIpSelector.PickAsync(
                candidates,
                port,
                TimeSpan.FromMilliseconds(800),
                cancellationToken).ConfigureAwait(false);
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

        async Task<ProbeResult> SendFirstPayloadAsync(
            NetworkStream target,
            byte[] payload,
            bool fragment,
            string host,
            int port,
            CancellationToken cancellationToken)
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
                    cancellationToken).ConfigureAwait(false);
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
            CancellationToken cancellationToken)
        {
            if (!fragment || payload.Length == 0)
            {
                await target.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                return false;
            }

            var strategy = (TlsFragmentStrategy)ProxySettings.SniFragmentStrategy.Value;
            var chunkSize = Math.Max(1, ProxySettings.SniFragmentChunkSize.Value);
            var delay = Math.Max(0, ProxySettings.SniFragmentDelayMilliseconds.Value);
            var jitter = Math.Max(0, ProxySettings.SniFragmentJitterMilliseconds.Value);
            var pieces = Math.Max(2, ProxySettings.SniSplitPieces.Value);
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
            lock (sync)
            {
                if (server == null) return;
                server.Dispose();
                server = null;
            }
        }
    }
}
