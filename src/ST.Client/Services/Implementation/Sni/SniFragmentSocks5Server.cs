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
            SniSidecarStats.OnConnection();
            using (client)
            {
                client.NoDelay = true;
                var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                try
                {
                    using var clientStream = client.GetStream();
                    if (!await NegotiateAsync(clientStream).ConfigureAwait(false)) return;

                    var request = await ReadRequestAsync(clientStream).ConfigureAwait(false);
                    if (request == null) return;
                    var req = request.Value;

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

                    TcpClient target;
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

                    using (target)
                    {
                        target.NoDelay = true;
                        await WriteReplyAsync(clientStream, SocksReply.Succeeded).ConfigureAwait(false);

                        using var targetStream = target.GetStream();
                        var upstream = PumpClientToTargetAsync(clientStream, targetStream, host, req.Port, excluded, connectionCts.Token);
                        var downstream = PumpAsync(targetStream, clientStream, connectionCts.Token);

                        await Task.WhenAny(upstream, downstream).ConfigureAwait(false);
                        connectionCts.Cancel();

                        await AwaitQuietlyAsync(upstream).ConfigureAwait(false);
                        await AwaitQuietlyAsync(downstream).ConfigureAwait(false);
                    }
                }
                catch (Exception ex) when (!cts.IsCancellationRequested)
                {
                    SniSidecarStats.OnFailure();
                    ProxyDiagnostics.Warn("SniSidecar", $"连接处理失败: {ex.Message}");
                }
                finally
                {
                    connectionCts.Dispose();
                }
            }
        }

        async Task<TcpClient> ConnectAsync(string host, int port, bool excluded, CancellationToken cancellationToken)
        {
            if (ProxySettings.EnableSniUpstreamRelay.Value && !excluded)
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
            var buffer = new byte[] { 0x05, (byte)reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
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
            string host,
            int port,
            bool excluded,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[32 * 1024];
            var first = true;
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await client.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (read <= 0) return;

                if (first)
                {
                    first = false;
                    var payload = await PrepareFirstPayloadAsync(client, buffer, read, cancellationToken).ConfigureAwait(false);
                    if (!excluded)
                    {
                        payload = MaybeRewriteSni(payload, host);
                    }
                    await WritePayloadAsync(target, payload, host, port, excluded, cancellationToken).ConfigureAwait(false);
                    SniSidecarStats.OnBytesUp(payload.Length);
                    continue;
                }

                await target.WriteAsync(buffer, 0, read, cancellationToken).ConfigureAwait(false);
                SniSidecarStats.OnBytesUp(read);
            }
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

        async Task WritePayloadAsync(
            NetworkStream target,
            byte[] payload,
            string host,
            int port,
            bool excluded,
            CancellationToken cancellationToken)
        {
            var isTls = payload.Length > 0 && payload[0] == 0x16;
            var fragment = !excluded &&
                           ProxySettings.EnableSniFragment.Value &&
                           (!ProxySettings.SniFragmentOnlyTls.Value || isTls) &&
                           IsDomainAllowed(host, ProxySettings.SniFragmentDomains.Value);

            if (!fragment || payload.Length == 0)
            {
                await target.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                return;
            }

            var strategy = (TlsFragmentStrategy)ProxySettings.SniFragmentStrategy.Value;
            var chunkSize = Math.Max(1, ProxySettings.SniFragmentChunkSize.Value);
            var delay = Math.Max(0, ProxySettings.SniFragmentDelayMilliseconds.Value);
            var chunks = TlsClientHello.Fragment(payload, strategy, chunkSize);

            if (chunks.Count <= 1 || (strategy == TlsFragmentStrategy.SniBoundary && chunks.Count == 1))
            {
                await target.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                return;
            }

            foreach (var chunk in chunks)
            {
                await target.WriteAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);
                if (delay > 0) await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }

            SniSidecarStats.OnFragment();
            ProxyDiagnostics.Info("SniSidecar",
                $"分片: {host}:{port} 策略={strategy} 段数={chunks.Count} 大小={payload.Length}");
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

        static async Task PumpAsync(NetworkStream from, NetworkStream to, CancellationToken cancellationToken)
        {
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
                try
                {
                    var instance = new SniFragmentSocks5Server(Port);
                    instance.Start();
                    server = instance;
                }
                catch (Exception ex)
                {
                    Log.Warn("SniSidecar", ex, "启动 SNI sidecar 失败");
                    ProxyDiagnostics.Warn("SniSidecar", $"启动失败: {ex.Message}");
                }
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
