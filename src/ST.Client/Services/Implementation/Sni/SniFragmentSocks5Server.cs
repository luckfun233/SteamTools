using System;
using System.Application.ProxyRules;
using System.Application.Settings;
using System.IO;
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
            using (client)
            {
                client.NoDelay = true;
                try
                {
                    using var clientStream = client.GetStream();
                    if (!await NegotiateAsync(clientStream).ConfigureAwait(false)) return;

                    var request = await ReadRequestAsync(clientStream).ConfigureAwait(false);
                    if (request == null) return;

                    using var target = new TcpClient();
                    target.NoDelay = true;
                    if (request.HostName != null)
                    {
                        await target.ConnectAsync(request.HostName, request.Port).ConfigureAwait(false);
                    }
                    else
                    {
                        await target.ConnectAsync(new IPEndPoint(request.Address!, request.Port)).ConfigureAwait(false);
                    }

                    await clientStream.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10).ConfigureAwait(false);

                    using var targetStream = target.GetStream();
                    var upstream = PumpClientToTargetAsync(clientStream, targetStream, request.HostName);
                    var downstream = PumpAsync(targetStream, clientStream);
                    await Task.WhenAny(upstream, downstream).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    ProxyDiagnostics.Warn("SniSidecar", $"连接处理失败: {ex.Message}");
                }
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
            if (header[0] != 0x05 || header[1] != 0x01) return null;

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
            return new SocksRequest(hostName, address, port);
        }

        async Task PumpClientToTargetAsync(NetworkStream client, NetworkStream target, string? hostName)
        {
            var buffer = new byte[16 * 1024];
            var first = true;
            while (!cts.IsCancellationRequested)
            {
                var read = await client.ReadAsync(buffer, 0, buffer.Length, cts.Token).ConfigureAwait(false);
                if (read <= 0) return;

                if (first)
                {
                    first = false;
                    var payload = new byte[read];
                    Buffer.BlockCopy(buffer, 0, payload, 0, read);

                    if (ProxySettings.EnableSniRewrite.Value && !string.IsNullOrWhiteSpace(ProxySettings.SniRewriteHost.Value))
                    {
                        if (TlsClientHello.TryGetSni(payload, out var originalSni) &&
                            IsRewriteAllowed(originalSni) &&
                            TlsClientHello.TryRewriteSni(payload, ProxySettings.SniRewriteHost.Value.Trim(), out var rewritten))
                        {
                            LogSniRewrite(originalSni, ProxySettings.SniRewriteHost.Value.Trim());
                            payload = rewritten;
                        }
                    }

                    if (ProxySettings.EnableSniFragment.Value)
                    {
                        var chunkSize = Math.Max(1, ProxySettings.SniFragmentChunkSize.Value);
                        var delay = Math.Max(0, ProxySettings.SniFragmentDelayMilliseconds.Value);
                        foreach (var chunk in TlsClientHello.Fragment(payload, chunkSize))
                        {
                            await target.WriteAsync(chunk, 0, chunk.Length, cts.Token).ConfigureAwait(false);
                            if (delay > 0) await Task.Delay(delay, cts.Token).ConfigureAwait(false);
                        }
                    }
                    else
                    {
                        await target.WriteAsync(payload, 0, payload.Length, cts.Token).ConfigureAwait(false);
                    }
                    continue;
                }

                await target.WriteAsync(buffer, 0, read, cts.Token).ConfigureAwait(false);
            }
        }

        static bool IsRewriteAllowed(string? host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            foreach (var pattern in ProxySettings.SniRewriteDomains.Value.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                if (DomainPatternMatcher.IsMatch(host, pattern.Trim())) return true;
            }
            return false;
        }

        static void LogSniRewrite(string? host, string sni)
        {
            ProxyDiagnostics.Info("SniSidecar", $"SNI 改写: {host ?? "(ip)"} -> {sni}");
        }

        async Task PumpAsync(NetworkStream from, NetworkStream to)
        {
            var buffer = new byte[16 * 1024];
            while (!cts.IsCancellationRequested)
            {
                var read = await from.ReadAsync(buffer, 0, buffer.Length, cts.Token).ConfigureAwait(false);
                if (read <= 0) return;
                await to.WriteAsync(buffer, 0, read, cts.Token).ConfigureAwait(false);
            }
        }

        static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buffer, int offset, int count)
        {
            var total = 0;
            while (total < count)
            {
                var read = await stream.ReadAsync(buffer, offset + total, count - total).ConfigureAwait(false);
                if (read <= 0) return false;
                total += read;
            }
            return true;
        }

        public void Dispose()
        {
            Stop();
            cts.Dispose();
        }

        readonly struct SocksRequest
        {
            public SocksRequest(string? hostName, IPAddress? address, int port)
            {
                HostName = hostName;
                Address = address;
                Port = port;
            }

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

        public static bool ShouldStart => ProxySettings.EnableSniFragment.Value || ProxySettings.EnableSniRewrite.Value;

        public static void Start()
        {
            if (!ShouldStart) return;
            lock (sync)
            {
                if (server != null) return;
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
