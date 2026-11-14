using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Proxy;
using NetAccel.Core.Tls;
using Xunit;

namespace NetAccel.Core.Tests;

/// <summary>
/// 无证书模式端到端测试：本地起一个真实 TLS 服务器，经 SOCKS5 代理建立 TLS 握手，
/// 验证分片/自动回退不会破坏 ClientHello，也不会让握手失败。
/// </summary>
public class CertlessModeTests
{
    [Theory]
    [InlineData(TlsFragmentStrategy.SniBoundary)]
    [InlineData(TlsFragmentStrategy.SniPieces)]
    [InlineData(TlsFragmentStrategy.TlsRecordSplit)]
    [InlineData(TlsFragmentStrategy.Fixed)]
    [InlineData(TlsFragmentStrategy.Record)]
    [InlineData(TlsFragmentStrategy.Random)]
    public async Task Tls_Handshake_Succeeds_Through_Proxy(TlsFragmentStrategy strategy)
    {
        await using var tls = new TlsEchoServer();
        await using var service = CreateService(strategy);
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        Assert.True(await ConnectAndEchoAsync(service.Socks5Port, tls.Port));
        Assert.True(service.Stats.Fragmented >= 1, "应至少发生一次分片");
    }

    [Fact]
    public async Task Auto_Strategy_Handshake_Succeeds()
    {
        await using var tls = new TlsEchoServer();
        await using var service = CreateService(TlsFragmentStrategy.Auto);
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        Assert.True(await ConnectAndEchoAsync(service.Socks5Port, tls.Port));
        Assert.True(service.Stats.Fragmented >= 1);
    }

    [Fact]
    public async Task Oob_Strategy_Falls_Back_Without_Breaking_Tls()
    {
        await using var tls = new TlsEchoServer();
        await using var service = CreateService(TlsFragmentStrategy.OobSplit);
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        // 某些平台/内核不允许 OOB 发送多字节，允许它回退到不分片，但握手必须成功。
        Assert.True(await ConnectAndEchoAsync(service.Socks5Port, tls.Port));
    }

    [Fact]
    public async Task Http_Connect_Relay_Works()
    {
        await using var echo = new EchoServer();
        await using var relay = new HttpConnectRelay();
        await using var service = CreateService(TlsFragmentStrategy.SniBoundary, configure: s =>
        {
            s.BypassLocalhost = false;
            s.EnableUpstreamRelay = true;
            s.RelayType = RelayType.Http;
            s.RelayHost = "127.0.0.1";
            s.RelayPort = relay.Port;
            s.RelayDomains = string.Empty;
            s.EnableSniFragment = false;
        });
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, service.Socks5Port);
        var stream = client.GetStream();
        await SocksConnectAsync(stream, "127.0.0.1", echo.Port);

        var payload = Encoding.UTF8.GetBytes("relay-" + Guid.NewGuid().ToString("N"));
        await stream.WriteAsync(payload);
        var response = new byte[payload.Length];
        Assert.True(await ReadExactAsync(stream, response));
        Assert.Equal(payload, response);
        Assert.True(service.Stats.Relayed >= 1);
    }

    [Fact]
    public async Task Socks5_Relay_Works()
    {
        await using var echo = new EchoServer();
        await using var upstream = CreateService(TlsFragmentStrategy.SniBoundary, s =>
        {
            s.EnableSniFragment = false;
            s.BypassLocalhost = true;
        });
        var upstreamStart = await upstream.StartAsync();
        Assert.True(upstreamStart.Success, upstreamStart.Message);

        await using var service = CreateService(TlsFragmentStrategy.SniBoundary, configure: s =>
        {
            s.BypassLocalhost = false;
            s.EnableUpstreamRelay = true;
            s.RelayType = RelayType.Socks5;
            s.RelayHost = "127.0.0.1";
            s.RelayPort = upstream.Socks5Port;
            s.RelayDomains = string.Empty;
            s.EnableSniFragment = false;
        });
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, service.Socks5Port);
        var stream = client.GetStream();
        await SocksConnectAsync(stream, "127.0.0.1", echo.Port);

        var payload = Encoding.UTF8.GetBytes("socks-relay-" + Guid.NewGuid().ToString("N"));
        await stream.WriteAsync(payload);
        var response = new byte[payload.Length];
        Assert.True(await ReadExactAsync(stream, response));
        Assert.Equal(payload, response);
        Assert.True(service.Stats.Relayed >= 1);
    }

    [Fact]
    public void Socks5_Address_Has_Atyp_First()
    {
        var domain = NetAccel.Core.Net.NetUtil.BuildSocks5Address("github.com", 443);
        Assert.Equal(0x03, domain[0]);
        Assert.Equal(10, domain[1]);
        Assert.Equal(443, (domain[^2] << 8) | domain[^1]);

        var ipv4 = NetAccel.Core.Net.NetUtil.BuildSocks5Address("127.0.0.1", 80);
        Assert.Equal(0x01, ipv4[0]);
        Assert.Equal(80, (ipv4[^2] << 8) | ipv4[^1]);

        var ipv6 = NetAccel.Core.Net.NetUtil.BuildSocks5Address("::1", 443);
        Assert.Equal(0x04, ipv6[0]);
    }

    static AccelProxyService CreateService(
        TlsFragmentStrategy strategy,
        Action<AccelSettings>? configure = null)
    {
        var settings = new AccelSettings
        {
            EnableSocks5 = true,
            EnableHttp = false,
            Socks5Port = GetFreePort(),
            EnableRemoteRules = false,
            EnableCustomRules = false,
            EnableBuiltInRules = false,
            EnableDoh = false,
            EnableSniFragment = true,
            OnlyFragmentTls = true,
            FragmentDomains = string.Empty,
            FragmentStrategy = strategy,
            FragmentDelayMs = 1,
            FragmentChunkSize = 32,
            SplitPieces = 3,
            FallbackProbeMs = 400,
            FirstPayloadTimeoutMs = 1200,
            SetSystemProxy = false,
            EnableDiagnostics = false,
            BypassLocalhost = false,
        };

        configure?.Invoke(settings);
        settings.Normalize();
        return new AccelProxyService(settings, NullLogger.Instance, new NetAccel.Core.SystemProxy.SystemProxyManager(
            Path.Combine(Path.GetTempPath(), "netaccel-tests", Guid.NewGuid().ToString("N"), "state.json")));
    }

    static async Task<bool> ConnectAndEchoAsync(int socksPort, int targetPort)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, socksPort);
        var stream = client.GetStream();
        await SocksConnectAsync(stream, "127.0.0.1", targetPort);

        using var ssl = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
        }, timeout.Token);

        var payload = Encoding.UTF8.GetBytes("certless-" + Guid.NewGuid().ToString("N"));
        await ssl.WriteAsync(payload, timeout.Token);

        var response = new byte[payload.Length];
        Assert.True(await ReadExactAsync(ssl, response, timeout.Token));
        return response.SequenceEqual(payload);
    }

    static async Task SocksConnectAsync(Stream stream, string host, int port)
    {
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var greeting = new byte[2];
        Assert.True(await ReadExactAsync(stream, greeting));
        Assert.Equal(0x05, greeting[0]);
        Assert.Equal(0x00, greeting[1]);

        var hostBytes = Encoding.ASCII.GetBytes(host);
        var request = new byte[5 + hostBytes.Length + 2];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x03;
        request[4] = (byte)hostBytes.Length;
        hostBytes.CopyTo(request, 5);
        request[^2] = (byte)(port >> 8);
        request[^1] = (byte)(port & 0xFF);
        await stream.WriteAsync(request);

        var reply = new byte[4];
        Assert.True(await ReadExactAsync(stream, reply));
        Assert.Equal(0x00, reply[1]);

        var length = reply[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => await ReadOneAsync(stream),
            _ => 0,
        };
        var tail = new byte[length + 2];
        if (tail.Length > 0) Assert.True(await ReadExactAsync(stream, tail));
    }

    static async Task<int> ReadOneAsync(Stream stream)
    {
        var one = new byte[1];
        return await ReadExactAsync(stream, one) ? one[0] : 0;
    }

    static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken = default)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken);
            if (read <= 0) return false;
            total += read;
        }
        return true;
    }

    static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    sealed class TlsEchoServer : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource cts = new();
        readonly Task acceptTask;
        readonly X509Certificate2 certificate;

        public TlsEchoServer()
        {
            certificate = CreateCertificate();
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            acceptTask = Task.Run(() => AcceptLoopAsync(cts.Token));
        }

        public int Port { get; }

        async Task AcceptLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken);
                }
                catch
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            using var ssl = new SslStream(client.GetStream(), false);
                            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                            {
                                ServerCertificate = certificate,
                            }, cancellationToken);

                            var buffer = new byte[4096];
                            var read = await ssl.ReadAsync(buffer, cancellationToken);
                            if (read > 0)
                            {
                                await ssl.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                            }
                        }
                        catch
                        {
                            // 客户端/握手失败不影响其它连接
                        }
                    }
                }, CancellationToken.None);
            }
        }

        static X509Certificate2 CreateCertificate()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=localhost",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
        }

        public async ValueTask DisposeAsync()
        {
            cts.Cancel();
            listener.Stop();
            certificate.Dispose();
            try
            {
                await acceptTask;
            }
            catch
            {
                // ignore
            }
            cts.Dispose();
        }
    }

    sealed class EchoServer : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource cts = new();
        readonly Task acceptTask;

        public EchoServer()
        {
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            acceptTask = Task.Run(() => AcceptLoopAsync(cts.Token));
        }

        public int Port { get; }

        async Task AcceptLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken);
                }
                catch
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            var stream = client.GetStream();
                            var buffer = new byte[8192];
                            while (true)
                            {
                                var read = await stream.ReadAsync(buffer, cancellationToken);
                                if (read <= 0) break;
                                await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                            }
                        }
                        catch
                        {
                            // ignore
                        }
                    }
                }, CancellationToken.None);
            }
        }

        public async ValueTask DisposeAsync()
        {
            cts.Cancel();
            listener.Stop();
            try
            {
                await acceptTask;
            }
            catch
            {
                // ignore
            }
            cts.Dispose();
        }
    }

    /// <summary>本地 HTTP CONNECT 中继，模拟公司代理/沙箱出口。</summary>
    sealed class HttpConnectRelay : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource cts = new();
        readonly Task acceptTask;

        public HttpConnectRelay()
        {
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            acceptTask = Task.Run(() => AcceptLoopAsync(cts.Token));
        }

        public int Port { get; }

        async Task AcceptLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken);
                }
                catch
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            var stream = client.GetStream();
                            var header = await ReadHeaderAsync(stream, cancellationToken);
                            if (header == null) return;

                            var requestLine = header.Split("\r\n")[0];
                            var parts = requestLine.Split(' ');
                            if (parts.Length < 2) return;

                            var target = parts[1];
                            var colon = target.LastIndexOf(':');
                            if (colon <= 0) return;
                            var host = target[..colon].Trim('[', ']');
                            var port = int.Parse(target[(colon + 1)..]);

                            using var upstream = new TcpClient();
                            await upstream.ConnectAsync(host, port, cancellationToken);
                            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"),
                                cancellationToken);

                            var upstreamStream = upstream.GetStream();
                            var up = PumpAsync(stream, upstreamStream, cancellationToken);
                            var down = PumpAsync(upstreamStream, stream, cancellationToken);
                            await Task.WhenAny(up, down);
                        }
                        catch
                        {
                            // ignore
                        }
                    }
                }, CancellationToken.None);
            }
        }

        static async Task<string?> ReadHeaderAsync(Stream stream, CancellationToken cancellationToken)
        {
            var bytes = new List<byte>(256);
            var one = new byte[1];
            while (bytes.Count < 16384)
            {
                if (!await ReadExactAsync(stream, one, cancellationToken)) return null;
                bytes.Add(one[0]);
                if (bytes.Count >= 4 &&
                    bytes[^4] == (byte)'\r' && bytes[^3] == (byte)'\n' &&
                    bytes[^2] == (byte)'\r' && bytes[^1] == (byte)'\n')
                {
                    return Encoding.ASCII.GetString(bytes.ToArray(), 0, bytes.Count - 4);
                }
            }
            return null;
        }

        static async Task PumpAsync(Stream from, Stream to, CancellationToken cancellationToken)
        {
            try
            {
                var buffer = new byte[8192];
                while (true)
                {
                    var read = await from.ReadAsync(buffer, cancellationToken);
                    if (read <= 0) break;
                    await to.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
            }
            catch
            {
                // ignore
            }
        }

        public async ValueTask DisposeAsync()
        {
            cts.Cancel();
            listener.Stop();
            try
            {
                await acceptTask;
            }
            catch
            {
                // ignore
            }
            cts.Dispose();
        }
    }
}
