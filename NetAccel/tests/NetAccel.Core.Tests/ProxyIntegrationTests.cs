using System.Net;
using System.Net.Sockets;
using System.Text;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Proxy;
using NetAccel.Core.Rules;
using NetAccel.Core.Tls;
using Xunit;

namespace NetAccel.Core.Tests;

public class ProxyIntegrationTests
{
    [Fact]
    public async Task Socks5_Tunnel_Echoes()
    {
        await using var echo = new EchoServer();
        await using var service = CreateService();
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, service.Socks5Port);
        var stream = client.GetStream();
        await SocksConnectAsync(stream, IPAddress.Loopback.ToString(), echo.Port);

        Assert.True(await EchoAsync(stream));
    }

    [Fact]
    public async Task Http_Connect_Tunnel_Echoes()
    {
        await using var echo = new EchoServer();
        await using var service = CreateService();
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, service.HttpPort);
        var stream = client.GetStream();

        var connect = Encoding.ASCII.GetBytes($"CONNECT 127.0.0.1:{echo.Port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        await stream.WriteAsync(connect);

        var header = await ReadHeaderAsync(stream);
        Assert.StartsWith("HTTP/1.1 200", header);
        Assert.True(await EchoAsync(stream));
    }

    [Fact]
    public async Task Http_Proxy_Forwards_Plain_Request()
    {
        await using var httpServer = new SimpleHttpServer("hello-netaccel");
        await using var service = CreateService();
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, service.HttpPort);
        using var stream = client.GetStream();

        var request = $"GET http://127.0.0.1:{httpServer.Port}/hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));

        using var ms = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read <= 0) break;
            ms.Write(buffer, 0, read);
        }

        var response = Encoding.UTF8.GetString(ms.ToArray());
        Assert.Contains("200 OK", response);
        Assert.Contains("hello-netaccel", response);
    }

    [Fact]
    public async Task Blocked_Rule_Refuses_Connection()
    {
        await using var echo = new EchoServer();
        await using var service = CreateService(s => s.EnableCustomRules = true);
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        service.Rules.SetCustom(new ProxyRuleSet(
            new[]
            {
                new ProxyRule
                {
                    DomainPattern = "127.0.0.1",
                    Group = ProxyRuleGroups.Custom,
                    Block = true,
                },
            },
            Array.Empty<string>(),
            new Dictionary<string, IReadOnlyList<string>>()));

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, service.Socks5Port);
        var stream = client.GetStream();

        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var greeting = new byte[2];
        await ReadExactAsync(stream, greeting);

        var request = new byte[10];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x01;
        request[4] = 127;
        request[5] = 0;
        request[6] = 0;
        request[7] = 1;
        request[8] = (byte)(echo.Port >> 8);
        request[9] = (byte)(echo.Port & 0xFF);
        await stream.WriteAsync(request);

        var reply = new byte[10];
        Assert.True(await ReadExactAsync(stream, reply));
        Assert.Equal(0x02, reply[1]);
    }

    [Fact]
    public async Task Fragmentation_Path_Still_Delivers_Data()
    {
        await using var echo = new EchoServer();
        await using var service = CreateService(configure: s =>
        {
            s.EnableSniFragment = true;
            s.OnlyFragmentTls = false;
            s.FragmentDomains = string.Empty;
            s.FragmentStrategy = TlsFragmentStrategy.Fixed;
            s.FragmentChunkSize = 4;
            s.FragmentDelayMs = 0;
            s.FallbackProbeMs = 300;
        });
        var start = await service.StartAsync();
        Assert.True(start.Success, start.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, service.Socks5Port);
        var stream = client.GetStream();
        await SocksConnectAsync(stream, IPAddress.Loopback.ToString(), echo.Port);

        Assert.True(await EchoAsync(stream));
        Assert.True(service.Stats.Fragmented >= 1);
    }

    [Fact]
    public async Task Start_Reports_Port_Conflict()
    {
        var blocker = new TcpListener(IPAddress.Loopback, 0);
        blocker.Start();
        var busyPort = ((IPEndPoint)blocker.LocalEndpoint).Port;

        try
        {
            await using var service = CreateService(configure: s =>
            {
                s.EnableSocks5 = true;
                s.EnableHttp = false;
                s.Socks5Port = busyPort;
            });
            var start = await service.StartAsync();
            Assert.False(start.Success);
            Assert.Contains("占用", start.Message);
        }
        finally
        {
            blocker.Stop();
        }
    }

    static AccelProxyService CreateService(Action<AccelSettings>? configure = null)
    {
        var settings = new AccelSettings
        {
            EnableSocks5 = true,
            EnableHttp = true,
            Socks5Port = GetFreePort(),
            HttpPort = GetFreePort(),
            EnableRemoteRules = false,
            EnableCustomRules = false,
            EnableDoh = false,
            EnableSniFragment = false,
            EnableSniRewrite = false,
            SetSystemProxy = false,
            EnableDiagnostics = false,
            FirstPayloadTimeoutMs = 200,
        };

        configure?.Invoke(settings);
        settings.Normalize();
        return new AccelProxyService(settings, NullLogger.Instance, new NetAccel.Core.SystemProxy.SystemProxyManager(
            Path.Combine(Path.GetTempPath(), "netaccel-tests", Guid.NewGuid().ToString("N"), "state.json")));
    }

    static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    static async Task SocksConnectAsync(NetworkStream stream, string host, int port)
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
        Assert.Equal(0x05, reply[0]);
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

    static async Task<int> ReadOneAsync(NetworkStream stream)
    {
        var one = new byte[1];
        return await ReadExactAsync(stream, one) ? one[0] : 0;
    }

    static async Task<bool> EchoAsync(NetworkStream stream)
    {
        var payload = Encoding.UTF8.GetBytes("netaccel-" + Guid.NewGuid().ToString("N"));
        await stream.WriteAsync(payload);

        var response = new byte[payload.Length];
        if (!await ReadExactAsync(stream, response)) return false;
        return response.SequenceEqual(payload);
    }

    static async Task<string> ReadHeaderAsync(NetworkStream stream)
    {
        var bytes = new List<byte>();
        var one = new byte[1];
        while (bytes.Count < 8192)
        {
            if (!await ReadExactAsync(stream, one)) break;
            bytes.Add(one[0]);
            if (bytes.Count >= 4 &&
                bytes[^4] == (byte)'\r' && bytes[^3] == (byte)'\n' &&
                bytes[^2] == (byte)'\r' && bytes[^1] == (byte)'\n')
            {
                break;
            }
        }
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total));
            if (read <= 0) return false;
            total += read;
        }
        return true;
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

    sealed class SimpleHttpServer : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource cts = new();
        readonly Task acceptTask;
        readonly string body;

        public SimpleHttpServer(string body)
        {
            this.body = body;
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
                            var buffer = new byte[4096];
                            await stream.ReadAsync(buffer, cancellationToken);

                            var bodyBytes = Encoding.UTF8.GetBytes(body);
                            var response = $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {bodyBytes.Length}\r\nConnection: close\r\n\r\n";
                            await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
                            await stream.WriteAsync(bodyBytes, cancellationToken);
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
}
