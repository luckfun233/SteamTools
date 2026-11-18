using NUnit.Framework;
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Application.ProxyRules;
using System.Application.Services.Implementation;
using System.Application.Settings;

namespace System.Application;

[TestFixture]
[Category("Integration")]
public class DnsAndSniIntegrationTest
{
    [Test]
    public async Task SniSidecar_UdpAssociate_Relays_Dns()
    {
        var originalFragment = ProxySettings.EnableSniFragment.Value;
        var originalPort = ProxySettings.SniFragmentPortId.Value;
        var originalDoh = ProxySettings.EnableDoh.Value;
        var sidecarPort = GetFreeTcpPort();
        var fakeDnsPort = GetFreeUdpPort();

        using var fakeDns = new FakeDnsServer(fakeDnsPort, IPAddress.Parse("5.6.7.8"));
        fakeDns.Start();

        try
        {
            ProxySettings.EnableSniFragment.Value = true;
            ProxySettings.SniFragmentPortId.Value = sidecarPort;
            ProxySettings.EnableDoh.Value = false;
            SniSidecarService.Start(force: true);
            Assert.That(SniSidecarService.IsRunning, Is.True);

            using var control = new TcpClient();
            await control.ConnectAsync(IPAddress.Loopback, SniSidecarService.ActivePort);
            var stream = control.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, 0, 3);
            var greeting = new byte[2];
            await ReadExactAsync(stream, greeting);

            await stream.WriteAsync(new byte[] { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
            var reply = new byte[10];
            await ReadExactAsync(stream, reply);
            Assert.That(reply[1], Is.EqualTo(0x00));
            var relayPort = (reply[8] << 8) | reply[9];

            var query = BuildDnsQuery("github.com");
            var packet = new byte[10 + query.Length];
            packet[3] = 0x01;
            packet[4] = 127; packet[5] = 0; packet[6] = 0; packet[7] = 1;
            packet[8] = (byte)(fakeDnsPort >> 8);
            packet[9] = (byte)(fakeDnsPort & 0xFF);
            query.CopyTo(packet, 10);

            using var udp = new UdpClient();
            await udp.SendAsync(packet, packet.Length, new IPEndPoint(IPAddress.Loopback, relayPort));
            var receive = udp.ReceiveAsync();
            var completed = await Task.WhenAny(receive, Task.Delay(5000));
            Assert.That(completed, Is.SameAs(receive), "UDP ASSOCIATE 无响应");

            var response = receive.Result.Buffer;
            Assert.That(response.Length, Is.GreaterThan(10));
            var dns = new byte[response.Length - 10];
            Buffer.BlockCopy(response, 10, dns, 0, dns.Length);
            Assert.That(dns[0], Is.EqualTo(query[0]));
            Assert.That(dns[1], Is.EqualTo(query[1]));
            Assert.That((dns[7]), Is.EqualTo(1), "应返回 1 条 A 记录");
        }
        finally
        {
            SniSidecarService.Stop();
            ProxySettings.EnableSniFragment.Value = originalFragment;
            ProxySettings.SniFragmentPortId.Value = originalPort;
            ProxySettings.EnableDoh.Value = originalDoh;
        }
    }

    [Test]
    public async Task DnsProxy_PresetIp_Overrides_Answer()
    {
        var originalDoh = ProxySettings.EnableDoh.Value;
        var originalFallback = ProxySettings.DnsFallbackServers.Value;
        var originalPort = ProxySettings.DnsProxyPortId.Value;
        var originalPreset = ProxySettings.EnableDnsPresetIp.Value;
        var fakeDnsPort = GetFreeUdpPort();
        var proxyPort = GetFreeUdpPort();

        using var fakeDns = new FakeDnsServer(fakeDnsPort, IPAddress.Parse("9.9.9.9"));
        fakeDns.Start();

        var rules = DevSidecarConfigLoader.Parse(@"{
  preSetIpList: {
    ""*.preset.test"": [""1.2.3.4"", ""1.2.3.5""],
  },
}");
        ProxyRuleEngine.Apply(rules);

        try
        {
            ProxySettings.EnableDoh.Value = false;
            ProxySettings.EnableDnsPresetIp.Value = true;
            ProxySettings.DnsFallbackServers.Value = "127.0.0.1:" + fakeDnsPort;
            ProxySettings.DnsProxyPortId.Value = proxyPort;
            DnsProxyService.Start(force: true);

            var query = BuildDnsQuery("a.preset.test");
            using var udp = new UdpClient();
            await udp.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Loopback, DnsProxyService.ActivePort));
            var receive = udp.ReceiveAsync();
            var completed = await Task.WhenAny(receive, Task.Delay(5000));
            Assert.That(completed, Is.SameAs(receive), "DNS 查询超时");

            var response = receive.Result.Buffer;
            Assert.That((response[7]), Is.EqualTo(2), "应返回 2 条预置 IP");
            var lastFour = new byte[4];
            Buffer.BlockCopy(response, response.Length - 4, lastFour, 0, 4);
            Assert.That(new IPAddress(lastFour).ToString(), Is.EqualTo("1.2.3.5"));
        }
        finally
        {
            DnsProxyService.Stop();
            ProxyRuleEngine.Apply(ProxyRuleSet.Empty);
            ProxySettings.EnableDoh.Value = originalDoh;
            ProxySettings.EnableDnsPresetIp.Value = originalPreset;
            ProxySettings.DnsFallbackServers.Value = originalFallback;
            ProxySettings.DnsProxyPortId.Value = originalPort;
        }
    }

    [Test]
    public async Task DnsProxy_HuggingFace_Fallback_Ip()
    {
        var originalDoh = ProxySettings.EnableDoh.Value;
        var originalFallback = ProxySettings.DnsFallbackServers.Value;
        var originalPort = ProxySettings.DnsProxyPortId.Value;
        var originalPreset = ProxySettings.EnableDnsPresetIp.Value;
        var originalHf = ProxySettings.EnableHuggingFaceFallback.Value;
        var fakeDnsPort = GetFreeUdpPort();
        var proxyPort = GetFreeUdpPort();

        using var fakeDns = new FakeDnsServer(fakeDnsPort, IPAddress.Parse("9.9.9.9"));
        fakeDns.Start();
        ProxyRuleEngine.Apply(ProxyRuleSet.Empty);

        try
        {
            ProxySettings.EnableDoh.Value = false;
            ProxySettings.EnableDnsPresetIp.Value = true;
            ProxySettings.EnableHuggingFaceFallback.Value = true;
            ProxySettings.DnsFallbackServers.Value = "127.0.0.1:" + fakeDnsPort;
            ProxySettings.DnsProxyPortId.Value = proxyPort;
            DnsProxyService.Start(force: true);

            var query = BuildDnsQuery("huggingface.co");
            using var udp = new UdpClient();
            await udp.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Loopback, DnsProxyService.ActivePort));
            var receive = udp.ReceiveAsync();
            var completed = await Task.WhenAny(receive, Task.Delay(5000));
            Assert.That(completed, Is.SameAs(receive), "DNS 查询超时");

            var response = receive.Result.Buffer;
            Assert.That((response[6] << 8) | response[7], Is.GreaterThan(0));
            var firstIp = new byte[4];
            Buffer.BlockCopy(response, response.Length - 4 - 16 * Math.Max(0, ((response[6] << 8) | response[7]) - 1), firstIp, 0, 4);
            Assert.That(new IPAddress(firstIp).ToString(), Is.EqualTo("3.167.200.113"));
        }
        finally
        {
            DnsProxyService.Stop();
            ProxySettings.EnableDoh.Value = originalDoh;
            ProxySettings.EnableDnsPresetIp.Value = originalPreset;
            ProxySettings.EnableHuggingFaceFallback.Value = originalHf;
            ProxySettings.DnsFallbackServers.Value = originalFallback;
            ProxySettings.DnsProxyPortId.Value = originalPort;
        }
    }

    [Test]
    public async Task DohWire_Query_Real_Network()
    {
        var query = BuildDnsQuery("github.com");
        var response = await DohWireResolver.QueryAsync(query);
        Assert.That(response, Is.Not.Null, "DoH 无响应（当前环境可能无法访问 DoH 服务）");
        Assert.That(response!.Length, Is.GreaterThan(12));
        Assert.That(response[0], Is.EqualTo(query[0]));
        Assert.That(response[1], Is.EqualTo(query[1]));
        Assert.That(response[3] & 0x0F, Is.EqualTo(0), "DNS RCODE 应为 NOERROR");
    }

    [Test]
    public async Task SniSidecar_Uses_PresetIp_When_Requested_Ip_Is_Blackholed()
    {
        var originalFragment = ProxySettings.EnableSniFragment.Value;
        var originalStrategy = ProxySettings.SniFragmentStrategy.Value;
        var originalDomains = ProxySettings.SniFragmentDomains.Value;
        var originalPort = ProxySettings.SniFragmentPortId.Value;
        var originalDoh = ProxySettings.EnableDoh.Value;
        var sidecarPort = GetFreeTcpPort();

        using var server = new LocalTlsServer();
        server.Start();

        var rules = DevSidecarConfigLoader.Parse(@"{
  preSetIpList: {
    ""hf.test"": [""127.0.0.1""],
  },
}");
        ProxyRuleEngine.Apply(rules);

        try
        {
            ProxySettings.EnableSniFragment.Value = true;
            ProxySettings.SniFragmentStrategy.Value = ProxySettings.SniFragmentStrategyTlsRecordSplit;
            ProxySettings.SniFragmentDomains.Value = "hf.test";
            ProxySettings.SniFragmentPortId.Value = sidecarPort;
            ProxySettings.EnableDoh.Value = false;
            SniSidecarService.Start(force: true);
            Assert.That(SniSidecarService.IsRunning, Is.True);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, SniSidecarService.ActivePort);
            var stream = client.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, 0, 3);
            var greeting = new byte[2];
            await ReadExactAsync(stream, greeting);

            // 请求一个不可达 IP，SNI 才是真实域名；sidecar 应在读到 SNI 后改用预置 IP。
            var request = new byte[] { 0x05, 0x01, 0x00, 0x01, 10, 255, 255, 1, (byte)(server.Port >> 8), (byte)(server.Port & 0xFF) };
            await stream.WriteAsync(request, 0, request.Length);
            var reply = new byte[10];
            await ReadExactAsync(stream, reply);
            Assert.That(reply[1], Is.EqualTo(0x00));

            using var ssl = new SslStream(stream, true, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync("hf.test");
            var payload = Encoding.ASCII.GetBytes("hello");
            await ssl.WriteAsync(payload, 0, payload.Length);
            var buffer = new byte[2];
            await ReadExactAsync(ssl, buffer);
            Assert.That(Encoding.ASCII.GetString(buffer), Is.EqualTo("ok"));
        }
        finally
        {
            SniSidecarService.Stop();
            ProxyRuleEngine.Apply(ProxyRuleSet.Empty);
            ProxySettings.EnableSniFragment.Value = originalFragment;
            ProxySettings.SniFragmentStrategy.Value = originalStrategy;
            ProxySettings.SniFragmentDomains.Value = originalDomains;
            ProxySettings.SniFragmentPortId.Value = originalPort;
            ProxySettings.EnableDoh.Value = originalDoh;
        }
    }

    [Test]
    public async Task DnsProxy_Uses_Doh_When_Enabled()
    {
        var originalDoh = ProxySettings.EnableDoh.Value;
        var originalFallback = ProxySettings.DnsFallbackServers.Value;
        var originalPort = ProxySettings.DnsProxyPortId.Value;
        var proxyPort = GetFreeUdpPort();

        try
        {
            ProxySettings.EnableDoh.Value = true;
            ProxySettings.DnsFallbackServers.Value = "127.0.0.1:1"; // 确保不会走回退
            ProxySettings.DnsProxyPortId.Value = proxyPort;
            DnsProxyService.Start(force: true);
            Assert.That(DnsProxyService.IsRunning, Is.True);

            var query = BuildDnsQuery("github.com");
            using var udp = new UdpClient();
            await udp.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Loopback, DnsProxyService.ActivePort));
            var receive = udp.ReceiveAsync();
            var completed = await Task.WhenAny(receive, Task.Delay(8000));
            Assert.That(completed, Is.SameAs(receive), "DoH 查询超时");

            var response = receive.Result.Buffer;
            Assert.That(response.Length, Is.GreaterThan(12));
            Assert.That(response[3] & 0x0F, Is.EqualTo(0), "DNS RCODE 应为 NOERROR");
            var answerCount = (response[6] << 8) | response[7];
            Assert.That(answerCount, Is.GreaterThan(0), "应返回 A 记录");
        }
        finally
        {
            DnsProxyService.Stop();
            ProxySettings.EnableDoh.Value = originalDoh;
            ProxySettings.DnsFallbackServers.Value = originalFallback;
            ProxySettings.DnsProxyPortId.Value = originalPort;
        }
    }

    [Test]
    public async Task DnsProxy_Forwards_To_Fallback_Server()
    {
        var originalDoh = ProxySettings.EnableDoh.Value;
        var originalFallback = ProxySettings.DnsFallbackServers.Value;
        var originalPort = ProxySettings.DnsProxyPortId.Value;
        var fakeDnsPort = GetFreeUdpPort();
        var proxyPort = GetFreeUdpPort();

        using var fakeDns = new FakeDnsServer(fakeDnsPort, IPAddress.Parse("1.2.3.4"));
        fakeDns.Start();

        try
        {
            ProxySettings.EnableDoh.Value = false;
            ProxySettings.DnsFallbackServers.Value = "127.0.0.1:" + fakeDnsPort;
            ProxySettings.DnsProxyPortId.Value = proxyPort;
            DnsProxyService.Start(force: true);
            Assert.That(DnsProxyService.IsRunning, Is.True);

            var query = BuildDnsQuery("dns-proxy-" + Guid.NewGuid().ToString("N") + ".example");
            using var udp = new UdpClient();
            await udp.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Loopback, DnsProxyService.ActivePort));
            var receive = udp.ReceiveAsync();
            var completed = await Task.WhenAny(receive, Task.Delay(5000));
            Assert.That(completed, Is.SameAs(receive), "DNS 代理查询超时");

            var response = receive.Result.Buffer;
            Assert.That(response.Length, Is.GreaterThan(12));
            Assert.That(response[0], Is.EqualTo(query[0]));
            Assert.That(response[1], Is.EqualTo(query[1]));
            Assert.That(response[7], Is.EqualTo(1), "应返回 1 条 A 记录");

            var lastFour = new byte[4];
            Buffer.BlockCopy(response, response.Length - 4, lastFour, 0, 4);
            Assert.That(new IPAddress(lastFour).ToString(), Is.EqualTo("1.2.3.4"));
        }
        finally
        {
            DnsProxyService.Stop();
            ProxySettings.EnableDoh.Value = originalDoh;
            ProxySettings.DnsFallbackServers.Value = originalFallback;
            ProxySettings.DnsProxyPortId.Value = originalPort;
        }
    }

    [Test]
    public async Task SniSidecar_TlsRecordSplit_Handshake_Succeeds()
    {
        var originalFragment = ProxySettings.EnableSniFragment.Value;
        var originalStrategy = ProxySettings.SniFragmentStrategy.Value;
        var originalDomains = ProxySettings.SniFragmentDomains.Value;
        var originalPort = ProxySettings.SniFragmentPortId.Value;
        var originalDoh = ProxySettings.EnableDoh.Value;
        var sidecarPort = GetFreeTcpPort();

        using var server = new LocalTlsServer();
        server.Start();

        try
        {
            ProxySettings.EnableSniFragment.Value = true;
            ProxySettings.SniFragmentStrategy.Value = ProxySettings.SniFragmentStrategyTlsRecordSplit;
            ProxySettings.SniFragmentDomains.Value = "localhost";
            ProxySettings.SniFragmentPortId.Value = sidecarPort;
            ProxySettings.EnableDoh.Value = false;
            SniSidecarService.Start(force: true);
            Assert.That(SniSidecarService.IsRunning, Is.True);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, SniSidecarService.ActivePort);
            var stream = client.GetStream();

            // SOCKS5 只传 IP，模拟 tun2socks；域名在 TLS 的 SNI 里。
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, 0, 3);
            var greeting = new byte[2];
            await ReadExactAsync(stream, greeting);
            Assert.That(greeting[1], Is.EqualTo(0x00));

            var request = new byte[] { 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, (byte)(server.Port >> 8), (byte)(server.Port & 0xFF) };
            await stream.WriteAsync(request, 0, request.Length);
            var reply = new byte[10];
            await ReadExactAsync(stream, reply);
            Assert.That(reply[1], Is.EqualTo(0x00), "SOCKS CONNECT 失败");

            using var ssl = new SslStream(stream, true, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync("localhost");

            var payload = Encoding.ASCII.GetBytes("hello");
            await ssl.WriteAsync(payload, 0, payload.Length);
            var buffer = new byte[2];
            await ReadExactAsync(ssl, buffer);
            Assert.That(Encoding.ASCII.GetString(buffer), Is.EqualTo("ok"));
        }
        finally
        {
            SniSidecarService.Stop();
            ProxySettings.EnableSniFragment.Value = originalFragment;
            ProxySettings.SniFragmentStrategy.Value = originalStrategy;
            ProxySettings.SniFragmentDomains.Value = originalDomains;
            ProxySettings.SniFragmentPortId.Value = originalPort;
            ProxySettings.EnableDoh.Value = originalDoh;
        }
    }

    static async Task ReadExactAsync(System.IO.Stream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer, total, buffer.Length - total);
            if (read <= 0) throw new InvalidOperationException("连接提前关闭");
            total += read;
        }
    }

    static byte[] BuildDnsQuery(string host)
    {
        var labels = host.Split('.');
        var length = 12 + 1;
        foreach (var label in labels) length += 1 + label.Length;
        length += 4;

        var buffer = new byte[length];
        buffer[0] = 0x12; buffer[1] = 0x34;
        buffer[2] = 0x01;
        buffer[5] = 0x01;

        var offset = 12;
        foreach (var label in labels)
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            buffer[offset++] = (byte)bytes.Length;
            bytes.CopyTo(buffer, offset);
            offset += bytes.Length;
        }
        buffer[offset++] = 0;
        buffer[offset++] = 0x00; buffer[offset++] = 0x01;
        buffer[offset++] = 0x00; buffer[offset] = 0x01;
        return buffer;
    }

    static int GetFreeUdpPort()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
    }

    static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    sealed class FakeDnsServer : IDisposable
    {
        readonly int port;
        readonly IPAddress answer;
        readonly UdpClient udp;
        readonly CancellationTokenSource cts = new();

        public FakeDnsServer(int port, IPAddress answer)
        {
            this.port = port;
            this.answer = answer;
            udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        }

        public void Start() => _ = LoopAsync();

        async Task LoopAsync()
        {
            while (!cts.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    result = await udp.ReceiveAsync();
                }
                catch
                {
                    return;
                }

                var query = result.Buffer;
                var questionEnd = FindQuestionEnd(query);
                var response = new byte[questionEnd + 16];
                Buffer.BlockCopy(query, 0, response, 0, questionEnd);
                response[2] = 0x81;
                response[3] = 0x80;
                response[6] = 0x00; response[7] = 0x01;
                var offset = questionEnd;
                response[offset++] = 0xC0;
                response[offset++] = 0x0C;
                response[offset++] = 0x00; response[offset++] = 0x01;
                response[offset++] = 0x00; response[offset++] = 0x01;
                response[offset++] = 0x00; response[offset++] = 0x00;
                response[offset++] = 0x00; response[offset++] = 0x3C;
                response[offset++] = 0x00; response[offset++] = 0x04;
                var ip = answer.GetAddressBytes();
                ip.CopyTo(response, offset);

                await udp.SendAsync(response, response.Length, result.RemoteEndPoint);
            }
        }

        static int FindQuestionEnd(byte[] query)
        {
            var offset = 12;
            while (offset < query.Length && query[offset] != 0)
            {
                offset += query[offset] + 1;
            }
            return offset + 5;
        }

        public void Dispose()
        {
            cts.Cancel();
            udp.Dispose();
        }
    }

    sealed class LocalTlsServer : IDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly X509Certificate2 certificate;
        readonly CancellationTokenSource cts = new();

        public LocalTlsServer()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");
            request.CertificateExtensions.Add(san.Build());
            certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
        }

        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

        public void Start()
        {
            listener.Start();
            _ = AcceptAsync();
        }

        async Task AcceptAsync()
        {
            while (!cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync();
                }
                catch
                {
                    return;
                }

                _ = HandleAsync(client);
            }
        }

        async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                using var ssl = new SslStream(client.GetStream(), false);
                await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12 | SslProtocols.Tls13, false);
                var buffer = new byte[5];
                var read = await ssl.ReadAsync(buffer, 0, buffer.Length);
                if (read > 0)
                {
                    var response = Encoding.ASCII.GetBytes("ok");
                    await ssl.WriteAsync(response, 0, response.Length);
                }
            }
        }

        public void Dispose()
        {
            cts.Cancel();
            listener.Stop();
            certificate.Dispose();
        }
    }
}
