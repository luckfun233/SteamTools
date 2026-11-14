using System.Net;
using NetAccel.Core.Models;
using Xunit;

namespace NetAccel.Core.Tests;

public class SettingsTests
{
    [Fact]
    public void Normalize_Clamps_Invalid_Values()
    {
        var settings = new AccelSettings
        {
            Socks5Port = 0,
            HttpPort = 99999,
            SplitPieces = 99,
            FragmentChunkSize = 0,
            FallbackProbeMs = -1,
            FirstPayloadTimeoutMs = 0,
            DiagnosticsRetentionDays = 0,
            DiagnosticsMaxFileSizeKB = 1,
        };

        Assert.True(settings.Normalize());
        Assert.InRange(settings.Socks5Port, 1, 65535);
        Assert.InRange(settings.HttpPort, 1, 65535);
        Assert.NotEqual(settings.Socks5Port, settings.HttpPort);
        Assert.InRange(settings.SplitPieces, 2, 8);
        Assert.InRange(settings.FragmentChunkSize, 1, 4096);
        Assert.InRange(settings.FallbackProbeMs, 100, 10000);
        Assert.InRange(settings.FirstPayloadTimeoutMs, 50, 5000);
        Assert.InRange(settings.DiagnosticsRetentionDays, 1, 365);
        Assert.InRange(settings.DiagnosticsMaxFileSizeKB, 64, 262144);
    }

    [Fact]
    public void Normalize_Rejects_NonHttps_Doh()
    {
        var settings = new AccelSettings { DohEndpoint = "http://dns.example.com/resolve" };
        settings.Normalize();
        Assert.StartsWith("https://", settings.DohEndpoint);
    }

    [Fact]
    public void Normalize_Fixes_Invalid_Listen_Address()
    {
        var settings = new AccelSettings { ListenAddress = "not-an-ip" };
        settings.Normalize();
        Assert.Equal("127.0.0.1", settings.ListenAddress);

        settings.ListenAddress = "*";
        settings.Normalize();
        Assert.Equal("0.0.0.0", settings.ListenAddress);

        settings.ListenAddress = "::1";
        settings.Normalize();
        Assert.Equal("::1", settings.ListenAddress);
    }

    [Fact]
    public void Settings_Roundtrip_Through_Store()
    {
        var dir = Path.Combine(Path.GetTempPath(), "netaccel-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "settings.json");

        var store = new SettingsStore(file);
        var settings = new AccelSettings
        {
            Socks5Port = 18868,
            HttpPort = 18869,
            FragmentStrategy = Core.Tls.TlsFragmentStrategy.TlsRecordSplit,
            EnabledRuleGroups = "github;huggingface",
            SniRewriteHost = "example.org",
        };

        Assert.True(store.Save(settings));
        var loaded = store.Load();

        Assert.Equal(18868, loaded.Socks5Port);
        Assert.Equal(18869, loaded.HttpPort);
        Assert.Equal(Core.Tls.TlsFragmentStrategy.TlsRecordSplit, loaded.FragmentStrategy);
        Assert.Equal("github;huggingface", loaded.EnabledRuleGroups);
        Assert.Equal("example.org", loaded.SniRewriteHost);

        Directory.Delete(dir, recursive: true);
    }

    [Fact]
    public void Store_Recovers_From_Corrupt_File()
    {
        var dir = Path.Combine(Path.GetTempPath(), "netaccel-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "settings.json");
        File.WriteAllText(file, "{ this is not json");

        var store = new SettingsStore(file);
        var loaded = store.Load();

        Assert.Equal(8868, loaded.Socks5Port);
        Directory.Delete(dir, recursive: true);
    }

    [Fact]
    public void Parses_Doh_Json_And_Ttl()
    {
        const string json = """
        {
          "Status": 0,
          "Answer": [
            { "name": "github.com.", "type": 1, "TTL": 60, "data": "140.82.121.4" },
            { "name": "github.com.", "type": 5, "TTL": 300, "data": "github.com.cdn.cloudflare.net." },
            { "name": "github.com.", "type": 1, "TTL": 120, "data": "140.82.121.3" }
          ]
        }
        """;

        var (addresses, ttl) = Core.Net.DohResolver.ParseJsonResponse(json);
        Assert.Equal(2, addresses.Count);
        Assert.Contains(IPAddress.Parse("140.82.121.4"), addresses);
        Assert.Equal(TimeSpan.FromSeconds(60), ttl);
    }

    [Fact]
    public void Doh_Parser_Handles_Empty_Answers()
    {
        var (addresses, ttl) = Core.Net.DohResolver.ParseJsonResponse("""{"Status":3}""");
        Assert.Empty(addresses);
        Assert.Equal(TimeSpan.FromSeconds(30), ttl);
    }

    [Fact]
    public void Doh_Enumerates_Https_Endpoints_Only()
    {
        var settings = new AccelSettings
        {
            DohEndpoint = "https://dns.alidns.com/resolve",
            DohFallbackEndpoints = "http://dns.example.com/resolve; https://dns.google/resolve;https://dns.alidns.com/resolve",
        };

        using var resolver = new Core.Net.DohResolver(settings);
        var endpoints = resolver.EnumerateEndpoints();

        Assert.Equal(2, endpoints.Count);
        Assert.Contains("https://dns.alidns.com/resolve", endpoints);
        Assert.Contains("https://dns.google/resolve", endpoints);
    }

    [Fact]
    public void Doh_Wire_Query_Has_Valid_Header()
    {
        var query = Core.Net.DohResolver.BuildWireQuery("github.com", 1);

        Assert.True(query.Length > 12);
        Assert.Equal(0x01, query[2]); // RD
        Assert.Equal(0x00, query[4]);
        Assert.Equal(0x01, query[5]); // QDCOUNT = 1
        Assert.Equal(0x01, query[^1]); // QCLASS = IN
        Assert.Equal(0x00, query[^2]); // QCLASS 高字节
        Assert.Equal(0x01, query[^3]); // QTYPE = A
    }

    [Fact]
    public void Doh_Wire_Response_Parses_A_Record()
    {
        // 手写一个最小响应：1 个问题 + 1 个 A 记录 140.82.121.4，TTL 60。
        var response = new byte[]
        {
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x06, (byte)'g', (byte)'i', (byte)'t', (byte)'h', (byte)'u', (byte)'b',
            0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xC0, 0x0C, // 指向问题域名
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C, // TTL 60
            0x00, 0x04,
            140, 82, 121, 4,
        };

        var (addresses, ttl) = Core.Net.DohResolver.ParseWireResponse(response);
        Assert.Single(addresses);
        Assert.Equal(IPAddress.Parse("140.82.121.4"), addresses[0]);
        Assert.Equal(TimeSpan.FromSeconds(60), ttl);
    }

    [Fact]
    public void Fragment_Fallback_Cache_Remembers_Strategy()
    {
        var cache = new Core.Stats.FragmentFallbackCache();
        Assert.False(cache.TryGetPreferredStrategy("github.com", out _));

        cache.RememberStrategy("github.com", Core.Tls.TlsFragmentStrategy.TlsRecordSplit);
        Assert.True(cache.TryGetPreferredStrategy("github.com", out var strategy));
        Assert.Equal(Core.Tls.TlsFragmentStrategy.TlsRecordSplit, strategy);

        cache.RememberStrategy("example.com", null);
        Assert.True(cache.TryGetPreferredStrategy("example.com", out var noFragment));
        Assert.Null(noFragment);
    }
}
