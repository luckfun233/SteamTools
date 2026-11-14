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
}
