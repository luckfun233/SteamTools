using NUnit.Framework;
using System.Application.ProxyRules;
using System.Linq;

namespace System.Application;

[TestFixture]
public class DevSidecarConfigTest
{
    const string SampleConfig = @"{
  server: {
    intercepts: {
      // GitHub
      ""github.com"": {
        ""^/([^/]+){2,}/.*"": {
          sni: ""baidu.com"",
          desc: ""GitHub 页面"",
        },
        "".*"": {
          proxy: ""https://ghp.ci"",
        },
      },
      ""raw.githubusercontent.com"": {
        "".*"": { sni: ""baidu.com"" },
      },
      // Pixiv
      ""pixiv.net"": {
        "".*"": { sni: ""baidu.com"" },
      },
      ""i.pximg.net"": {
        "".*"": {
          requestReplace: {
            headers: {
              referer: ""https://www.pixiv.net/"",
            },
          },
        },
      },
      //DockerHub
      ""docker.io"": {
        "".*"": { sni: ""baidu.com"" },
      },
    },
    preSetIpList: {
      // GitHub
      ""github.com"": [""140.82.112.3"", ""140.82.113.3""],
    },
    dns: {
      providers: {
        ""cf-DoH"": {
          ""server"": ""https://cloudflare-dns.com/dns-query"",
        },
        ""cf-DoT"": {
          ""server"": ""tls://1.1.1.1"",
        },
      },
      mapping: {
        // Google
        ""fonts.googleapis.com"": ""cf-DoH"",
        ""*.example.org"": ""cf-DoT"",
      },
    },
    whiteList: {
      ""localhost"": true,
      ""*.local"": true,
    },
    proxy: {
      excludeIpList: {
        ""*.lan"": true,
      },
    },
  },
  proxy: {
    excludeIpList: {
      ""*.internal"": true,
    },
  },
}";

    [Test]
    public void Parse_Groups_From_Comments()
    {
        var rules = DevSidecarConfigLoader.Parse(SampleConfig);

        Assert.That(rules.Rules.Count, Is.GreaterThan(0));
        Assert.That(rules.Rules.Where(x => x.DomainPattern == "github.com").All(x => x.Group == "GitHub"), Is.True);
        Assert.That(rules.Rules.Where(x => x.DomainPattern == "raw.githubusercontent.com").All(x => x.Group == "GitHub"), Is.True);
        Assert.That(rules.Rules.Where(x => x.DomainPattern.StartsWith("pixiv") || x.DomainPattern == "i.pximg.net").All(x => x.Group == "Pixiv"), Is.True);
        Assert.That(rules.Rules.Where(x => x.DomainPattern == "docker.io").All(x => x.Group == "DockerHub"), Is.True);

        var groups = rules.GetGroups();
        Assert.That(groups.Any(x => x.Name == "GitHub" && x.ServiceCount == 2), Is.True);
        Assert.That(groups.Any(x => x.Name == "Pixiv" && x.ServiceCount == 2), Is.True);
    }

    [Test]
    public void Parse_DnsMapping_WhiteList_And_Excludes()
    {
        var rules = DevSidecarConfigLoader.Parse(SampleConfig);

        Assert.That(rules.PresetIps.ContainsKey("github.com"), Is.True);
        Assert.That(rules.PresetIps["github.com"].Count, Is.EqualTo(2));
        Assert.That(rules.DnsMappings.Any(x => x.DomainPattern == "fonts.googleapis.com"), Is.True);
        Assert.That(rules.GetDohEndpoint("fonts.googleapis.com"), Is.EqualTo("https://cloudflare-dns.com/dns-query"));
        // DoT provider 当前跳过，不会出现在映射里
        Assert.That(rules.DnsMappings.Any(x => x.DomainPattern == "*.example.org"), Is.False);

        Assert.That(rules.ExcludePatterns, Does.Contain("localhost"));
        Assert.That(rules.ExcludePatterns, Does.Contain("*.local"));
        Assert.That(rules.ExcludePatterns, Does.Contain("*.lan"));
        Assert.That(rules.ExcludePatterns, Does.Contain("*.internal"));
    }

    [Test]
    public void FilterDisabled_Groups_And_Services()
    {
        var rules = DevSidecarConfigLoader.Parse(SampleConfig);

        var filtered = rules.FilterDisabled(
            new System.Collections.Generic.HashSet<string>(new[] { "Pixiv" }, StringComparer.OrdinalIgnoreCase),
            new System.Collections.Generic.HashSet<string>(new[] { "docker.io" }, StringComparer.OrdinalIgnoreCase));

        Assert.That(filtered.Rules.Any(x => x.Group == "Pixiv"), Is.False);
        Assert.That(filtered.Rules.Any(x => x.DomainPattern == "docker.io"), Is.False);
        Assert.That(filtered.Rules.Any(x => x.Group == "GitHub"), Is.True);
        Assert.That(filtered.PresetIps.ContainsKey("github.com"), Is.True);
    }

    [Test]
    public void MatchServices_Finds_Wildcards_And_Regex()
    {
        var rules = DevSidecarConfigLoader.Parse(@"{
  intercepts: {
    ""*.example.com"": {
      "".*"": { sni: ""baidu.com"" },
    },
    ""^api\\.test\\.com$"": {
      "".*"": { sni: ""baidu.com"" },
    },
  },
}");

        var matches = rules.MatchServices("cdn.example.com");
        Assert.That(matches, Does.Contain("*.example.com"));

        var regexMatches = rules.MatchServices("api.test.com");
        Assert.That(regexMatches, Does.Contain("^api\\.test\\.com$"));
    }

    [Test]
    public void Regex_Timeout_Does_Not_Throw()
    {
        var rules = DevSidecarConfigLoader.Parse(@"{
  intercepts: {
    ""^(a+)+$"": {
      "".*"": { sni: ""baidu.com"" },
    },
  },
}");

        var host = new string('a', 200) + "!";
        Assert.DoesNotThrow(() => rules.Match(host));
    }

    [Test]
    public void Parse_Real_Remote_Config_When_Available()
    {
        var path = Environment.GetEnvironmentVariable("DEV_SIDECAR_CONFIG");
        if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path))
        {
            Assert.Ignore("未设置 DEV_SIDECAR_CONFIG，跳过真实远程配置解析");
        }

        var rules = DevSidecarConfigLoader.Parse(System.IO.File.ReadAllText(path!));
        Assert.That(rules.Rules.Count, Is.GreaterThan(30));
        Assert.That(rules.PresetIps.Count, Is.GreaterThan(0));

        var groups = rules.GetGroups();
        Assert.That(groups.Any(x => x.Name == "GitHub"), Is.True);
        Assert.That(groups.Any(x => x.Name == "Pixiv"), Is.True);
        Assert.That(groups.Any(x => x.Name == "DockerHub"), Is.True);
        Assert.That(rules.Rules.Any(x => x.DomainPattern == "github.com" && x.Group == "GitHub"), Is.True);
        Assert.That(rules.ExcludePatterns.Count, Is.GreaterThan(0));
        Assert.That(rules.DnsMappings.Count, Is.GreaterThan(0), "应解析出 DevSidecar dns.mapping 的 HTTPS provider");
        Assert.That(rules.GetDohEndpoint("docker.io"), Is.Not.Null.And.StartsWith("https://"));
        // preSetIpList 里不应混入 provider 名称
        foreach (var item in rules.PresetIps)
        {
            foreach (var ip in item.Value)
            {
                Assert.That(System.Net.IPAddress.TryParse(ip, out _), Is.True, $"{item.Key} 的预置 IP 非法: {ip}");
            }
        }
    }
}
