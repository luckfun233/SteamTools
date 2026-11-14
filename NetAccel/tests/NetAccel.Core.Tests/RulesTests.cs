using System.Text;
using NetAccel.Core.Rules;
using Xunit;

namespace NetAccel.Core.Tests;

public class Json5Tests
{
    [Fact]
    public void Normalizes_DevSidecar_Syntax()
    {
        const string json5 = @"{
  // comment
  /* block comment */
  app: { id: 'official', version: 202611031515, },
  list: [1, 2, 3,],
  text: 'it\'s ""ok""',
  url: ""https://example.com/a//b"",
}";

        var json = Json5.ToJson(json5);
        using var doc = System.Text.Json.JsonDocument.Parse(json);

        Assert.Equal("official", doc.RootElement.GetProperty("app").GetProperty("id").GetString());
        Assert.Equal(3, doc.RootElement.GetProperty("list").GetArrayLength());
        Assert.Equal("it's \"ok\"", doc.RootElement.GetProperty("text").GetString());
        Assert.Equal("https://example.com/a//b", doc.RootElement.GetProperty("url").GetString());
    }

    [Fact]
    public void Keeps_Urls_With_Comments_Inside_Strings()
    {
        const string json5 = "{ url: 'https://a.b/c//d', n: 1 }";
        using var doc = System.Text.Json.JsonDocument.Parse(Json5.ToJson(json5));
        Assert.Equal("https://a.b/c//d", doc.RootElement.GetProperty("url").GetString());
        Assert.Equal(1, doc.RootElement.GetProperty("n").GetInt32());
    }
}

public class DomainPatternTests
{
    [Theory]
    [InlineData("api.github.com", "*.github.com", true)]
    [InlineData("github.com.evil.com", "github.com", false)]
    [InlineData("github.com", "github.com", true)]
    [InlineData("accounts.google.com", "(*account*|scholar).google.com", true)]
    [InlineData("scholar.google.com", "(*account*|scholar).google.com", true)]
    [InlineData("www.google.com", "^(?!.*(translate)).*google.*$", true)]
    [InlineData("translate.google.com", "^(?!.*(translate)).*google.*$", false)]
    [InlineData("2001:db8::1", "[2001:db8::1]", true)]
    [InlineData("a.huggingface.co", "*.huggingface.co", true)]
    public void Matches_Wildcard_Regex_And_Hybrid(string host, string pattern, bool expected)
        => Assert.Equal(expected, DomainPatternMatcher.IsMatch(host, pattern));

    [Fact]
    public void Bad_Regex_Does_Not_Throw()
        => Assert.False(DomainPatternMatcher.IsMatch("example.com", "(["));
}

public class RuleSetTests
{
    [Fact]
    public void Merges_All_Matching_Rules()
    {
        var rules = new[]
        {
            new ProxyRule
            {
                DomainPattern = "*.pximg.net",
                Group = ProxyRuleGroups.Pixiv,
                Sni = "baidu.com",
            },
            new ProxyRule
            {
                DomainPattern = "i.pximg.net",
                Group = ProxyRuleGroups.Pixiv,
                RequestHeaders = new Dictionary<string, string?>
                {
                    ["referer"] = "https://www.pixiv.net/",
                },
            },
        };
        var set = new ProxyRuleSet(rules, Array.Empty<string>(),
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["i.pximg.net"] = new[] { "210.140.139.132" },
            });

        var rule = set.Match("i.pximg.net", "/img.jpg");
        Assert.NotNull(rule);
        Assert.Equal("baidu.com", rule!.Sni);
        Assert.Equal("https://www.pixiv.net/", rule.RequestHeaders["referer"]);
        Assert.Single(set.GetPresetIps("i.pximg.net"));
    }

    [Fact]
    public void Filters_Groups_And_PresetIps()
    {
        var rules = new[]
        {
            new ProxyRule { DomainPattern = "github.com", Group = ProxyRuleGroups.GitHub, Sni = "baidu.com" },
            new ProxyRule { DomainPattern = "*.pixiv.org", Group = ProxyRuleGroups.Pixiv, Sni = "baidu.com" },
        };
        var presets = new Dictionary<string, IReadOnlyList<string>>
        {
            ["github.com"] = new[] { "140.82.121.4" },
            ["i.pximg.net"] = new[] { "210.140.139.132" },
        };
        var set = new ProxyRuleSet(rules, Array.Empty<string>(), presets);

        var filtered = set.FilterGroups(new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ProxyRuleGroups.GitHub,
        });

        Assert.NotNull(filtered.Match("github.com"));
        Assert.Null(filtered.Match("i.pixiv.org"));
        Assert.Single(filtered.GetPresetIps("github.com"));
        Assert.Empty(filtered.GetPresetIps("i.pximg.net"));
    }

    [Fact]
    public void Custom_Rules_Take_Precedence()
    {
        const string custom = @"{
  intercepts: {
    ""example.com"": {
      "".*"": { sni: ""baidu.com"", desc: ""custom"" },
    },
  },
  preSetIpList: { ""example.com"": [""1.2.3.4""] },
  excludeIpList: { ""*.local"": true },
}";

        Assert.True(DevSidecarConfigLoader.TryParse(custom, ProxyRuleGroups.Custom, out var customRules, out var error), error);
        Assert.Single(customRules.Rules);
        Assert.Equal(ProxyRuleGroups.Custom, customRules.Rules[0].Group);
        Assert.Single(customRules.GetPresetIps("example.com"));
        Assert.True(customRules.IsExcluded("printer.local"));

        var remote = new ProxyRuleSet(
            new[] { new ProxyRule { DomainPattern = "example.com", Group = ProxyRuleGroups.Other, Sni = "remote" } },
            Array.Empty<string>(),
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["example.com"] = new[] { "9.9.9.9" },
            });

        var merged = ProxyRuleSet.Combine(customRules, remote);
        Assert.Equal("baidu.com", merged.Match("example.com")?.Sni);
        Assert.Equal("1.2.3.4", merged.GetPresetIps("example.com")[0]);
        Assert.True(merged.IsExcluded("printer.local"));
    }

    [Fact]
    public void Custom_Rules_Serialize_Roundtrip()
    {
        var rules = new ProxyRuleSet(
            new[]
            {
                new ProxyRule
                {
                    DomainPattern = "example.com",
                    PathPattern = "^/repo/.*",
                    Group = ProxyRuleGroups.Custom,
                    Redirect = "https://ghp.ci/https://example.com",
                    RequestHeaders = new Dictionary<string, string?>
                    {
                        ["referer"] = "https://example.com/",
                        ["cookie"] = null,
                    },
                    Description = "样例",
                },
                new ProxyRule
                {
                    DomainPattern = "ads.example.com",
                    Group = ProxyRuleGroups.Custom,
                    Block = true,
                },
            },
            new[] { "*.local" },
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["example.com"] = new[] { "1.2.3.4", "5.6.7.8" },
            });

        var text = CustomRuleStore.Serialize(rules);
        Assert.True(DevSidecarConfigLoader.TryParse(text, ProxyRuleGroups.Custom, out var reparsed, out var error), error);
        Assert.Equal(2, reparsed.Rules.Count);
        Assert.Equal("https://ghp.ci/https://example.com", reparsed.Match("example.com", "/repo/a")?.Redirect);
        Assert.Null(reparsed.Match("example.com", "/repo/a")?.RequestHeaders["cookie"]);
        Assert.True(reparsed.Match("ads.example.com")?.Block);
        Assert.Equal(2, reparsed.GetPresetIps("example.com").Count);
        Assert.True(reparsed.IsExcluded("printer.local"));
    }

    [Fact]
    public void Loader_Handles_Server_Wrapper_And_Abort()
    {
        const string json = @"{
  server: {
    preSetIpList: { ""github.com"": [""140.82.121.4"", ""140.82.121.5""] },
    intercepts: {
      ""github.com"": {
        "".*"": { desc: ""all"" },
        ""^/login"": { abort: true },
      },
    },
  },
  proxy: { excludeIpList: { ""*.lan"": true, ""*.keep"": false } },
}";

        Assert.True(DevSidecarConfigLoader.TryParse(json, null, out var set, out var error), error);
        Assert.Single(set.Rules);
        Assert.True(set.Rules[0].Block);
        Assert.Equal("github.com", set.Rules[0].DomainPattern);
        Assert.Single(set.ExcludePatterns);
        Assert.Equal(2, set.GetPresetIps("github.com").Count);
    }
}
