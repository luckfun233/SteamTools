using NUnit.Framework;
using System.Application.ProxyRules;
using System.Text.Json;

namespace System.Application;

[TestFixture]
public class ProxyRulesTest
{
    [Test]
    public void Json5_Normalizes_DevSidecar_Syntax()
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
        using var doc = JsonDocument.Parse(json);

        Assert.That(doc.RootElement.GetProperty("app").GetProperty("id").GetString(), Is.EqualTo("official"));
        Assert.That(doc.RootElement.GetProperty("list").GetArrayLength(), Is.EqualTo(3));
        Assert.That(doc.RootElement.GetProperty("text").GetString(), Is.EqualTo("it's \"ok\""));
        Assert.That(doc.RootElement.GetProperty("url").GetString(), Is.EqualTo("https://example.com/a//b"));
    }

    [Test]
    public void DomainPatternMatcher_Handles_Wildcard_Regex_And_Hybrid()
    {
        Assert.That(DomainPatternMatcher.IsMatch("api.github.com", "*.github.com"), Is.True);
        Assert.That(DomainPatternMatcher.IsMatch("github.com.evil.com", "github.com"), Is.False);
        Assert.That(DomainPatternMatcher.IsMatch("accounts.google.com", "(*account*|scholar).google.com"), Is.True);
        Assert.That(DomainPatternMatcher.IsMatch("scholar.google.com", "(*account*|scholar).google.com"), Is.True);
        Assert.That(DomainPatternMatcher.IsMatch("www.google.com", "^(?!.*(translate)).*google.*$"), Is.True);
        Assert.That(DomainPatternMatcher.IsMatch("2001:db8::1", "[2001:db8::1]"), Is.True);
    }

    [Test]
    public void ProxyRuleSet_Merges_All_Matching_Rules()
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
                RequestHeaders = new System.Collections.Generic.Dictionary<string, string?>
                {
                    ["referer"] = "https://www.pixiv.net/",
                },
            },
        };
        var set = new ProxyRuleSet(rules, Array.Empty<string>(),
            new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IReadOnlyList<string>>
            {
                ["i.pximg.net"] = new[] { "210.140.139.132" },
            });

        var rule = set.Match("i.pximg.net", "/img.jpg");
        Assert.That(rule, Is.Not.Null);
        Assert.That(rule!.Sni, Is.EqualTo("baidu.com"));
        Assert.That(rule.RequestHeaders["referer"], Is.EqualTo("https://www.pixiv.net/"));
        Assert.That(set.GetPresetIps("i.pximg.net"), Has.Count.EqualTo(1));
    }

    [Test]
    public void ProxyRuleSet_Filters_Groups_And_PresetIps()
    {
        var rules = new[]
        {
            new ProxyRule { DomainPattern = "github.com", Group = ProxyRuleGroups.GitHub, Sni = "baidu.com" },
            new ProxyRule { DomainPattern = "*.pixiv.org", Group = ProxyRuleGroups.Pixiv, Sni = "baidu.com" },
        };
        var presets = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IReadOnlyList<string>>
        {
            ["github.com"] = new[] { "140.82.121.4" },
            ["i.pximg.net"] = new[] { "210.140.139.132" },
        };
        var set = new ProxyRuleSet(rules, Array.Empty<string>(), presets);

        var filtered = set.FilterGroups(new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ProxyRuleGroups.GitHub,
        });

        Assert.That(filtered.Match("github.com"), Is.Not.Null);
        Assert.That(filtered.Match("i.pixiv.org"), Is.Null);
        Assert.That(filtered.GetPresetIps("github.com"), Has.Count.EqualTo(1));
        Assert.That(filtered.GetPresetIps("i.pximg.net"), Is.Empty);
    }

    [Test]
    public void CustomRules_Parse_And_Take_Precedence()
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

        Assert.That(
            DevSidecarConfigLoader.TryParse(custom, ProxyRuleGroups.Custom, out var customRules, out var error),
            Is.True,
            error);
        Assert.That(customRules.Rules, Has.Count.EqualTo(1));
        Assert.That(customRules.Rules[0].Group, Is.EqualTo(ProxyRuleGroups.Custom));
        Assert.That(customRules.GetPresetIps("example.com"), Has.Count.EqualTo(1));
        Assert.That(customRules.IsExcluded("printer.local"), Is.True);

        var remote = new ProxyRuleSet(
            new[] { new ProxyRule { DomainPattern = "example.com", Group = ProxyRuleGroups.Other, Sni = "remote" } },
            Array.Empty<string>(),
            new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IReadOnlyList<string>>
            {
                ["example.com"] = new[] { "9.9.9.9" },
            });

        var merged = ProxyRuleSet.Combine(customRules, remote);
        Assert.That(merged.Match("example.com")?.Sni, Is.EqualTo("baidu.com"));
        Assert.That(merged.GetPresetIps("example.com")[0], Is.EqualTo("1.2.3.4"));
        Assert.That(merged.IsExcluded("printer.local"), Is.True);
    }

    [Test]
    public void CustomRules_Serialize_Roundtrip()
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
                    RequestHeaders = new System.Collections.Generic.Dictionary<string, string?>
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
            new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IReadOnlyList<string>>
            {
                ["example.com"] = new[] { "1.2.3.4", "5.6.7.8" },
            });

        var text = CustomProxyRules.Serialize(rules);
        Assert.That(
            DevSidecarConfigLoader.TryParse(text, ProxyRuleGroups.Custom, out var reparsed, out var error),
            Is.True,
            error);
        Assert.That(reparsed.Rules, Has.Count.EqualTo(2));
        Assert.That(reparsed.Match("example.com", "/repo/a")?.Redirect, Is.EqualTo("https://ghp.ci/https://example.com"));
        Assert.That(reparsed.Match("example.com", "/repo/a")?.RequestHeaders["cookie"], Is.Null);
        Assert.That(reparsed.Match("ads.example.com")?.Block, Is.True);
        Assert.That(reparsed.GetPresetIps("example.com"), Has.Count.EqualTo(2));
        Assert.That(reparsed.IsExcluded("printer.local"), Is.True);
    }
}
