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
}
