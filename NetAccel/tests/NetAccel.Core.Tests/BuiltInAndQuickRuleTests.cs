using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Rules;
using Xunit;

namespace NetAccel.Core.Tests;

public class BuiltInAndQuickRuleTests
{
    [Fact]
    public void BuiltIn_PresetIps_Are_Filtered_By_Group()
    {
        var githubOnly = BuiltInRules.CreateFiltered(new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ProxyRuleGroups.GitHub,
        });

        Assert.Contains("github.com", githubOnly.PresetIps.Keys);
        Assert.DoesNotContain("i.pximg.net", githubOnly.PresetIps.Keys);

        var none = BuiltInRules.CreateFiltered(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        Assert.Empty(none.PresetIps);
    }

    [Fact]
    public void RuleEngine_Adds_BuiltIn_PresetIps()
    {
        var settings = new AccelSettings
        {
            EnableRemoteRules = false,
            EnableCustomRules = false,
            EnableBuiltInRules = true,
            EnabledRuleGroups = ProxyRuleGroups.GitHub,
        };

        var engine = new RuleEngine(settings, NullLogger.Instance);
        engine.Rebuild();

        Assert.NotEmpty(engine.Current.GetPresetIps("github.com"));
        Assert.Empty(engine.Current.GetPresetIps("i.pximg.net"));

        settings.EnableBuiltInRules = false;
        engine.Rebuild();
        Assert.Empty(engine.Current.GetPresetIps("github.com"));
    }

    [Fact]
    public void QuickAdd_Sni_Roundtrips()
    {
        Assert.True(CustomRuleEditor.TryApply(
            ProxyRuleSet.Empty, QuickRuleAction.Sni, "example.com", "baidu.com", out var rules, out var error), error);

        Assert.Equal("baidu.com", rules.Match("example.com")?.Sni);

        var text = CustomRuleStore.Serialize(rules);
        Assert.True(DevSidecarConfigLoader.TryParse(text, ProxyRuleGroups.Custom, out var reparsed, out error), error);
        Assert.Equal("baidu.com", reparsed.Match("example.com")?.Sni);
    }

    [Fact]
    public void QuickAdd_RemoveSni_Uses_None_Semantics()
    {
        Assert.True(CustomRuleEditor.TryApply(
            ProxyRuleSet.Empty, QuickRuleAction.RemoveSni, "example.com", null, out var rules, out var error), error);

        Assert.True(rules.Match("example.com")?.RemoveSni);
    }

    [Fact]
    public void QuickAdd_Block_And_Exclude()
    {
        Assert.True(CustomRuleEditor.TryApply(
            ProxyRuleSet.Empty, QuickRuleAction.Block, "ads.example.com", null, out var rules, out var error), error);
        Assert.True(rules.Match("ads.example.com")?.Block);

        Assert.True(CustomRuleEditor.TryApply(
            rules, QuickRuleAction.Exclude, "*.local", null, out var withExclude, out error), error);
        Assert.True(withExclude.IsExcluded("printer.local"));
    }

    [Fact]
    public void QuickAdd_PresetIp_Validates_Addresses()
    {
        Assert.False(CustomRuleEditor.TryApply(
            ProxyRuleSet.Empty, QuickRuleAction.PresetIp, "example.com", "not-an-ip", out _, out var error));
        Assert.NotNull(error);

        Assert.True(CustomRuleEditor.TryApply(
            ProxyRuleSet.Empty, QuickRuleAction.PresetIp, "example.com", "1.2.3.4, 5.6.7.8", out var rules, out error),
            error);
        Assert.Equal(2, rules.GetPresetIps("example.com").Count);
    }

    [Fact]
    public void QuickAdd_Replaces_Same_Domain()
    {
        Assert.True(CustomRuleEditor.TryApply(
            ProxyRuleSet.Empty, QuickRuleAction.Sni, "example.com", "a.com", out var first, out _));
        Assert.True(CustomRuleEditor.TryApply(
            first, QuickRuleAction.Sni, "example.com", "b.com", out var second, out _));

        Assert.Single(second.Rules);
        Assert.Equal("b.com", second.Match("example.com")?.Sni);
    }

    [Fact]
    public void QuickAdd_Rejects_Bad_Domain()
    {
        Assert.False(CustomRuleEditor.TryApply(
            ProxyRuleSet.Empty, QuickRuleAction.Block, "bad domain", null, out _, out var error));
        Assert.NotNull(error);
    }

    [Fact]
    public async Task Http_Remote_Url_Is_Rejected_Without_Network()
    {
        var cachePath = Path.Combine(Path.GetTempPath(), "netaccel-tests", Guid.NewGuid().ToString("N"),
            "remote_config.json5");
        var loader = new DevSidecarConfigLoader(cachePath);

        var rules = await loader.LoadAsync("http://example.com/config.json5");

        Assert.Empty(rules.Rules);
        Assert.False(File.Exists(cachePath));
    }
}
