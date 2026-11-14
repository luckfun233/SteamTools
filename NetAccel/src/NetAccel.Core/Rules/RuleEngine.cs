using NetAccel.Core.Logging;
using NetAccel.Core.Models;

namespace NetAccel.Core.Rules;

/// <summary>
/// 当前生效的规则集。远程 DevSidecar 规则按组过滤，用户自定义规则始终叠加在最前面。
/// 所有读取都走不可变快照，代理连接线程不会看到半更新的状态。
/// </summary>
public sealed class RuleEngine
{
    readonly AccelSettings settings;
    readonly IAccelLogger log;
    readonly DevSidecarConfigLoader loader;
    readonly CustomRuleStore customStore;

    ProxyRuleSet current = ProxyRuleSet.Empty;
    ProxyRuleSet remote = ProxyRuleSet.Empty;
    ProxyRuleSet custom = ProxyRuleSet.Empty;

    public RuleEngine(AccelSettings settings, IAccelLogger? logger = null,
        DevSidecarConfigLoader? loader = null, CustomRuleStore? customStore = null)
    {
        this.settings = settings;
        log = logger ?? NullLogger.Instance;
        this.loader = loader ?? new DevSidecarConfigLoader();
        this.customStore = customStore ?? new CustomRuleStore();
    }

    public ProxyRuleSet Current => Volatile.Read(ref current);
    public ProxyRuleSet Remote => Volatile.Read(ref remote);
    public ProxyRuleSet CustomSet => Volatile.Read(ref custom);
    public int CustomRuleCount => CustomSet.Rules.Count;
    public DateTimeOffset? LastSyncTime { get; private set; }
    public string? LastError { get; private set; }
    public string? LastCustomError { get; private set; }
    public CustomRuleStore CustomStore => customStore;

    public IReadOnlyList<ProxyRuleGroupInfo> Groups => ProxyRuleGroups.All;

    public int GetRemoteRuleCount(string groupId)
        => Remote.Rules.Count(x => string.Equals(x.Group, groupId, StringComparison.OrdinalIgnoreCase));

    public void Initialize()
    {
        if (settings.EnableRemoteRules)
        {
            var cached = loader.LoadCache();
            if (cached.Rules.Count > 0 || cached.PresetIps.Count > 0)
            {
                ApplyRemote(cached);
                LastSyncTime = File.Exists(loader.CacheFilePath)
                    ? File.GetLastWriteTimeUtc(loader.CacheFilePath)
                    : null;
            }
        }
        ReloadCustom();
    }

    public async Task SyncRemoteAsync(CancellationToken cancellationToken = default)
    {
        if (!settings.EnableRemoteRules)
        {
            ClearRemote();
            return;
        }

        try
        {
            var rules = await loader.LoadAsync(settings.RemoteRuleUrl, cancellationToken).ConfigureAwait(false);
            ApplyRemote(rules);
            if (rules.Rules.Count > 0 || rules.PresetIps.Count > 0)
            {
                LastSyncTime = DateTimeOffset.Now;
                LastError = null;
            }
            else
            {
                LastError = "远程规则为空或下载失败";
            }
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            log.Warn("Rules", "同步远程规则失败: " + ex.Message);
        }
    }

    public void ApplyRemote(ProxyRuleSet rules)
    {
        Volatile.Write(ref remote, rules);
        Rebuild();
    }

    public void ReloadCustom()
    {
        if (!settings.EnableCustomRules)
        {
            Volatile.Write(ref custom, ProxyRuleSet.Empty);
            LastCustomError = null;
            Rebuild();
            return;
        }

        if (customStore.TryLoad(out var rules, out var error))
        {
            Volatile.Write(ref custom, rules);
            LastCustomError = error;
        }
        else
        {
            LastCustomError = error;
            log.Warn("Rules", "加载自定义规则失败: " + error);
        }
        Rebuild();
    }

    public void SetCustom(ProxyRuleSet rules, string? error = null)
    {
        Volatile.Write(ref custom, rules);
        LastCustomError = error;
        Rebuild();
    }

    public void Rebuild()
    {
        var remoteFiltered = ProxyRuleSet.Empty;
        if (settings.EnableRemoteRules && Remote.Rules.Count > 0)
        {
            var groups = ProxyRuleGroups.ParseEnabled(settings.EnabledRuleGroups);
            remoteFiltered = Remote.FilterGroups(groups);
        }

        var customSet = settings.EnableCustomRules ? CustomSet : ProxyRuleSet.Empty;
        var combined = ProxyRuleSet.Combine(customSet, remoteFiltered);
        Volatile.Write(ref current, combined);

        log.Info("Rules",
            $"自定义 {customSet.Rules.Count} 条 + 远程启用 {remoteFiltered.Rules.Count} 条 = {combined.Rules.Count} 条");
    }

    public void ClearRemote()
    {
        Volatile.Write(ref remote, ProxyRuleSet.Empty);
        LastError = null;
        LastSyncTime = null;
        Rebuild();
    }

    public void ClearAll()
    {
        Volatile.Write(ref remote, ProxyRuleSet.Empty);
        Volatile.Write(ref custom, ProxyRuleSet.Empty);
        Volatile.Write(ref current, ProxyRuleSet.Empty);
        LastSyncTime = null;
        LastError = null;
        LastCustomError = null;
    }
}
