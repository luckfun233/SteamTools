using System;
using System.Application.Services.Implementation;
using System.Application.Settings;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 当前的 DevSidecar 兼容规则集。关闭开关时为空，走内置项目规则。
    /// 规则会按设置里选中的规则组过滤，未选中的组不会参与匹配。
    /// </summary>
    public static class ProxyRuleEngine
    {
        static ProxyRuleSet current = ProxyRuleSet.Empty;
        static ProxyRuleSet all = ProxyRuleSet.Empty;

        /// <summary>
        /// 已按规则组过滤、实际参与匹配的规则集。
        /// </summary>
        public static ProxyRuleSet Current => Volatile.Read(ref current);

        /// <summary>
        /// 未过滤的完整规则集，仅用于设置页展示各组数量。
        /// </summary>
        public static ProxyRuleSet All => Volatile.Read(ref all);

        public static DateTimeOffset? LastSyncTime { get; private set; }

        public static string? LastError { get; private set; }

        public static IReadOnlyList<ProxyRuleGroupInfo> Groups => ProxyRuleGroups.All;

        public static int GetRuleCount(string groupId)
            => All.Rules.Count(x => string.Equals(x.Group, groupId, StringComparison.OrdinalIgnoreCase));

        public static int GetEnabledRuleCount()
            => Current.Rules.Count;

        public static async Task ReloadAsync(CancellationToken cancellationToken = default)
        {
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                Clear();
                Log.Info("ProxyRuleEngine", "DevSidecar 规则同步未启用");
                return;
            }

            var rules = await DevSidecarConfigLoader.LoadAsync(
                ProxySettings.DevSidecarConfigUrl.Value,
                cancellationToken).ConfigureAwait(false);
            Apply(rules);
            LastSyncTime = DateTimeOffset.Now;
        }

        public static void LoadFromCache()
        {
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                Clear();
                return;
            }

            try
            {
                var path = DevSidecarConfigLoader.GetCacheFilePath();
                if (File.Exists(path))
                {
                    var rules = DevSidecarConfigLoader.Parse(File.ReadAllText(path));
                    Apply(rules);
                    LastSyncTime = DateTimeOffset.Now;
                    Log.Info("ProxyRuleEngine", $"已加载本地 DevSidecar 规则 {rules.Rules.Count} 条");
                }
                else
                {
                    Log.Info("ProxyRuleEngine", "没有 DevSidecar 本地缓存");
                }
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                Log.Warn("ProxyRuleEngine", ex, "读取 DevSidecar 缓存失败");
            }
        }

        public static void Apply(ProxyRuleSet rules)
        {
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                // 保留 All 以便设置页显示各组数量；实际匹配集合清空。
                Volatile.Write(ref current, ProxyRuleSet.Empty);
                return;
            }

            var groups = ProxyRuleGroups.ParseEnabled(ProxySettings.DevSidecarRuleGroups.Value);
            var filtered = rules.FilterGroups(groups);

            Volatile.Write(ref all, rules);
            Volatile.Write(ref current, filtered);

            LastError = rules.Rules.Count == 0 ? "配置解析结果为空" : null;

            Log.Info("ProxyRuleEngine",
                $"规则已应用: 全部 {rules.Rules.Count} 条, 启用 {filtered.Rules.Count} 条, 组 {string.Join(",", groups)}");
            ProxyDiagnostics.Info("Rules",
                $"全部 {rules.Rules.Count} 条 / 启用 {filtered.Rules.Count} 条 / 组 {string.Join(",", groups)}");
        }

        public static void Clear()
        {
            Volatile.Write(ref current, ProxyRuleSet.Empty);
            Volatile.Write(ref all, ProxyRuleSet.Empty);
            LastSyncTime = null;
            LastError = null;
        }
    }
}
