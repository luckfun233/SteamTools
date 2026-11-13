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
    /// 当前的规则集。远程 DevSidecar 规则会按规则组过滤，用户自定义规则始终叠加在最前面，
    /// 两者合并后参与匹配，而不是二选一。
    /// </summary>
    public static class ProxyRuleEngine
    {
        static ProxyRuleSet current = ProxyRuleSet.Empty;
        static ProxyRuleSet remote = ProxyRuleSet.Empty;
        static ProxyRuleSet custom = ProxyRuleSet.Empty;

        /// <summary>
        /// 远程规则 + 自定义规则合并后、实际参与匹配的规则集。
        /// </summary>
        public static ProxyRuleSet Current => Volatile.Read(ref current);

        /// <summary>
        /// 未过滤的远程规则集，仅用于设置页展示各组数量。
        /// </summary>
        public static ProxyRuleSet Remote => Volatile.Read(ref remote);

        /// <summary>
        /// 用户自定义规则集。
        /// </summary>
        public static ProxyRuleSet Custom => Volatile.Read(ref custom);

        public static int CustomRuleCount => Custom.Rules.Count;

        public static DateTimeOffset? LastSyncTime { get; private set; }

        public static string? LastError { get; private set; }

        public static string? LastCustomError { get; private set; }

        public static IReadOnlyList<ProxyRuleGroupInfo> Groups => ProxyRuleGroups.All;

        public static int GetRuleCount(string groupId)
            => Remote.Rules.Count(x => string.Equals(x.Group, groupId, StringComparison.OrdinalIgnoreCase));

        public static int GetEnabledRuleCount()
            => Current.Rules.Count;

        public static async Task ReloadAsync(CancellationToken cancellationToken = default)
        {
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                ClearRemote();
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
                ClearRemote();
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

        /// <summary>
        /// 应用远程规则集（会与现有自定义规则合并）。
        /// </summary>
        public static void Apply(ProxyRuleSet rules)
        {
            Volatile.Write(ref remote, rules);
            LastError = rules.Rules.Count == 0 ? "配置解析结果为空" : null;
            Rebuild();
        }

        /// <summary>
        /// 从本地文件重新加载自定义规则。
        /// </summary>
        public static void ReloadCustom()
        {
            if (!ProxySettings.EnableCustomRules.Value)
            {
                Volatile.Write(ref custom, ProxyRuleSet.Empty);
                LastCustomError = null;
                Rebuild();
                return;
            }

            if (CustomProxyRules.TryLoad(out var rules, out var error))
            {
                Volatile.Write(ref custom, rules);
                LastCustomError = error;
                if (rules.Rules.Count > 0)
                {
                    Log.Info("ProxyRuleEngine", $"已加载自定义规则 {rules.Rules.Count} 条");
                }
            }
            else
            {
                LastCustomError = error;
                Log.Warn("ProxyRuleEngine", $"加载自定义规则失败: {error}");
            }
            Rebuild();
        }

        /// <summary>
        /// 直接设置自定义规则集（保存后调用）。
        /// </summary>
        public static void SetCustom(ProxyRuleSet rules, string? error = null)
        {
            Volatile.Write(ref custom, rules);
            LastCustomError = error;
            Rebuild();
        }

        public static void Rebuild()
        {
            var remoteFiltered = ProxyRuleSet.Empty;
            if (ProxySettings.EnableDevSidecarRules.Value && Remote.Rules.Count > 0)
            {
                var groups = ProxyRuleGroups.ParseEnabled(ProxySettings.DevSidecarRuleGroups.Value);
                remoteFiltered = Remote.FilterGroups(groups);
            }

            var customSet = ProxySettings.EnableCustomRules.Value ? Custom : ProxyRuleSet.Empty;

            // 自定义规则优先匹配，远程规则作为补充。
            var combined = ProxyRuleSet.Combine(customSet, remoteFiltered);
            Volatile.Write(ref current, combined);

            ProxyDiagnostics.Info("Rules",
                $"自定义 {customSet.Rules.Count} 条 + 远程启用 {remoteFiltered.Rules.Count} 条 = {combined.Rules.Count} 条");
        }

        static void ClearRemote()
        {
            Volatile.Write(ref remote, ProxyRuleSet.Empty);
            LastError = null;
            Rebuild();
        }

        /// <summary>
        /// 清空远程规则，保留自定义规则。
        /// </summary>
        public static void Clear()
        {
            Volatile.Write(ref remote, ProxyRuleSet.Empty);
            LastSyncTime = null;
            LastError = null;
            Rebuild();
        }

        /// <summary>
        /// 清空全部规则，包括自定义规则。
        /// </summary>
        public static void ClearAll()
        {
            Volatile.Write(ref remote, ProxyRuleSet.Empty);
            Volatile.Write(ref custom, ProxyRuleSet.Empty);
            Volatile.Write(ref current, ProxyRuleSet.Empty);
            LastSyncTime = null;
            LastError = null;
            LastCustomError = null;
        }
    }
}
