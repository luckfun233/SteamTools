using System;
using System.Application.Settings;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 当前的 DevSidecar 兼容规则集。关闭开关时为空，走内置项目规则。
    /// </summary>
    public static class ProxyRuleEngine
    {
        static ProxyRuleSet current = ProxyRuleSet.Empty;

        public static ProxyRuleSet Current => Volatile.Read(ref current);

        public static async Task ReloadAsync(CancellationToken cancellationToken = default)
        {
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                Volatile.Write(ref current, ProxyRuleSet.Empty);
                Log.Info("ProxyRuleEngine", "DevSidecar 规则同步未启用");
                return;
            }

            var rules = await DevSidecarConfigLoader.LoadAsync(
                ProxySettings.DevSidecarConfigUrl.Value,
                cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref current, rules);
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
                    Volatile.Write(ref current, rules);
                    Log.Info("ProxyRuleEngine", $"已加载本地 DevSidecar 规则 {rules.Rules.Count} 条");
                }
                else
                {
                    Log.Info("ProxyRuleEngine", "没有 DevSidecar 本地缓存");
                }
            }
            catch (Exception ex)
            {
                Log.Warn("ProxyRuleEngine", ex, "读取 DevSidecar 缓存失败");
            }
        }

        public static void Clear() => Volatile.Write(ref current, ProxyRuleSet.Empty);
    }
}
