using System.Application.ProxyRules;
using System.Application.Services;
using System.Application.Settings;
using System.Application.UI.Resx;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using ReactiveUI;

// ReSharper disable once CheckNamespace
namespace System.Application.UI.ViewModels
{
    public class ProxySettingsWindowViewModel : WindowViewModel
    {
        public static string DisplayName => AppResources.CommunityFix_ProxySettings;

        public ProxySettingsWindowViewModel()
        {
            Title = GetTitleByDisplayName(DisplayName);

            var enabled = ProxyRuleGroups.ParseEnabled(ProxySettings.DevSidecarRuleGroups.Value);
            foreach (var info in ProxyRuleGroups.All)
            {
                var item = new ProxyRuleGroupToggle(info, enabled.Contains(info.Id));
                item.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(ProxyRuleGroupToggle.IsEnabled))
                    {
                        SaveRuleGroups();
                    }
                };
                RuleGroups.Add(item);
            }
            RefreshRuleStatus();
        }

        public IEnumerable<EExternalProxyType> ProxyTypes { get; }
            = Enum2.GetAll<EExternalProxyType>();

        public IEnumerable<string> ProxyDNSs { get; } = new[]
        {
            "System Default",
            IDnsAnalysisService.PrimaryDNS_114,
            IDnsAnalysisService.PrimaryDNS_Ali,
            IDnsAnalysisService.PrimaryDNS_Dnspod,
            IDnsAnalysisService.PrimaryDNS_Baidu,
            IDnsAnalysisService.PrimaryDNS_Google,
            IDnsAnalysisService.PrimaryDNS_Cloudflare,
        };

        public IEnumerable<string> SystemProxyIps { get; }
            = new[] { "0.0.0.0", "127.0.0.1" };

        #region 加速规则

        /// <summary>
        /// DevSidecar 远程规则组，可单独开启或关闭。
        /// </summary>
        public ObservableCollection<ProxyRuleGroupToggle> RuleGroups { get; } = new();

        string ruleStatusText = string.Empty;

        public string RuleStatusText
        {
            get => ruleStatusText;
            private set => this.RaiseAndSetIfChanged(ref ruleStatusText, value);
        }

        void SaveRuleGroups()
        {
            ProxySettings.DevSidecarRuleGroups.Value = ProxyRuleGroups.ToStorage(
                RuleGroups.Where(x => x.IsEnabled).Select(x => x.Id));
            ProxyRuleEngine.Rebuild();
            RefreshRuleStatus();
        }

        public void RefreshRuleStatus()
        {
            var enabledGroups = RuleGroups.Count(x => x.IsEnabled);
            var text = $"已勾选 {enabledGroups} 个规则组；远程规则 {ProxyRuleEngine.Remote.Rules.Count} 条，当前生效 {ProxyRuleEngine.Current.Rules.Count} 条";
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                text += "（订阅规则未启用）";
            }
            if (!string.IsNullOrEmpty(ProxyRuleEngine.LastError))
            {
                text += Environment.NewLine + "同步失败: " + ProxyRuleEngine.LastError;
            }
            RuleStatusText = text;
        }

        /// <summary>
        /// 立即同步远程规则，成功后刷新状态文本。
        /// </summary>
        public async Task SyncRulesAsync()
        {
            await ProxyRuleEngine.ReloadAsync();
            RefreshRuleStatus();
        }

        #endregion
    }

    /// <summary>
    /// 规则组的可勾选状态，勾选结果会写回 DevSidecarRuleGroups 设置。
    /// </summary>
    public sealed class ProxyRuleGroupToggle : ReactiveObject
    {
        public ProxyRuleGroupToggle(ProxyRuleGroupInfo info, bool isEnabled)
        {
            Id = info.Id;
            Name = info.Name;
            Description = info.Description;
            this.isEnabled = isEnabled;
        }

        public string Id { get; }

        public string Name { get; }

        public string Description { get; }

        bool isEnabled;

        public bool IsEnabled
        {
            get => isEnabled;
            set => this.RaiseAndSetIfChanged(ref isEnabled, value);
        }
    }
}
