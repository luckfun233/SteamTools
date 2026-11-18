using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Android.App;
using Android.Content.PM;
using Android.Content.Res;
using Android.Graphics;
using Android.Graphics.Drawables;
using Android.OS;
using Android.Text;
using Android.Util;
using Android.Views;
using Android.Widget;
using Color = Android.Graphics.Color;
using Orientation = Android.Widget.Orientation;
using System.Application.ProxyRules;
using System.Application.Services;
using System.Application.Settings;

namespace System.Application.UI.Activities
{
    /// <summary>
    /// DevSidecar 服务分组：组开关、单个服务开关、搜索（包含/正则/匹配域名）。
    /// 分组名来自远程配置里的 // 注释，与 DevSidecar 2.3.x 的服务分组保持一致。
    /// </summary>
    [Activity(
        Theme = ManifestConstants.MainTheme2_NoActionBar,
        LaunchMode = LaunchMode.SingleTask,
        ConfigurationChanges = ManifestConstants.ConfigurationChanges)]
    internal sealed class RuleGroupsActivity : Activity
    {
        LinearLayout? container;
        LinearLayout? listContainer;
        EditText? searchInput;
        Spinner? modeSpinner;
        TextView? summaryView;
        TextView? searchStatusView;
        int searchMode; // 0=包含 1=正则 2=匹配域名
        bool building = true;

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            var root = new LinearLayout(this) { Orientation = Orientation.Vertical };
            root.SetBackgroundColor(ResColor(Resource.Color.grey_window_background));
            AddHeader(root);

            var searchBar = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            searchBar.SetGravity(GravityFlags.CenterVertical);
            searchBar.SetPadding(Dp(12), Dp(6), Dp(12), Dp(6));

            modeSpinner = new Spinner(this);
            var modeAdapter = new ArrayAdapter<string>(
                this,
                Android.Resource.Layout.SimpleSpinnerItem,
                new[] { "包含匹配", "正则匹配", "匹配域名" });
            modeAdapter.SetDropDownViewResource(Android.Resource.Layout.SimpleSpinnerDropDownItem);
            modeSpinner.Adapter = modeAdapter;
            modeSpinner.ItemSelected += (_, e) =>
            {
                searchMode = e.Position;
                if (searchInput == null) return;
                searchInput.Hint = searchMode switch
                {
                    1 => "输入正则，例如 \\.google\\.com$",
                    2 => "输入完整域名，例如 www.google.com",
                    _ => "搜索服务 / 分组，例如 github",
                };
                RefreshList();
            };
            searchBar.AddView(modeSpinner, new LinearLayout.LayoutParams(Dp(108), Dp(42)));

            searchInput = new EditText(this) { TextSize = 13 };
            searchInput.SetSingleLine(true);
            searchInput.SetTextColor(ResColor(Resource.Color.text_primary));
            searchInput.SetHintTextColor(ResColor(Resource.Color.text_secondary));
            searchInput.Hint = "搜索服务 / 分组，例如 github";
            searchInput.TextChanged += (_, _) =>
            {
                if (building) return;
                RefreshList();
            };
            searchBar.AddView(searchInput, new LinearLayout.LayoutParams(0, Dp(42), 1f));

            var sync = CreateButton("同步", SyncAsync, true);
            searchBar.AddView(sync, new LinearLayout.LayoutParams(Dp(64), Dp(40)));
            root.AddView(searchBar);

            var quickBar = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            quickBar.SetPadding(Dp(12), 0, Dp(12), Dp(4));
            quickBar.AddView(CreateButton("全部开启", EnableAll, false), new LinearLayout.LayoutParams(0, Dp(40), 1f));
            quickBar.AddView(CreateButton("刷新", RefreshList, false), new LinearLayout.LayoutParams(0, Dp(40), 1f));
            root.AddView(quickBar);

            var statusLayout = new LinearLayout(this) { Orientation = Orientation.Vertical };
            statusLayout.SetPadding(Dp(14), 0, Dp(14), Dp(4));
            summaryView = new TextView(this) { TextSize = 12 };
            summaryView.SetTextColor(ResColor(Resource.Color.text_secondary));
            statusLayout.AddView(summaryView);
            searchStatusView = new TextView(this) { TextSize = 12 };
            searchStatusView.SetTextColor(ResColor(Resource.Color.text_link));
            searchStatusView.SetPadding(0, Dp(2), 0, Dp(2));
            statusLayout.AddView(searchStatusView);
            root.AddView(statusLayout);

            var scroll = new ScrollView(this)
            {
                LayoutParameters = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MatchParent, 0, 1f),
            };
            container = new LinearLayout(this) { Orientation = Orientation.Vertical };
            container.SetPadding(Dp(14), 0, Dp(14), Dp(28));
            scroll.AddView(container);
            root.AddView(scroll);

            listContainer = new LinearLayout(this) { Orientation = Orientation.Vertical };
            container.AddView(listContainer);

            SetContentView(root);
            building = false;
            RefreshList();
        }

        void AddHeader(LinearLayout root)
        {
            var header = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            header.SetGravity(GravityFlags.CenterVertical);
            header.SetPadding(Dp(14), Dp(12), Dp(14), Dp(12));
            header.SetBackgroundColor(ResColor(Resource.Color.grey_window_background));

            var back = new TextView(this)
            {
                Text = "‹ 返回",
                TextSize = 15,
                Gravity = GravityFlags.CenterVertical,
            };
            back.SetTextColor(ResColor(Resource.Color.text_link));
            back.Click += (_, _) => Finish();
            header.AddView(back, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WrapContent, Dp(40)));

            var title = new TextView(this)
            {
                Text = "规则组 / 服务",
                TextSize = 19,
                Typeface = Typeface.DefaultBold,
                Gravity = GravityFlags.Center,
            };
            title.SetTextColor(ResColor(Resource.Color.text_primary));
            header.AddView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

            var done = new TextView(this)
            {
                Text = "完成",
                TextSize = 15,
                Gravity = GravityFlags.CenterVertical,
            };
            done.SetTextColor(ResColor(Resource.Color.text_link));
            done.Click += (_, _) => Finish();
            header.AddView(done, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WrapContent, Dp(40)));

            root.AddView(header);
        }

        async void SyncAsync()
        {
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                ShowToast("请先在实验性设置里启用 DevSidecar 规则");
                return;
            }

            ShowToast("正在同步远程配置…");
            try
            {
                await ProxyRuleEngine.ReloadAsync();
                RefreshList();
                ShowToast($"已同步：{ProxyRuleEngine.Remote.Rules.Count} 条规则，" +
                          $"{ProxyRuleEngine.Remote.PresetIps.Count} 组预置 IP");
            }
            catch (Exception ex)
            {
                ShowToast("同步失败: " + ex.Message);
            }
        }

        void EnableAll()
        {
            ProxySettings.DevSidecarDisabledGroups.Value = string.Empty;
            ProxySettings.DevSidecarDisabledServices.Value = string.Empty;
            SettingsHost.Save();
            ProxyRuleEngine.Rebuild();
            RefreshList();
            ShowToast("已开启全部规则组和服务");
        }

        void RefreshList()
        {
            if (listContainer == null || building) return;

            building = true;
            listContainer.RemoveAllViews();

            var disabledGroups = ProxyRuleGroups.ParseList(ProxySettings.DevSidecarDisabledGroups.Value);
            var disabledServices = ProxyRuleGroups.ParseList(ProxySettings.DevSidecarDisabledServices.Value);
            var groups = ProxyRuleEngine.Remote.GetGroups();
            var keyword = searchInput?.Text?.Trim() ?? string.Empty;

            HashSet<string>? hostnameMatches = null;
            if (searchMode == 2 && keyword.Length > 0)
            {
                hostnameMatches = new HashSet<string>(
                    ProxyRuleEngine.Remote.MatchServices(keyword),
                    StringComparer.OrdinalIgnoreCase);
            }

            Regex? regex = null;
            string? regexError = null;
            if (searchMode == 1 && keyword.Length > 0)
            {
                try
                {
                    regex = new Regex(keyword, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                        TimeSpan.FromMilliseconds(100));
                }
                catch (Exception ex)
                {
                    regexError = "正则表达式无效: " + ex.Message;
                }
            }

            var totalServices = groups.Sum(x => x.ServiceCount);
            var enabledServices = groups.Sum(g => g.Services.Count(s =>
                !disabledGroups.Contains(g.Id) && !disabledServices.Contains(s)));

            if (summaryView != null)
            {
                summaryView.Text = $"共 {groups.Count} 个分组、{totalServices} 个服务，已开启 {enabledServices} 个。" +
                                   "分组名读取自 remote_config.json5 的 // 注释。";
            }
            if (searchStatusView != null)
            {
                if (regexError != null)
                {
                    searchStatusView.Text = regexError;
                }
                else if (searchMode == 2 && keyword.Length > 0)
                {
                    searchStatusView.Text = hostnameMatches!.Count > 0
                        ? $"找到 {hostnameMatches.Count} 个会作用于「{keyword}」的配置"
                        : $"没有配置会作用于「{keyword}」";
                }
                else
                {
                    searchStatusView.Text = string.Empty;
                }
            }

            var shownGroups = 0;
            foreach (var group in groups)
            {
                var groupEnabled = !disabledGroups.Contains(group.Id);
                var services = group.Services.Where(service =>
                {
                    if (hostnameMatches != null) return hostnameMatches.Contains(service);
                    if (keyword.Length == 0) return true;
                    if (regex != null)
                    {
                        try
                        {
                            return regex.IsMatch(service) || regex.IsMatch(group.Name);
                        }
                        catch (RegexMatchTimeoutException)
                        {
                            return false;
                        }
                    }
                    return service.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                           group.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase);
                }).ToList();

                if (services.Count == 0) continue;
                shownGroups++;

                var card = AddCard();
                var header = new LinearLayout(this) { Orientation = Orientation.Horizontal };
                header.SetGravity(GravityFlags.CenterVertical);
                header.SetPadding(0, Dp(8), 0, Dp(6));

                var title = new TextView(this)
                {
                    Text = $"{group.Name}  {services.Count}/{group.ServiceCount}",
                    TextSize = 15,
                    Typeface = Typeface.DefaultBold,
                };
                title.SetTextColor(ResColor(Resource.Color.text_primary));
                header.AddView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

                var allOn = CreateSmallButton("全开", () => SetGroupEnabled(group.Id, true));
                var allOff = CreateSmallButton("全关", () => SetGroupEnabled(group.Id, false));
                header.AddView(allOn);
                header.AddView(allOff);

                var groupSwitch = new Switch(this)
                {
                    Checked = groupEnabled,
                    Clickable = false,
                    Focusable = false,
                };
                groupSwitch.CheckedChange += (_, e) =>
                {
                    if (building) return;
                    SetGroupEnabled(group.Id, e.IsChecked);
                };
                header.AddView(groupSwitch);
                card.AddView(header);

                foreach (var service in services)
                {
                    var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
                    row.SetGravity(GravityFlags.CenterVertical);
                    row.SetPadding(0, Dp(7), 0, Dp(7));

                    var text = new LinearLayout(this) { Orientation = Orientation.Vertical };
                    var name = new TextView(this) { Text = service, TextSize = 13 };
                    name.SetTextColor(ResColor(Resource.Color.text_primary));
                    text.AddView(name);

                    var serviceInfo = ProxyRuleEngine.Remote.Services.FirstOrDefault(x =>
                        string.Equals(x.DomainPattern, service, StringComparison.OrdinalIgnoreCase));
                    var detailParts = new List<string> { group.Name };
                    var ruleCount = CountRules(group.Id, service);
                    if (ruleCount > 0) detailParts.Add($"{ruleCount} 条规则");
                    if (serviceInfo?.PresetIpCount > 0) detailParts.Add($"{serviceInfo.PresetIpCount} 个预置 IP");
                    if (!string.IsNullOrEmpty(serviceInfo?.DnsProvider)) detailParts.Add($"DNS {serviceInfo.DnsProvider}");
                    if (serviceInfo?.InWhiteList == true) detailParts.Add("白名单");
                    if (serviceInfo?.InEch == true) detailParts.Add("ECH");
                    if (serviceInfo?.InNat64 == true) detailParts.Add("NAT64");

                    var detail = new TextView(this)
                    {
                        Text = string.Join(" · ", detailParts),
                        TextSize = 11,
                    };
                    detail.SetTextColor(ResColor(Resource.Color.text_secondary));
                    text.AddView(detail);

                    var serviceSwitch = new Switch(this)
                    {
                        Checked = groupEnabled && !disabledServices.Contains(service),
                        Clickable = false,
                        Focusable = false,
                    };
                    serviceSwitch.CheckedChange += (_, e) =>
                    {
                        if (building) return;
                        SetServiceEnabled(group.Id, service, e.IsChecked);
                    };

                    row.Click += (_, _) => serviceSwitch.Checked = !serviceSwitch.Checked;
                    row.AddView(text, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));
                    row.AddView(serviceSwitch);
                    card.AddView(row);

                    var divider = new View(this);
                    divider.SetBackgroundColor(ResColor(Resource.Color.bg_divider));
                    card.AddView(divider, new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MatchParent, Dp(1)));
                }

                var spacer = new Space(this);
                container!.AddView(spacer, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MatchParent, Dp(10)));
            }

            if (shownGroups == 0)
            {
                var empty = new TextView(this)
                {
                    Text = ProxyRuleEngine.Remote.Rules.Count == 0
                        ? "还没有远程规则。点击右上角“同步”下载 DevSidecar 配置。"
                        : "没有匹配的服务。",
                    TextSize = 13,
                };
                empty.SetTextColor(ResColor(Resource.Color.text_secondary));
                empty.SetPadding(Dp(8), Dp(24), Dp(8), Dp(24));
                listContainer.AddView(empty);
            }

            building = false;
        }

        int CountRules(string group, string service)
            => ProxyRuleEngine.Remote.Rules.Count(x =>
                string.Equals(x.DomainPattern, service, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Group, group, StringComparison.OrdinalIgnoreCase));

        void SetGroupEnabled(string group, bool enabled)
        {
            var disabled = ProxyRuleGroups.ParseList(ProxySettings.DevSidecarDisabledGroups.Value);
            if (enabled) disabled.Remove(group);
            else disabled.Add(group);
            ProxySettings.DevSidecarDisabledGroups.Value = ProxyRuleGroups.ToStorage(disabled);
            SettingsHost.Save();
            ProxyRuleEngine.Rebuild();
            RefreshList();
        }

        void SetServiceEnabled(string group, string service, bool enabled)
        {
            var disabled = ProxyRuleGroups.ParseList(ProxySettings.DevSidecarDisabledServices.Value);
            if (enabled) disabled.Remove(service);
            else disabled.Add(service);
            ProxySettings.DevSidecarDisabledServices.Value = ProxyRuleGroups.ToStorage(disabled);

            // 单个服务重新开启时，如果所在组被整体关闭，同时把组打开。
            if (enabled)
            {
                var disabledGroups = ProxyRuleGroups.ParseList(ProxySettings.DevSidecarDisabledGroups.Value);
                if (disabledGroups.Remove(group))
                {
                    ProxySettings.DevSidecarDisabledGroups.Value = ProxyRuleGroups.ToStorage(disabledGroups);
                }
            }

            SettingsHost.Save();
            ProxyRuleEngine.Rebuild();
            RefreshList();
        }

        LinearLayout AddCard()
        {
            var card = new LinearLayout(this) { Orientation = Orientation.Vertical };
            var background = new GradientDrawable();
            background.SetColor(IsNightMode ? Color.ParseColor("#1E1E1E") : Color.White);
            background.SetCornerRadius(Dp(12));
            background.SetStroke(Dp(1), IsNightMode
                ? Color.ParseColor("#33FFFFFF")
                : Color.ParseColor("#1F000000"));
            card.Background = background;
            card.SetPadding(Dp(14), Dp(2), Dp(14), Dp(8));
            var layout = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent);
            layout.BottomMargin = Dp(10);
            listContainer!.AddView(card, layout);
            return card;
        }

        Button CreateSmallButton(string text, Action action)
        {
            var button = new Button(this) { Text = text };
            button.SetAllCaps(false);
            button.TextSize = 11;
            button.SetMinWidth(0);
            button.SetMinimumWidth(0);
            button.SetPadding(Dp(8), 0, Dp(8), 0);
            button.Click += (_, _) => action();
            button.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WrapContent, Dp(34));
            return button;
        }

        Button CreateButton(string text, Action action, bool primary)
        {
            var button = new Button(this) { Text = text };
            button.SetAllCaps(false);
            button.TextSize = 13;
            if (primary)
            {
                button.SetTextColor(Color.White);
                var background = new GradientDrawable();
                background.SetColor(Color.ParseColor("#2F6FED"));
                background.SetCornerRadius(Dp(8));
                button.Background = background;
            }
            button.Click += (_, _) => action();
            return button;
        }

        void ShowToast(string message)
            => Android.Widget.Toast.MakeText(this, new Java.Lang.String(message), Android.Widget.ToastLength.Short)?.Show();

        bool IsNightMode
            => (Resources.Configuration.UiMode & UiMode.NightMask) == UiMode.NightYes;

        Color ResColor(int resourceId)
        {
            int value;
            if (Build.VERSION.SdkInt >= BuildVersionCodes.M)
            {
                value = Resources.GetColor(resourceId, Theme);
            }
            else
            {
#pragma warning disable CA1422
                value = Resources.GetColor(resourceId);
#pragma warning restore CA1422
            }
            return new Color(value);
        }

        int Dp(int value)
            => (int)TypedValue.ApplyDimension(ComplexUnitType.Dip, value, Resources.DisplayMetrics);
    }
}
