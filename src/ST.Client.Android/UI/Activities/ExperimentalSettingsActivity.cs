using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Android.App;
using Android.Content.Res;
using Android.Graphics;
using Android.OS;
using Android.Text;
using Android.Util;
using Android.Views;
using Android.Widget;
using System.Application.ProxyRules;
using System.Application.Services;
using System.Application.Services.Implementation;
using System.Application.Settings;

namespace System.Application.UI.Activities
{
    /// <summary>
    /// 实验性加速设置：DevSidecar 规则组、免证书 SNI 分片/改写、DoH、中继与诊断。
    /// </summary>
    [Activity(
        Theme = ManifestConstants.MainTheme2_NoActionBar,
        LaunchMode = LaunchMode.SingleTask,
        ConfigurationChanges = ManifestConstants.ConfigurationChanges)]
    internal sealed class ExperimentalSettingsActivity : Activity
    {
        LinearLayout? container;
        TextView? statusView;
        readonly List<GroupRow> groupRows = new();
        bool building = true;

        sealed class GroupRow
        {
            public GroupRow(string id, string name, CheckBox box)
            {
                Id = id;
                Name = name;
                Box = box;
            }

            public string Id { get; }
            public string Name { get; }
            public CheckBox Box { get; }
        }

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            var root = new LinearLayout(this) { Orientation = Orientation.Vertical };
            root.SetBackgroundColor(ResColor(Resource.Color.grey_window_background));
            AddHeader(root);

            var scroll = new ScrollView(this)
            {
                LayoutParameters = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MatchParent,
                    0,
                    1f),
            };
            container = new LinearLayout(this) { Orientation = Orientation.Vertical };
            container.SetPadding(Dp(14), 0, Dp(14), Dp(28));
            scroll.AddView(container);
            root.AddView(scroll);
            SetContentView(root);

            BuildUi();
            building = false;
            RefreshStatus();
            RefreshGroupCounts();
        }

        protected override void OnResume()
        {
            base.OnResume();
            RefreshStatus();
        }

        protected override void OnPause()
        {
            SettingsHost.Save();
            base.OnPause();
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
                Text = "实验性加速设置",
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

        void BuildUi()
        {
            BuildStatusSection();
            BuildDevSidecarSection();
            BuildCertificateLessSection();
            BuildRelaySection();
            BuildVpnAndLogSection();
            BuildBottomActions();

            AddParagraph(
                "提示：修改规则组、SNI 分片、免证书模式后，建议先停止加速再重新启动，确保 VPN 出口和本地代理使用新配置。");
        }

        void BuildStatusSection()
        {
            var card = AddSection("运行状态", "这里显示当前进程内的真实状态，不会访问外部服务。");
            statusView = AddInfoText(card, "正在读取…");

            var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row.AddView(CreateButton("刷新状态", () =>
            {
                RefreshStatus();
                RefreshGroupCounts();
            }, false), WeightedButtonParams());
            row.AddView(CreateButton("重置统计", () =>
            {
                SniSidecarStats.Reset();
                RefreshStatus();
                ShowToast("统计已重置");
            }, false), WeightedButtonParams());
            card.AddView(row);
        }

        void BuildDevSidecarSection()
        {
            var card = AddSection(
                "DevSidecar 兼容规则",
                "读取官方 remote_config.json5，只执行代理相关子集：域名/路径匹配、SNI、镜像、反代、预置 IP、请求/响应头替换。不会执行它的 Node 脚本。");

            AddSwitch(card, "启用 DevSidecar 规则", "总开关。关闭后完全使用内置加速项目。", ProxySettings.EnableDevSidecarRules);
            AddSwitch(card, "启动时同步配置", "启动加速时重新下载；关闭则优先使用本地缓存。", ProxySettings.SyncDevSidecarConfigOnStartup);
            AddText(card, "配置地址", "仅支持 HTTPS，修改后点“立即同步”。", ProxySettings.DevSidecarConfigUrl, false, InputTypes.ClassText | InputTypes.TextVariationUri);

            AddSubTitle(card, "规则组");
            AddParagraphTo(card, "未选中的组不会参与匹配，也不会使用该组的预置 IP。至少保留一个组。");

            foreach (var group in ProxyRuleGroups.All)
            {
                var box = new CheckBox(this)
                {
                    Text = group.Name,
                    TextSize = 14,
                };
                box.SetTextColor(ResColor(Resource.Color.text_primary));
                box.Checked = ProxyRuleGroups.ParseEnabled(ProxySettings.DevSidecarRuleGroups.Value)
                    .Contains(group.Id);
                box.CheckedChange += (_, e) =>
                {
                    if (building) return;
                    if (!e.IsChecked && groupRows.Count(x => x.Box.Checked) == 0)
                    {
                        box.Checked = true;
                        ShowToast("至少保留一个规则组");
                        return;
                    }
                    SaveGroups();
                };
                card.AddView(box);
                AddParagraphTo(card, group.Description);
                groupRows.Add(new GroupRow(group.Id, group.Name, box));
            }

            var groupButtons = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            groupButtons.AddView(CreateButton("全选", () =>
            {
                foreach (var row in groupRows) row.Box.Checked = true;
                SaveGroups();
            }, false), WeightedButtonParams());
            groupButtons.AddView(CreateButton("仅默认组", () =>
            {
                var defaults = ProxyRuleGroups.ParseEnabled(ProxyRuleGroups.DefaultEnabled);
                foreach (var row in groupRows) row.Box.Checked = defaults.Contains(row.Id);
                SaveGroups();
            }, false), WeightedButtonParams());
            card.AddView(groupButtons);

            var actions = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            actions.AddView(CreateButton("立即同步并应用", SyncRulesAsync, true), WeightedButtonParams());
            actions.AddView(CreateButton("重新应用本地规则", ApplyRules, false), WeightedButtonParams());
            card.AddView(actions);
        }

        void BuildCertificateLessSection()
        {
            var card = AddSection(
                "免证书模式与 SNI 分片",
                "不安装根证书时使用：本地 SOCKS5 只做 TCP 转发，不终止 TLS。分片把 ClientHello 拆成多段，绕过只检查首包的 DPI；对会重组流的设备无效。");

            AddSwitch(card, "免证书模式", "开启后 VPN 出口切换到本地 SNI sidecar，不再做 MITM、镜像和脚本注入。", ProxySettings.IsCertificateLessMode);
            AddParagraphTo(card, "只有免证书模式或系统未安装根证书时，VPN 才会使用 sidecar；已安装根证书且关闭免证书模式时，流量仍走 Titanium 的 MITM/规则链路，此时 SNI 分片设置不会生效。");

            AddSwitch(card, "启用 SNI 分片", "只对下方列出的域名做分片，其它流量原样转发。", ProxySettings.EnableSniFragment);
            AddChoice(card, "分片策略", "SNI 边界：在域名首字节处拆成三段，推荐。固定大小：按字节数拆分。TLS 记录头：仅拆 record/handshake 头，强度较弱。",
                new[] { "固定大小", "SNI 边界（推荐）", "TLS 记录头" },
                ProxySettings.SniFragmentStrategy.Value,
                value => ProxySettings.SniFragmentStrategy.Value = value);

            AddNumber(card, "固定分片大小（字节）", "仅固定大小策略生效。过小会产生大量 TCP 段并明显变慢。", ProxySettings.SniFragmentChunkSize, 1, 4096);
            AddNumber(card, "分片间隔（毫秒）", "每段之间的延迟。0 表示不等待；10~30ms 通常足够。", ProxySettings.SniFragmentDelayMilliseconds, 0, 1000);
            AddNumber(card, "ClientHello 最大缓冲（字节）", "超过后不再等待剩余字节，直接按已有内容转发。", ProxySettings.SniFragmentMaxBufferBytes, 1024, 65536);
            AddNumber(card, "等待剩余字节超时（毫秒）", "ClientHello 被拆到多个 TCP 包时，等待剩余部分的超时。", ProxySettings.SniFragmentReadTimeoutMilliseconds, 50, 3000);
            AddText(card, "分片生效域名", "分号分隔，支持 * 通配符。留空表示全部域名。", ProxySettings.SniFragmentDomains, false);
            AddSwitch(card, "只对 TLS 连接分片", "建议开启，避免影响普通 HTTP 和自定义协议。", ProxySettings.SniFragmentOnlyTls);

            AddSubTitle(card, "SNI 改写（实验）");
            AddParagraphTo(card, "直接改 ClientHello 里的域名。客户端仍按原域名校验证书，只有源站忽略 SNI 或返回原域名证书时才成立，不能作为通用方案。");
            AddSwitch(card, "启用 SNI 改写", "高风险，仅用于明确知道源站行为的域名。", ProxySettings.EnableSniRewrite);
            AddText(card, "改写目标", "例如 baidu.com 或 none（none 表示删除 SNI 扩展）。", ProxySettings.SniRewriteHost, false);
            AddText(card, "允许改写的域名", "分号分隔，支持 * 通配符。", ProxySettings.SniRewriteDomains, false);

            AddNumber(card, "Sidecar 端口", "本地 SOCKS5 监听端口，仅绑定 127.0.0.1。", ProxySettings.SniFragmentPortId, 1024, 65535);
        }

        void BuildRelaySection()
        {
            var card = AddSection(
                "上游中继与 DNS",
                "中继是免证书场景下最可靠的兜底方式：TLS 端到端，中继看不到 Authorization/Cookie。DoH 只解决 DNS 污染，不解决 IP 黑洞或 SNI 阻断。");

            AddSwitch(card, "启用上游 SOCKS5 中继", "所有 TCP 流量先到中继，再由中继连接目标；支持用户名/密码认证。", ProxySettings.EnableSniUpstreamRelay);
            AddText(card, "中继地址", "IP 或域名。", ProxySettings.SniUpstreamRelayHost, false);
            AddNumber(card, "中继端口", "常见本地代理端口：7890、1080、10808。", ProxySettings.SniUpstreamRelayPort, 1, 65535);
            AddText(card, "中继用户名", "没有认证时留空。", ProxySettings.SniUpstreamRelayUserName, false);
            AddText(card, "中继密码", "没有认证时留空。", ProxySettings.SniUpstreamRelayPassword, true);

            AddDivider(card);
            AddSwitch(card, "启用 DoH", "通过 HTTPS 查询 A 记录，避免 DNS 污染；失败时按下方开关决定是否回退系统 DNS。", ProxySettings.EnableDoh);
            AddText(card, "DoH JSON 接口", "例如 https://dns.alidns.com/resolve 或 https://dns.google/resolve。仅支持 HTTPS。", ProxySettings.DohEndpoint, false, InputTypes.ClassText | InputTypes.TextVariationUri);
            AddSwitch(card, "DoH 失败回退系统 DNS", "关闭后 DoH 失败会直接使用域名连接，可能再次被污染。", ProxySettings.DohFallbackToSystem);
        }

        void BuildVpnAndLogSection()
        {
            var card = AddSection("VPN 与诊断日志", "日志只写本地应用目录，不记录 Authorization/Cookie/请求体。");

            AddSwitch(card, "增强模式仅浏览器走 VPN", "未安装系统证书时，其它应用可能因 MITM 断网；开启后只把常见浏览器加入 VPN。", ProxySettings.EnableBrowserOnlyVpn);
            AddSwitch(card, "写代理诊断日志", "关闭后不再新增日志，已有日志保留。", ProxySettings.EnableProxyDiagnostics);
            AddChoice(card, "日志最低级别", "Info 最详细；Warn 只记录警告和错误；Error 只记录错误。",
                new[] { "Info", "Warn", "Error" },
                ProxySettings.ProxyDiagnosticsMinimumLevel.Value,
                value => ProxySettings.ProxyDiagnosticsMinimumLevel.Value = value);
            AddSwitch(card, "日志保留主机名", "关闭后会把日志里形似域名的文本替换为 ***，便于分享日志。", ProxySettings.ProxyDiagnosticsIncludeHost);
            AddNumber(card, "日志保留天数", "启动时会清理超过天数的 proxy-*.log。", ProxySettings.ProxyDiagnosticsRetentionDays, 1, 365);
            AddNumber(card, "单文件上限（KB）", "超过后写入新的时间戳文件。", ProxySettings.ProxyDiagnosticsMaxFileSizeKB, 64, 1048576);

            var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row.AddView(CreateButton("清理日志", () =>
            {
                ProxyDiagnostics.Clear();
                ShowToast("日志已清理");
            }, false), WeightedButtonParams());
            row.AddView(CreateButton("日志目录", () =>
            {
                Toast.MakeText(this, ProxyDiagnostics.LogDirectory, ToastLength.Long)?.Show();
            }, false), WeightedButtonParams());
            card.AddView(row);
        }

        void BuildBottomActions()
        {
            var title = new TextView(this)
            {
                Text = "操作",
                TextSize = 16,
                Typeface = Typeface.DefaultBold,
            };
            title.SetTextColor(ResColor(Resource.Color.text_primary));
            title.SetPadding(Dp(4), Dp(20), Dp(4), Dp(6));
            container!.AddView(title);

            var apply = CreateButton("保存并重新应用", () =>
            {
                SettingsHost.Save();
                ProxyDiagnostics.Initialize();
                ApplyRules();
                SniSidecarService.Restart();
                RefreshStatus();
                ShowToast("已应用；如修改了免证书模式，请重启加速");
            }, true);
            apply.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(48));
            container.AddView(apply);

            var test = CreateButton("测试 SNI 分片是否有效", ShowTestDialog, false);
            test.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(48));
            container.AddView(test);

            var reset = CreateButton("恢复本页默认值", () =>
            {
                var dialog = new AlertDialog.Builder(this)
                    .SetTitle("恢复默认值")
                    .SetMessage("将重置本页所有实验性选项（规则组、SNI、DoH、中继、日志），不会修改代理端口和二级代理。")
                    .SetPositiveButton("恢复", (_, _) =>
                    {
                        ProxySettings.RestoreExperimentalDefaults();
                        ProxyRuleEngine.Clear();
                        SniSidecarService.Stop();
                        Recreate();
                    })
                    .SetNegativeButton("取消", (_, _) => { })
                    .Create();
                dialog.Show();
            }, false);
            reset.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(48));
            container.AddView(reset);
        }

        async void SyncRulesAsync()
        {
            if (!ProxySettings.EnableDevSidecarRules.Value)
            {
                ShowToast("请先启用 DevSidecar 规则");
                return;
            }

            SettingsHost.Save();
            ShowToast("正在同步配置…");
            try
            {
                await ProxyRuleEngine.ReloadAsync();
                RefreshStatus();
                RefreshGroupCounts();
                ShowToast($"已应用 {ProxyRuleEngine.Current.Rules.Count} 条规则");
            }
            catch (Exception ex)
            {
                ShowToast("同步失败: " + ex.Message);
            }
        }

        void ApplyRules()
        {
            SettingsHost.Save();
            if (ProxySettings.EnableDevSidecarRules.Value)
            {
                if (ProxyRuleEngine.All.Rules.Count > 0)
                {
                    ProxyRuleEngine.Apply(ProxyRuleEngine.All);
                }
                else
                {
                    // 本地还没有缓存时直接同步一次，避免“开关打开了但一条规则都没有”。
                    _ = SyncRulesAsync();
                    return;
                }
            }
            else
            {
                ProxyRuleEngine.Clear();
            }
            RefreshStatus();
            RefreshGroupCounts();
        }

        void SaveGroups()
        {
            var enabled = groupRows.Where(x => x.Box.Checked).Select(x => x.Id).ToArray();
            if (enabled.Length == 0) return;

            ProxySettings.DevSidecarRuleGroups.Value = ProxyRuleGroups.ToStorage(enabled);
            SettingsHost.Save();
            if (ProxyRuleEngine.All.Rules.Count > 0)
            {
                ProxyRuleEngine.Apply(ProxyRuleEngine.All);
            }
            RefreshStatus();
        }

        void RefreshGroupCounts()
        {
            var allCount = ProxyRuleEngine.All.Rules.Count;
            foreach (var row in groupRows)
            {
                var count = ProxyRuleEngine.GetRuleCount(row.Id);
                row.Box.Text = allCount > 0 ? $"{row.Name}（{count} 条）" : row.Name;
            }
        }

        void RefreshStatus()
        {
            if (statusView == null) return;

            try
            {
                var sidecar = SniSidecarService.IsRunning
                    ? $"运行中 127.0.0.1:{SniSidecarService.ActivePort}"
                    : "未运行";
                var cert = IReverseProxyService.Instance.CertificateManager.IsRootCertificateInstalled
                    ? "已安装"
                    : "未安装";
                var sync = ProxyRuleEngine.LastSyncTime.HasValue
                    ? ProxyRuleEngine.LastSyncTime.Value.ToString("yyyy-MM-dd HH:mm:ss")
                    : "未同步";
                var error = string.IsNullOrEmpty(ProxyRuleEngine.LastError)
                    ? string.Empty
                    : $"\n错误: {ProxyRuleEngine.LastError}";

                statusView.Text =
                    $"Sidecar: {sidecar}\n" +
                    $"根证书: {cert}\n" +
                    $"规则组: {ProxySettings.DevSidecarRuleGroups.Value}\n" +
                    $"规则: 启用 {ProxyRuleEngine.Current.Rules.Count} / 共 {ProxyRuleEngine.All.Rules.Count} 条\n" +
                    $"上次同步: {sync}{error}\n" +
                    $"统计: {SniSidecarStats.ToDisplayString()}";
            }
            catch (Exception ex)
            {
                statusView.Text = "读取状态失败: " + ex.Message;
            }
        }

        void ShowTestDialog()
        {
            var input = new EditText(this)
            {
                Text = "github.com",
                Hint = "要测试的域名，例如 github.com 或 i.pximg.net",
            };
            input.SetSingleLine(true);
            input.SetTextColor(ResColor(Resource.Color.text_primary));

            var builder = new AlertDialog.Builder(this)
                .SetTitle("测试 SNI 分片")
                .SetMessage("会分别用直连和本地 sidecar 建立 TLS 握手。测试使用当前设置；需要先启用 SNI 分片才能验证分片策略。")
                .SetView(input)
                .SetPositiveButton("开始测试", (_, _) => _ = RunTestAsync(input.Text))
                .SetNegativeButton("取消", (_, _) => { });
            builder.Show();
        }

        async Task RunTestAsync(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return;

            var progress = new AlertDialog.Builder(this)
                .SetMessage("正在测试，请保持网络连接…")
                .SetCancelable(false)
                .Create();
            progress.Show();

            try
            {
                var result = await SniConnectivityTester.RunAsync(host.Trim());
                progress.Dismiss();
                if (IsFinishing) return;
                ShowTextDialog("SNI 测试结果", result);
                RefreshStatus();
            }
            catch (Exception ex)
            {
                progress.Dismiss();
                ShowToast("测试失败: " + ex.Message);
            }
        }

        void ShowTextDialog(string title, string text)
        {
            var view = new TextView(this)
            {
                Text = text,
                TextSize = 12,
                Typeface = Typeface.Monospace,
            };
            view.SetTextIsSelectable(true);
            view.SetPadding(Dp(16), Dp(8), Dp(16), Dp(8));
            view.SetTextColor(ResColor(Resource.Color.text_primary));

            var scroll = new ScrollView(this);
            scroll.AddView(view);

            new AlertDialog.Builder(this)
                .SetTitle(title)
                .SetView(scroll)
                .SetPositiveButton("关闭", (_, _) => { })
                .Show();
        }

        LinearLayout AddSection(string title, string description)
        {
            var titleView = new TextView(this)
            {
                Text = title,
                TextSize = 16,
                Typeface = Typeface.DefaultBold,
            };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            titleView.SetPadding(Dp(4), Dp(20), Dp(4), Dp(2));
            container!.AddView(titleView);

            var descView = new TextView(this)
            {
                Text = description,
                TextSize = 12,
            };
            descView.SetTextColor(ResColor(Resource.Color.text_secondary));
            descView.SetPadding(Dp(4), 0, Dp(4), Dp(8));
            container.AddView(descView);

            var card = new LinearLayout(this) { Orientation = Orientation.Vertical };
            var background = new GradientDrawable();
            background.SetColor(IsNightMode ? Color.ParseColor("#1E1E1E") : Color.White);
            background.SetCornerRadius(Dp(12));
            background.SetStroke(Dp(1), IsNightMode ? Color.ParseColor("#33FFFFFF") : Color.ParseColor("#1F000000"));
            card.Background = background;
            card.SetPadding(Dp(14), Dp(4), Dp(14), Dp(8));
            var layout = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent);
            layout.BottomMargin = Dp(4);
            container.AddView(card, layout);
            return card;
        }

        void AddSwitch(
            LinearLayout parent,
            string title,
            string description,
            SerializableProperty<bool> property)
        {
            var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row.SetGravity(GravityFlags.CenterVertical);
            row.SetPadding(0, Dp(10), 0, Dp(10));
            row.Clickable = true;
            row.Focusable = true;

            var textLayout = new LinearLayout(this) { Orientation = Orientation.Vertical };
            var titleView = new TextView(this) { Text = title, TextSize = 14 };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            textLayout.AddView(titleView);
            if (!string.IsNullOrEmpty(description))
            {
                var descView = new TextView(this) { Text = description, TextSize = 11 };
                descView.SetTextColor(ResColor(Resource.Color.text_secondary));
                descView.SetPadding(0, Dp(2), Dp(8), 0);
                textLayout.AddView(descView);
            }
            row.AddView(textLayout, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

            var switchView = new Switch(this)
            {
                Checked = property.Value,
                Clickable = false,
                Focusable = false,
            };
            row.AddView(switchView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WrapContent, ViewGroup.LayoutParams.WrapContent));

            switchView.CheckedChange += (_, e) =>
            {
                if (building) return;
                property.Value = e.IsChecked;
                SettingsHost.Save();
            };
            row.Click += (_, _) => switchView.Checked = !switchView.Checked;
            parent.AddView(row);
            AddRowDivider(parent);
        }

        void AddText(
            LinearLayout parent,
            string title,
            string hint,
            SerializableProperty<string> property,
            bool password,
            InputTypes inputType = InputTypes.ClassText)
        {
            var layout = new LinearLayout(this) { Orientation = Orientation.Vertical };
            layout.SetPadding(0, Dp(10), 0, Dp(6));

            var titleView = new TextView(this) { Text = title, TextSize = 13 };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            layout.AddView(titleView);

            var input = new EditText(this)
            {
                Text = property.Value,
                Hint = hint,
                TextSize = 13,
            };
            input.SetSingleLine(true);
            input.SetTextColor(ResColor(Resource.Color.text_primary));
            input.SetHintTextColor(ResColor(Resource.Color.text_secondary));
            input.InputType = password
                ? InputTypes.ClassText | InputTypes.TextVariationPassword
                : inputType;
            input.TextChanged += (_, e) =>
            {
                if (building) return;
                property.Value = e.Text?.ToString() ?? string.Empty;
                SettingsHost.Save();
            };
            layout.AddView(input);
            parent.AddView(layout);
            AddRowDivider(parent);
        }

        void AddNumber(
            LinearLayout parent,
            string title,
            string description,
            SerializableProperty<int> property,
            int min,
            int max)
        {
            var layout = new LinearLayout(this) { Orientation = Orientation.Vertical };
            layout.SetPadding(0, Dp(10), 0, Dp(6));

            var titleView = new TextView(this) { Text = $"{title}（{min}~{max}）", TextSize = 13 };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            layout.AddView(titleView);

            if (!string.IsNullOrEmpty(description))
            {
                var descView = new TextView(this) { Text = description, TextSize = 11 };
                descView.SetTextColor(ResColor(Resource.Color.text_secondary));
                descView.SetPadding(0, Dp(1), 0, Dp(2));
                layout.AddView(descView);
            }

            var input = new EditText(this)
            {
                Text = property.Value.ToString(),
                TextSize = 13,
            };
            input.SetSingleLine(true);
            input.InputType = InputTypes.ClassNumber;
            input.SetTextColor(ResColor(Resource.Color.text_primary));
            input.TextChanged += (_, e) =>
            {
                if (building) return;
                if (!int.TryParse(e.Text?.ToString(), out var value)) return;
                property.Value = Math.Min(max, Math.Max(min, value));
                SettingsHost.Save();
            };
            layout.AddView(input);
            parent.AddView(layout);
            AddRowDivider(parent);
        }

        void AddChoice(
            LinearLayout parent,
            string title,
            string description,
            string[] options,
            int selected,
            Action<int> changed)
        {
            var layout = new LinearLayout(this) { Orientation = Orientation.Vertical };
            layout.SetPadding(0, Dp(10), 0, Dp(6));

            var titleView = new TextView(this) { Text = title, TextSize = 13 };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            layout.AddView(titleView);

            if (!string.IsNullOrEmpty(description))
            {
                var descView = new TextView(this) { Text = description, TextSize = 11 };
                descView.SetTextColor(ResColor(Resource.Color.text_secondary));
                descView.SetPadding(0, Dp(1), 0, Dp(2));
                layout.AddView(descView);
            }

            var spinner = new Spinner(this);
            var adapter = new ArrayAdapter<string>(
                this,
                Android.Resource.Layout.SimpleSpinnerItem,
                options);
            adapter.SetDropDownViewResource(Android.Resource.Layout.SimpleSpinnerDropDownItem);
            spinner.Adapter = adapter;
            spinner.SetSelection(Math.Max(0, Math.Min(options.Length - 1, selected)), false);
            spinner.ItemSelected += (_, e) =>
            {
                if (building) return;
                changed(e.Position);
                SettingsHost.Save();
            };
            layout.AddView(spinner);
            parent.AddView(layout);
            AddRowDivider(parent);
        }

        void AddSubTitle(LinearLayout parent, string text)
        {
            var view = new TextView(this)
            {
                Text = text,
                TextSize = 14,
                Typeface = Typeface.DefaultBold,
            };
            view.SetTextColor(ResColor(Resource.Color.text_primary));
            view.SetPadding(0, Dp(14), 0, Dp(2));
            parent.AddView(view);
        }

        TextView AddInfoText(LinearLayout parent, string text)
        {
            var view = new TextView(this)
            {
                Text = text,
                TextSize = 12,
                Typeface = Typeface.Monospace,
            };
            view.SetTextColor(ResColor(Resource.Color.text_primary));
            view.SetPadding(0, Dp(10), 0, Dp(8));
            parent.AddView(view);
            AddRowDivider(parent);
            return view;
        }

        void AddParagraph(string text)
        {
            var view = new TextView(this) { Text = text, TextSize = 11 };
            view.SetTextColor(ResColor(Resource.Color.text_secondary));
            view.SetPadding(Dp(4), Dp(16), Dp(4), 0);
            container!.AddView(view);
        }

        void AddParagraphTo(LinearLayout parent, string text)
        {
            var view = new TextView(this) { Text = text, TextSize = 11 };
            view.SetTextColor(ResColor(Resource.Color.text_secondary));
            view.SetPadding(0, 0, 0, Dp(4));
            parent.AddView(view);
        }

        void AddDivider(LinearLayout parent)
        {
            var view = new View(this);
            view.SetBackgroundColor(ResColor(Resource.Color.bg_divider));
            var layout = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, Dp(1));
            layout.TopMargin = Dp(8);
            layout.BottomMargin = Dp(8);
            parent.AddView(view, layout);
        }

        void AddRowDivider(LinearLayout parent)
        {
            var view = new View(this);
            view.SetBackgroundColor(ResColor(Resource.Color.bg_divider));
            parent.AddView(view, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(1)));
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
            var layout = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WrapContent, Dp(42));
            layout.RightMargin = Dp(4);
            button.LayoutParameters = layout;
            return button;
        }

        LinearLayout.LayoutParams WeightedButtonParams()
        {
            var layout = new LinearLayout.LayoutParams(0, Dp(42), 1f);
            layout.RightMargin = Dp(4);
            return layout;
        }

        void ShowToast(string message)
            => Toast.MakeText(this, message, ToastLength.Short)?.Show();

        bool IsNightMode
            => (Resources.Configuration.UiMode & UiMode.NightMask) == UiMode.NightYes;

        int ResColor(int resourceId)
        {
            if (Build.VERSION.SdkInt >= BuildVersionCodes.M)
            {
                return Resources.GetColor(resourceId, Theme);
            }
#pragma warning disable CA1422
            return Resources.GetColor(resourceId);
#pragma warning restore CA1422
        }

        int Dp(int value)
            => (int)TypedValue.ApplyDimension(ComplexUnitType.Dip, value, Resources.DisplayMetrics);
    }
}
