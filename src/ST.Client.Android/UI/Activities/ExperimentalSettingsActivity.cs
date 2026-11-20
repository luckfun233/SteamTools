using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Content.Res;
using Android.Graphics;
using Android.Graphics.Drawables;
using Android.OS;
using Android.Text;
using Android.Util;
using Android.Views;
using Android.Widget;
using ClipboardManager = Android.Content.ClipboardManager;
using Color = Android.Graphics.Color;
using Orientation = Android.Widget.Orientation;
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
        bool building = true;
        const int ExportLogRequestCode = 4301;
        string? pendingLogExport;

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
        }

        protected override void OnResume()
        {
            base.OnResume();
            RefreshStatus();
        }

        protected override void OnPause()
        {
            SettingsHost.Save();
            ProxyRuleEngine.Rebuild();
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
            BuildCertificateSection();
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
            }, false), WeightedButtonParams());
            row.AddView(CreateButton("重置统计", () =>
            {
                SniSidecarStats.Reset();
                DnsProxyServer.ResetStats();
                RefreshStatus();
                ShowToast("统计已重置");
            }, false), WeightedButtonParams());
            card.AddView(row);

            var labButton = CreateButton("打开加速实验室（一键测试 + 导出日志）", () =>
            {
                StartActivity(new Intent(this, typeof(AcceleratorLabActivity)));
            }, true);
            labButton.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(44));
            card.AddView(labButton);
        }

        void BuildDevSidecarSection()
        {
            var card = AddSection(
                "DevSidecar 规则",
                "规则和分组来自 DevSidecar 的 remote_config.json5。主界面只需要管理分组；下面的高级项一般不用改。");

            AddSwitch(card, "启用 DevSidecar 远程规则", "总开关。关闭后规则组和自定义规则都不生效。", ProxySettings.EnableDevSidecarRules);

            var groupButton = CreateButton("打开规则组 / 服务分组（搜索、开关、全部开启）", () =>
            {
                StartActivity(new Intent(this, typeof(RuleGroupsActivity)));
            }, true);
            groupButton.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(44));
            card.AddView(groupButton);

            var customButton = CreateButton("管理自定义规则", () =>
            {
                StartActivity(new Intent(this, typeof(CustomRulesActivity)));
            }, false);
            customButton.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(42));
            card.AddView(customButton);

            var advanced = AddExpander(card, "高级规则设置");
            AddSwitch(advanced, "启动时同步配置", "启动加速时重新下载；关闭则优先使用本地缓存。", ProxySettings.SyncDevSidecarConfigOnStartup);
            AddNumber(advanced, "后台同步间隔（小时）", "0 表示只在启动时同步。", ProxySettings.DevSidecarAutoSyncHours, 0, 168);
            AddText(advanced, "配置地址", "仅支持 HTTPS。", ProxySettings.DevSidecarConfigUrl, false, InputTypes.ClassText | InputTypes.TextVariationUri);
            AddSwitch(advanced, "启用自定义规则", "与远程规则合并，优先匹配。", ProxySettings.EnableCustomRules);
            AddText(advanced, "已关闭的分组", "分号分隔；一般通过规则组页面操作。", ProxySettings.DevSidecarDisabledGroups, false);
            AddText(advanced, "已关闭的服务", "分号分隔的域名/通配符；一般通过规则组页面操作。", ProxySettings.DevSidecarDisabledServices, false);

            var actions = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            actions.AddView(CreateButton("立即同步并应用", SyncRulesAsync, true), WeightedButtonParams());
            actions.AddView(CreateButton("重新应用本地规则", ApplyRules, false), WeightedButtonParams());
            advanced.AddView(actions);
        }

        void BuildCertificateLessSection()
        {
            var card = AddSection(
                "免证书模式与 SNI 分片",
                "不安装根证书时使用：本地 SOCKS5 只做 TCP 转发，不终止 TLS。默认已经开启；只有遇到问题时才需要改下面的参数。");

            AddSwitch(card, "免证书模式", "开启后 VPN 出口切换到本地 SNI sidecar，不做 MITM/证书安装。", ProxySettings.IsCertificateLessMode);
            AddSwitch(card, "启用 SNI 分片", "对下方域名拆分 ClientHello，绕过 SNI 阻断。", ProxySettings.EnableSniFragment);
            AddChoice(card, "分片策略", "推荐 TLS record 拆分；TLS record 随机拆分更难被指纹。若仍被重置，可试 Tiny record 脉冲或 ClientHello 填充。SNI 边界/多段只拆 TCP 段，对能重组 TCP 的 DPI 无效。",
                new[] { "固定大小", "SNI 边界", "TLS 记录头", "SNI 多段", "TLS record 拆分（推荐）", "随机分片", "TLS record 随机拆分", "Tiny record 脉冲", "ClientHello 填充" },
                ProxySettings.SniFragmentStrategy.Value,
                value => ProxySettings.SniFragmentStrategy.Value = value);
            AddText(card, "分片生效域名", "分号分隔，支持 * 通配符。默认包含 GitHub/Hugging Face/Pixiv。", ProxySettings.SniFragmentDomains, false);
            AddSwitch(card, "启用自动回退", "分片失败时自动换 IP/不分片重试一次。", ProxySettings.EnableSniFragmentFallback);

            var advanced = AddExpander(card, "高级分片参数（一般不用改）");
            AddNumber(advanced, "SNI 多段数", "仅 SNI 多段策略生效。", ProxySettings.SniSplitPieces, 2, 8);
            AddNumber(advanced, "固定分片大小（字节）", "固定大小和随机分片策略使用。", ProxySettings.SniFragmentChunkSize, 1, 4096);
            AddNumber(advanced, "分片间隔（毫秒）", "每段之间的延迟，10~30ms 通常足够。", ProxySettings.SniFragmentDelayMilliseconds, 0, 1000);
            AddNumber(advanced, "随机抖动（毫秒）", "在固定间隔上增加随机等待。", ProxySettings.SniFragmentJitterMilliseconds, 0, 500);
            AddNumber(advanced, "ClientHello 填充字节", "仅“ClientHello 填充”策略生效，默认 4096；上限受单 record 16384 字节限制。", ProxySettings.SniPaddingBytes, 0, 16384);
            AddNumber(advanced, "ClientHello 最大缓冲（字节）", "新版浏览器 ClientHello 可能接近 16KB。", ProxySettings.SniFragmentMaxBufferBytes, 1024, 65536);
            AddNumber(advanced, "首字节探测超时（毫秒）", "分片后等待上游响应的最长时间。", ProxySettings.SniFragmentFallbackProbeMilliseconds, 100, 5000);
            AddNumber(advanced, "跳过分片缓存（分钟）", "失败后对该域名暂停分片的时间。", ProxySettings.SniFragmentFallbackCacheMinutes, 1, 1440);
            AddNumber(advanced, "Sidecar 端口", "本地 SOCKS5 监听端口，仅绑定 127.0.0.1。", ProxySettings.SniFragmentPortId, 1024, 65535);

            var rewrite = AddExpander(advanced, "SNI 改写（高风险，仅特殊站点）");
            AddParagraphTo(rewrite, "客户端仍按原域名校验证书，只有源站忽略 SNI 或返回原域名证书时才成立，不能作为通用方案。");
            AddSwitch(rewrite, "启用 SNI 改写", "仅用于明确知道源站行为的域名。", ProxySettings.EnableSniRewrite);
            AddText(rewrite, "改写目标", "例如 baidu.com 或 none（删除 SNI 扩展）。", ProxySettings.SniRewriteHost, false);
            AddText(rewrite, "允许改写的域名", "分号分隔，支持 * 通配符。", ProxySettings.SniRewriteDomains, false);
        }

        void BuildCertificateSection()
        {
            var card = AddSection(
                "证书模式（MITM）",
                "安装根证书后可以做 SNI 伪装/镜像/请求头改写，是 DevSidecar 访问 Hugging Face 的方式。Android 必须手动把证书装到“用户 CA”里。");

            AddInfoText(card,
                "限制：Chrome/Firefox 一般信任用户 CA，但 Android 7+ 的普通应用默认不信任用户 CA。\n" +
                "因此证书模式主要影响浏览器；其它应用仍建议保持免证书模式。\n" +
                "未安装证书时，VPN 会自动退回免证书 sidecar，不会断网。\n\n" +
                "Android 13 的系统 CA 位于只读 /system 分区，Shizuku 只有 shell 权限，无法写入系统 CA。\n" +
                "如果已用 Shizuku/ADB 把本应用设为“设备所有者”，可以静默安装用户 CA（Chrome 信任）。");

            var owner = AndroidCertificateInstaller.IsDeviceOwner(this);
            AddInfoText(card, $"设备所有者: {(owner ? "是，可静默安装用户 CA" : "否")}");

            var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row.AddView(CreateButton("安装根证书（打开引导）", InstallRootCertificateAsync, true), WeightedButtonParams());
            row.AddView(CreateButton("系统安全设置", () =>
            {
                GoToPlatformPages.SystemSettingsSecurity(this);
            }, false), WeightedButtonParams());
            card.AddView(row);

            var row2 = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row2.AddView(CreateButton(owner ? "静默安装用户 CA" : "复制 Shizuku 命令", () =>
            {
                if (!AndroidCertificateInstaller.IsDeviceOwner(this))
                {
                    CopyText(AndroidCertificateInstaller.ShizukuCommand);
                    ShowToast("已复制。请在 Shizuku 终端执行，然后回到本页");
                    return;
                }

                var manager = IReverseProxyService.Instance.CertificateManager;
                var cer = manager.GetCerFilePathGeneratedWhenNoFileExists();
                if (cer == null)
                {
                    ShowToast("证书生成失败");
                    return;
                }

                ShowToast(AndroidCertificateInstaller.InstallUserCa(this, cer)
                    ? "用户 CA 已静默安装"
                    : "安装失败，请改用系统安装引导");
            }, !owner), WeightedButtonParams());
            row2.AddView(CreateButton("复制设备所有者命令", () =>
            {
                CopyText(AndroidCertificateInstaller.ShizukuCommand);
                ShowToast("已复制设备所有者命令");
            }, false), WeightedButtonParams());
            card.AddView(row2);
        }

        void CopyText(string text)
        {
            var clipboard = (ClipboardManager?)GetSystemService(ClipboardService);
            if (clipboard == null) return;
            clipboard.SetPrimaryClip(ClipData.NewPlainText("SteamTools", text));
        }

        async void InstallRootCertificateAsync()
        {
            try
            {
                var manager = IReverseProxyService.Instance.CertificateManager;
                if (manager.GetCerFilePathGeneratedWhenNoFileExists() == null)
                {
                    ShowToast("证书生成失败，请查看诊断日志");
                    return;
                }

                // Android 上 SetupRootCertificate 的返回值只代表“是否已信任”，
                // 而用户此时还没在系统设置里确认，所以这里直接打开安装引导。
                await manager.PlatformTrustRootCertificateGuide();
                RefreshStatus();
            }
            catch (Exception ex)
            {
                ShowToast("安装证书失败: " + ex.Message);
            }
        }

        void BuildRelaySection()
        {
            var card = AddSection(
                "DNS 与上游中继",
                "安全 DNS 默认开启，负责把被污染的域名解析换成可用 IP。中继只在直连/分片都失败时才需要。");

            AddSecureDnsSwitch(card);

            AddSwitch(card, "使用 DevSidecar 预置 IP",
                "把 remote_config 的 preSetIpList 直接写进 DNS 响应。免证书模式下 GitHub/Hugging Face 依赖它。",
                ProxySettings.EnableDnsPresetIp);
            AddSwitch(card, "Hugging Face 兜底 IP",
                "为 Hugging Face 域名补充 CloudFront 兜底 IP；远程配置里的 IP 会优先。",
                ProxySettings.EnableHuggingFaceFallback);
            AddSwitch(card, "允许 UDP / HTTP/3（QUIC）",
                "允许应用通过 UDP 443 直连，可能绕过只针对 TCP SNI 的 DPI。关闭后 tun2socks 不再启用 UDP 转发。",
                ProxySettings.EnableUdpRelay);

            var advanced = AddExpander(card, "高级 DNS 与 DoH");
            AddSwitch(advanced, "仅 DoH（不启用本地 DNS 代理）", "调试用。一般保持上面的“安全 DNS”开启即可。", ProxySettings.EnableDoh);
            AddSwitch(advanced, "本地 DNS 代理", "通过 tun2socks --dnsgw 接管 UDP:53。", ProxySettings.EnableDnsProxy);
            AddText(advanced, "DoH wire 接口", "用于本地 DNS 代理转发完整 DNS 报文。", ProxySettings.DohWireEndpoint, false, InputTypes.ClassText | InputTypes.TextVariationUri);
            AddText(advanced, "DoH JSON 接口", "用于 sidecar 选路。", ProxySettings.DohEndpoint, false, InputTypes.ClassText | InputTypes.TextVariationUri);
            AddSwitch(advanced, "DoH 失败回退系统 DNS", "关闭后 DoH 失败会返回 SERVFAIL，便于确认 DoH 是否可用。", ProxySettings.DohFallbackToSystem);
            AddNumber(advanced, "DNS 代理端口", "仅绑定 127.0.0.1；被占用时自动向后寻找。", ProxySettings.DnsProxyPortId, 1024, 65535);
            AddText(advanced, "回退 DNS 服务器", "分号分隔，例如 223.5.5.5;119.29.29.29。", ProxySettings.DnsFallbackServers, false);

            var relay = AddExpander(advanced, "上游 SOCKS5 中继（有本地代理时可开）");
            AddSwitch(relay, "启用上游 SOCKS5 中继", "所有 TCP 先到中继，再由中继连接目标。", ProxySettings.EnableSniUpstreamRelay);
            AddText(relay, "中继地址", "IP 或域名。", ProxySettings.SniUpstreamRelayHost, false);
            AddNumber(relay, "中继端口", "常见端口：7890、1080、10808。", ProxySettings.SniUpstreamRelayPort, 1, 65535);
            AddText(relay, "中继生效域名", "留空表示全部（排除列表除外）。", ProxySettings.SniUpstreamRelayDomains, false);
            AddText(relay, "中继用户名", "没有认证时留空。", ProxySettings.SniUpstreamRelayUserName, false);
            AddText(relay, "中继密码", "没有认证时留空。", ProxySettings.SniUpstreamRelayPassword, true);
        }

        void BuildVpnAndLogSection()
        {
            var card = AddSection("VPN 与诊断日志", "日志只写本地应用目录，不记录 Authorization/Cookie/请求体。可以先导出再发给别人。");

            AddSwitch(card, "增强模式仅浏览器走 VPN", "未安装系统证书时，其它应用可能因 MITM 断网；开启后只把常见浏览器加入 VPN。", ProxySettings.EnableBrowserOnlyVpn);
            AddSwitch(card, "写代理诊断日志", "关闭后不再新增日志，已有日志保留。", ProxySettings.EnableProxyDiagnostics);

            var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row.AddView(CreateButton("导出日志", ExportLogs, true), WeightedButtonParams());
            row.AddView(CreateButton("分享日志", ShareLogs, false), WeightedButtonParams());
            card.AddView(row);

            var row2 = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row2.AddView(CreateButton("上次崩溃日志", () =>
            {
                var path = AndroidCrashLogger.CrashFilePath;
                if (string.IsNullOrEmpty(path) || !File.Exists(path))
                {
                    ShowToast("没有崩溃日志");
                    return;
                }
                GoToPlatformPages.OpenFile(this, new Java.IO.File(path), "text/plain");
            }, false), WeightedButtonParams());
            row2.AddView(CreateButton("清理日志", () =>
            {
                ProxyDiagnostics.Clear();
                ShowToast("日志已清理");
            }, false), WeightedButtonParams());
            row2.AddView(CreateButton("日志目录", () =>
            {
                Android.Widget.Toast.MakeText(this, new Java.Lang.String(ProxyDiagnostics.LogDirectory), Android.Widget.ToastLength.Long)?.Show();
            }, false), WeightedButtonParams());
            card.AddView(row2);

            var advanced = AddExpander(card, "高级日志设置");
            AddChoice(advanced, "日志最低级别", "Info 最详细；Warn 只记录警告和错误；Error 只记录错误。",
                new[] { "Info", "Warn", "Error" },
                ProxySettings.ProxyDiagnosticsMinimumLevel.Value,
                value => ProxySettings.ProxyDiagnosticsMinimumLevel.Value = value);
            AddSwitch(advanced, "日志保留主机名", "关闭后会把日志里形似域名的文本替换为 ***，便于分享日志。", ProxySettings.ProxyDiagnosticsIncludeHost);
            AddNumber(advanced, "日志保留天数", "启动时会清理超过天数的 proxy-*.log。", ProxySettings.ProxyDiagnosticsRetentionDays, 1, 365);
            AddNumber(advanced, "单文件上限（KB）", "超过后写入新的时间戳文件。", ProxySettings.ProxyDiagnosticsMaxFileSizeKB, 64, 1048576);
        }

        string BuildLogBundle()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Watt Toolkit Android 诊断日志");
            sb.AppendLine($"时间: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
            sb.AppendLine($"设备: {Build.Manufacturer} {Build.Model} / Android {Build.VERSION.Release} (API {(int)Build.VERSION.SdkInt}) / {string.Join(",", Build.SupportedAbis ?? Array.Empty<string>())}");
            sb.AppendLine();
            sb.AppendLine(AcceleratorLabService.BuildSettingsSnapshot());
            sb.AppendLine("== 最近日志 ==");
            var logs = ProxyDiagnostics.GetRecentLogText(2000);
            sb.AppendLine(string.IsNullOrWhiteSpace(logs) ? "(无日志)" : logs);
            return sb.ToString();
        }

        void ExportLogs()
        {
            pendingLogExport = BuildLogBundle();
            try
            {
                var intent = new Intent(Intent.ActionCreateDocument);
                intent.AddCategory(Intent.CategoryOpenable);
                intent.SetType("text/plain");
                intent.PutExtra(Intent.ExtraTitle, $"watt-logs-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
                StartActivityForResult(intent, ExportLogRequestCode);
            }
            catch (Exception ex)
            {
                pendingLogExport = null;
                ShowToast("无法打开文件选择器: " + ex.Message);
            }
        }

        void ShareLogs()
        {
            try
            {
                var text = BuildLogBundle();
                var intent = new Intent(Intent.ActionSend);
                intent.SetType("text/plain");
                intent.PutExtra(Intent.ExtraText, text);
                StartActivity(Intent.CreateChooser(intent, "分享诊断日志"));
            }
            catch (Exception ex)
            {
                ShowToast("分享失败: " + ex.Message);
            }
        }

        protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
        {
            base.OnActivityResult(requestCode, resultCode, data);
            if (requestCode != ExportLogRequestCode) return;
            if (resultCode != Result.Ok || data?.Data == null || pendingLogExport == null) return;

            try
            {
                using var stream = ContentResolver?.OpenOutputStream(data.Data);
                if (stream == null)
                {
                    ShowToast("无法写入所选文件");
                    return;
                }
                using var writer = new System.IO.StreamWriter(stream);
                writer.Write(pendingLogExport);
                ShowToast("日志已导出");
            }
            catch (Exception ex)
            {
                ShowToast("导出失败: " + ex.Message);
            }
            finally
            {
                pendingLogExport = null;
            }
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
                DnsProxyService.Restart();
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
                        DnsProxyService.Stop();
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
                ShowToast($"已应用 {ProxyRuleEngine.Current.Rules.Count} 条规则，{ProxyRuleEngine.GroupStats.Count} 个分组");
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
                if (ProxyRuleEngine.Remote.Rules.Count > 0)
                {
                    ProxyRuleEngine.Apply(ProxyRuleEngine.Remote);
                }
                else
                {
                    // 本地还没有缓存时直接同步一次，避免“开关打开了但一条规则都没有”。
                    SyncRulesAsync();
                    return;
                }
            }
            else
            {
                ProxyRuleEngine.Clear();
            }
            RefreshStatus();
        }

        void RefreshStatus()
        {
            if (statusView == null) return;

            try
            {
                var sidecar = SniSidecarService.IsRunning
                    ? $"运行中 127.0.0.1:{SniSidecarService.ActivePort}"
                    : "未运行";
                var dnsProxy = DnsProxyService.IsRunning
                    ? $"运行中 127.0.0.1:{DnsProxyService.ActivePort}"
                    : "未运行";
                var cert = IReverseProxyService.Instance.CertificateManager.IsRootCertificateInstalled
                    ? "已安装"
                    : "未安装";
                var sync = ProxyRuleEngine.LastSyncTime.HasValue
                    ? ProxyRuleEngine.LastSyncTime.Value.ToString("yyyy-MM-dd HH:mm:ss")
                    : "未同步";
                var error = string.IsNullOrEmpty(ProxyRuleEngine.LastError)
                    ? string.Empty
                    : $"\n远程错误: {ProxyRuleEngine.LastError}";
                var customError = string.IsNullOrEmpty(ProxyRuleEngine.LastCustomError)
                    ? string.Empty
                    : $"\n自定义错误: {ProxyRuleEngine.LastCustomError}";

                statusView.Text =
                    $"Sidecar: {sidecar}\n" +
                    $"DNS 代理: {dnsProxy}\n" +
                    $"根证书: {cert}\n" +
                    $"远程分组: {ProxyRuleEngine.GroupStats.Count} 个，关闭组: {(string.IsNullOrWhiteSpace(ProxySettings.DevSidecarDisabledGroups.Value) ? "无" : ProxySettings.DevSidecarDisabledGroups.Value)}\n" +
                    $"自定义: {(ProxySettings.EnableCustomRules.Value ? "启用" : "关闭")}，{ProxyRuleEngine.CustomRuleCount} 条\n" +
                    $"规则: 实际启用 {ProxyRuleEngine.Current.Rules.Count} / 远程 {ProxyRuleEngine.Remote.Rules.Count} 条\n" +
                    $"上次同步: {sync}{error}{customError}\n" +
                    $"SNI 统计: {SniSidecarStats.ToDisplayString()}\n" +
                    $"DNS 统计: {DnsProxyServer.GetStats()}\n" +
                    $"回退缓存: {FragmentFallbackCache.Count} 个域名";
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

        /// <summary>
        /// 可折叠的高级设置区域，减少主界面的重复开关。
        /// </summary>
        LinearLayout AddExpander(LinearLayout parent, string title)
        {
            var header = new TextView(this)
            {
                Text = "▸ " + title,
                TextSize = 13,
                Typeface = Typeface.DefaultBold,
            };
            header.SetTextColor(ResColor(Resource.Color.text_primary));
            header.SetPadding(0, Dp(12), 0, Dp(6));

            var content = new LinearLayout(this) { Orientation = Orientation.Vertical };
            content.Visibility = ViewStates.Gone;

            header.Click += (_, _) =>
            {
                var open = content.Visibility != ViewStates.Visible;
                content.Visibility = open ? ViewStates.Visible : ViewStates.Gone;
                header.Text = (open ? "▾ " : "▸ ") + title;
            };

            parent.AddView(header);
            parent.AddView(content);
            return content;
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

        /// <summary>
        /// 一个开关同时控制 DoH 和本地 DNS 代理，避免用户面对两个重复开关。
        /// </summary>
        void AddSecureDnsSwitch(LinearLayout parent)
        {
            var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            row.SetGravity(GravityFlags.CenterVertical);
            row.SetPadding(0, Dp(10), 0, Dp(10));
            row.Clickable = true;
            row.Focusable = true;

            var textLayout = new LinearLayout(this) { Orientation = Orientation.Vertical };
            var titleView = new TextView(this) { Text = "启用安全 DNS（DoH + 本地 DNS 代理）", TextSize = 14 };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            textLayout.AddView(titleView);

            var descView = new TextView(this)
            {
                Text = "VPN 的 DNS 会送到 127.0.0.1，避免 ERR_NAME_NOT_RESOLVED 和 DNS 污染。一般保持开启。",
                TextSize = 11,
            };
            descView.SetTextColor(ResColor(Resource.Color.text_secondary));
            descView.SetPadding(0, Dp(2), Dp(8), 0);
            textLayout.AddView(descView);

            row.AddView(textLayout, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

            var switchView = new Switch(this)
            {
                Checked = ProxySettings.EnableDoh.Value && ProxySettings.EnableDnsProxy.Value,
                Clickable = false,
                Focusable = false,
            };
            switchView.CheckedChange += (_, e) =>
            {
                if (building) return;
                ProxySettings.EnableDoh.Value = e.IsChecked;
                ProxySettings.EnableDnsProxy.Value = e.IsChecked;
                SettingsHost.Save();
            };
            row.AddView(switchView);
            row.Click += (_, _) => switchView.Checked = !switchView.Checked;

            parent.AddView(row);
            AddRowDivider(parent);
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
