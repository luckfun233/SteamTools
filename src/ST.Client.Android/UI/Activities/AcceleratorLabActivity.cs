using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Content.Res;
using Android.OS;
using Android.Runtime;
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
    /// Android 加速实验室：一键运行设备状态、DNS、TCP/TLS、Sidecar、代理和 UDP 检查，并导出报告。
    /// </summary>
    [Activity(
        Theme = ManifestConstants.MainTheme2_NoActionBar,
        LaunchMode = LaunchMode.SingleTask,
        ConfigurationChanges = ManifestConstants.ConfigurationChanges)]
    internal sealed class AcceleratorLabActivity : Activity
    {
        const int ExportRequestCode = 4201;

        LinearLayout? container;
        EditText? hostInput;
        EditText? runsInput;
        TextView? statusView;
        TextView? resultsView;
        string? pendingExport;
        string? lastReport;
        IReadOnlyList<LabTestResult>? lastResults;

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            var root = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Vertical };
            root.SetBackgroundColor(new Android.Graphics.Color(ResColor(Resource.Color.grey_window_background)));
            AddHeader(root);

            var scroll = new ScrollView(this)
            {
                LayoutParameters = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1f),
            };
            container = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Vertical };
            container.SetPadding(Dp(14), 0, Dp(14), Dp(28));
            scroll.AddView(container);
            root.AddView(scroll);
            SetContentView(root);

            BuildUi();
            RefreshStatus();
        }

        void AddHeader(LinearLayout root)
        {
            var header = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Horizontal };
            header.SetGravity(GravityFlags.CenterVertical);
            header.SetPadding(Dp(14), Dp(12), Dp(14), Dp(12));
            header.SetBackgroundColor(new Android.Graphics.Color(ResColor(Resource.Color.grey_window_background)));

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
                Text = "加速实验室",
                TextSize = 19,
                Typeface = Android.Graphics.Typeface.DefaultBold,
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
            var statusCard = AddSection("设备与代理状态", "这些信息会写入导出报告，方便对比不同设备/网络。");
            statusView = AddInfoText(statusCard, "正在读取…");
            statusCard.AddView(CreateButton("刷新状态", () =>
            {
                RefreshStatus();
                ToastShow("状态已刷新");
            }, false));

            var testCard = AddSection("一键测试", "会依次检查规则集、DNS、DoH、TCP、直连 TLS、Sidecar TLS、Titanium 代理和 UDP。测试不会修改代理状态。");
            AddTextRow(testCard, "测试域名", out hostInput, AcceleratorLabService.DefaultHost);
            AddTextRow(testCard, "策略矩阵次数", out runsInput, "3", InputTypes.ClassNumber);

            var row = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Horizontal };
            row.AddView(CreateButton("运行全部", RunAllAsync, true), WeightedButtonParams());
            row.AddView(CreateButton("分片策略矩阵", RunMatrixAsync, false), WeightedButtonParams());
            testCard.AddView(row);

            var row2 = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Horizontal };
            row2.AddView(CreateButton("导出报告", ExportReport, true), WeightedButtonParams());
            row2.AddView(CreateButton("复制报告", CopyReport, false), WeightedButtonParams());
            testCard.AddView(row2);

            var row3 = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Horizontal };
            row3.AddView(CreateButton("清空统计", () =>
            {
                SniSidecarStats.Reset();
                RefreshStatus();
                ToastShow("统计与回退缓存已清空");
            }, false), WeightedButtonParams());
            row3.AddView(CreateButton("查看最近日志", ShowLogDialog, false), WeightedButtonParams());
            testCard.AddView(row3);

            var resultCard = AddSection("测试结果", "失败的项会标记为 FAIL；INFO 表示该检查只能作为参考，不能判定通过/失败。");
            resultsView = AddInfoText(resultCard, "尚未运行测试。");
        }

        string GetDeviceInfo()
        {
            try
            {
                var abis = Build.SupportedAbis == null ? string.Empty : string.Join(",", Build.SupportedAbis);
                var vpn = Android.Net.VpnService.Prepare(this) == null ? "已授权" : "未授权";
                var cert = "未知";
                try
                {
                    cert = IReverseProxyService.Instance.CertificateManager.IsRootCertificateInstalled ? "已安装" : "未安装";
                }
                catch
                {
                    // DI 未初始化时忽略
                }

                return
                    $"{Build.Manufacturer} {Build.Model} / Android {Build.VERSION.Release} (API {(int)Build.VERSION.SdkInt}) / {abis}\n" +
                    $"VPN: {vpn}，根证书: {cert}";
            }
            catch (Exception ex)
            {
                return "读取设备信息失败: " + ex.Message;
            }
        }

        void RefreshStatus()
        {
            if (statusView == null) return;

            try
            {
                var proxy = ProxyService.Current;
                var sidecar = SniSidecarService.IsRunning
                    ? $"运行中 127.0.0.1:{SniSidecarService.ActivePort}"
                    : "未运行";

                statusView.Text =
                    GetDeviceInfo() + "\n" +
                    $"代理模式: {ProxySettings.ProxyModeValue}\n" +
                    $"代理状态: {(proxy.ProxyStatus ? "运行中" : "已停止")}，监听 {proxy.ProxyIp}:{proxy.ProxyPort}，SOCKS5 {proxy.Socks5ProxyPortId}\n" +
                    $"Sidecar: {sidecar}\n" +
                    $"规则: 自定义 {ProxyRuleEngine.CustomRuleCount} 条，启用 {ProxyRuleEngine.Current.Rules.Count} 条\n" +
                    $"统计: {SniSidecarStats.ToDisplayString()}\n" +
                    $"回退缓存: {FragmentFallbackCache.Count} 个域名";
            }
            catch (Exception ex)
            {
                statusView.Text = "读取状态失败: " + ex.Message;
            }
        }

        async void RunAllAsync()
        {
            if (hostInput == null) return;
            var host = hostInput.Text?.Trim();
            if (string.IsNullOrWhiteSpace(host)) host = AcceleratorLabService.DefaultHost;

            var progress = ShowProgress("正在运行测试…");
            try
            {
                var device = GetDeviceInfo();
                var results = await Task.Run(() => AcceleratorLabService.RunAllAsync(host!, device, ProxyTestAsync));
                lastResults = results;
                lastReport = AcceleratorLabService.BuildReport(device, results);
                ShowResults(results);
                RefreshStatus();

                var failed = results.Count(x => !x.Success && !x.Informational);
                ToastShow(failed == 0 ? "测试完成，全部通过" : $"测试完成，{failed} 项失败");
            }
            catch (Exception ex)
            {
                ToastShow("测试失败: " + ex.Message);
            }
            finally
            {
                progress.Dismiss();
            }
        }

        async void RunMatrixAsync()
        {
            if (hostInput == null) return;
            var host = hostInput.Text?.Trim();
            if (string.IsNullOrWhiteSpace(host)) host = AcceleratorLabService.DefaultHost;

            var runs = 3;
            if (runsInput != null && int.TryParse(runsInput.Text, out var parsed))
            {
                runs = Math.Max(1, Math.Min(10, parsed));
            }

            var progress = ShowProgress("正在逐项测试分片策略，每种会重复多次，请保持网络连接…");
            try
            {
                var report = await Task.Run(() => SniConnectivityTester.RunStrategyMatrixAsync(host!, 443, 8, runs));
                lastReport = report;
                if (resultsView != null) resultsView.Text = report;
                RefreshStatus();
                ShowTextDialog("分片策略矩阵", report);
            }
            catch (Exception ex)
            {
                ToastShow("矩阵测试失败: " + ex.Message);
            }
            finally
            {
                progress.Dismiss();
            }
        }

        Task<LabTestResult> ProxyTestAsync(CancellationToken cancellationToken)
        {
            var proxy = ProxyService.Current;
            if (!proxy.ProxyStatus)
            {
                return Task.FromResult(new LabTestResult(
                    "Titanium 代理 HTTP",
                    true,
                    0,
                    "代理未运行，已跳过",
                    informational: true));
            }

            return TestProxyAsync(proxy, cancellationToken);
        }

        async Task<LabTestResult> TestProxyAsync(ProxyService proxy, CancellationToken cancellationToken)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var ip = proxy.ProxyIp;
                if (IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip)) ip = IPAddress.Loopback;

                var handler = new Xamarin.Android.Net.AndroidClientHandler
                {
                    Proxy = new WebProxy(ip.ToString(), proxy.ProxyPort),
                    UseCookies = false,
                };

                try
                {
                    var certPath = IReverseProxyService.Instance.CertificateManager.GetCerFilePathGeneratedWhenNoFileExists();
                    if (certPath != null && File.Exists(certPath))
                    {
                        handler.AddTrustedCert(File.OpenRead(certPath));
                    }
                }
                catch
                {
                    // 证书不可用时仍然测试明文 HTTP 行为
                }

                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
                using var response = await client.GetAsync("https://github.com/robots.txt", cancellationToken);
                return new LabTestResult(
                    "Titanium 代理 HTTP",
                    response.IsSuccessStatusCode,
                    watch.ElapsedMilliseconds,
                    $"HTTP {(int)response.StatusCode}");
            }
            catch (Exception ex)
            {
                return new LabTestResult("Titanium 代理 HTTP", false, watch.ElapsedMilliseconds, ex.Message);
            }
        }

        void ShowResults(IReadOnlyList<LabTestResult> results)
        {
            if (resultsView == null) return;

            var sb = new System.Text.StringBuilder();
            foreach (var result in results)
            {
                sb.AppendLine(result.ToLine());
            }
            resultsView.Text = sb.ToString();
        }

        void ExportReport()
        {
            var report = lastReport;
            if (string.IsNullOrEmpty(report))
            {
                if (lastResults == null)
                {
                    ToastShow("请先运行一次测试");
                    return;
                }
                report = AcceleratorLabService.BuildReport(GetDeviceInfo(), lastResults);
                lastReport = report;
            }

            pendingExport = report;
            try
            {
                var intent = new Intent(Intent.ActionCreateDocument);
                intent.AddCategory(Intent.CategoryOpenable);
                intent.SetType("text/plain");
                intent.PutExtra(Intent.ExtraTitle, $"watt-lab-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
                StartActivityForResult(intent, ExportRequestCode);
            }
            catch (Exception ex)
            {
                ToastShow("无法打开文件选择器: " + ex.Message);
            }
        }

        protected override void OnActivityResult(int requestCode, [GeneratedEnum] Result resultCode, Intent? data)
        {
            base.OnActivityResult(requestCode, resultCode, data);

            if (requestCode != ExportRequestCode) return;
            if (resultCode != Result.Ok || data?.Data == null || pendingExport == null) return;

            try
            {
                using var stream = ContentResolver?.OpenOutputStream(data.Data);
                if (stream == null)
                {
                    ToastShow("无法写入所选文件");
                    return;
                }
                using var writer = new StreamWriter(stream);
                writer.Write(pendingExport);
                ToastShow("报告已导出");
            }
            catch (Exception ex)
            {
                ToastShow("导出失败: " + ex.Message);
            }
            finally
            {
                pendingExport = null;
            }
        }

        void CopyReport()
        {
            var report = lastReport;
            if (string.IsNullOrEmpty(report))
            {
                if (lastResults == null)
                {
                    ToastShow("请先运行一次测试");
                    return;
                }
                report = AcceleratorLabService.BuildReport(GetDeviceInfo(), lastResults);
                lastReport = report;
            }

            try
            {
                var clipboard = (Android.Content.ClipboardManager?)GetSystemService(ClipboardService);
                if (clipboard != null) clipboard.PrimaryClip = Android.Content.ClipData.NewPlainText("steamtools", report);
                ToastShow("报告已复制到剪贴板");
            }
            catch (Exception ex)
            {
                ToastShow("复制失败: " + ex.Message);
            }
        }

        void ShowLogDialog()
        {
            var log = ProxyDiagnostics.GetRecentLogText();
            ShowTextDialog("最近诊断日志", string.IsNullOrEmpty(log) ? "暂无日志" : log);
        }

        void ShowTextDialog(string title, string text)
        {
            var view = new TextView(this)
            {
                Text = text,
                TextSize = 11,
                Typeface = Android.Graphics.Typeface.Monospace,
            };
            view.SetTextIsSelectable(true);
            view.SetPadding(Dp(14), Dp(8), Dp(14), Dp(8));
            view.SetTextColor(ResColor(Resource.Color.text_primary));

            var scroll = new ScrollView(this);
            scroll.AddView(view);

            var dialog = new AlertDialog.Builder(this)
                .SetTitle(title)
                .SetView(scroll)
                .SetPositiveButton("关闭", (_, _) => { })
                .Create();
            dialog.Show();
        }

        AlertDialog ShowProgress(string message)
        {
            var dialog = new AlertDialog.Builder(this)
                .SetMessage(message)
                .SetCancelable(false)
                .Create();
            dialog.Show();
            return dialog;
        }

        LinearLayout AddSection(string title, string description)
        {
            var titleView = new TextView(this)
            {
                Text = title,
                TextSize = 16,
                Typeface = Android.Graphics.Typeface.DefaultBold,
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

            var card = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Vertical };
            var background = new Android.Graphics.Drawables.GradientDrawable();
            background.SetColor(IsNightMode
                ? Android.Graphics.Color.ParseColor("#1E1E1E")
                : Android.Graphics.Color.White);
            background.SetCornerRadius(Dp(12));
            background.SetStroke(Dp(1), IsNightMode
                ? Android.Graphics.Color.ParseColor("#33FFFFFF")
                : Android.Graphics.Color.ParseColor("#1F000000"));
            card.Background = background;
            card.SetPadding(Dp(14), Dp(4), Dp(14), Dp(10));
            container.AddView(card);
            return card;
        }

        TextView AddInfoText(LinearLayout parent, string text)
        {
            var view = new TextView(this)
            {
                Text = text,
                TextSize = 12,
                Typeface = Android.Graphics.Typeface.Monospace,
            };
            view.SetTextColor(ResColor(Resource.Color.text_primary));
            view.SetPadding(0, Dp(10), 0, Dp(8));
            parent.AddView(view);
            return view;
        }

        void AddTextRow(
            LinearLayout parent,
            string title,
            out EditText input,
            string defaultValue,
            InputTypes inputType = InputTypes.ClassText)
        {
            var layout = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Vertical };
            layout.SetPadding(0, Dp(8), 0, Dp(6));

            var titleView = new TextView(this) { Text = title, TextSize = 13 };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            layout.AddView(titleView);

            input = new EditText(this)
            {
                Text = defaultValue,
                TextSize = 13,
            };
            input.SetSingleLine(true);
            input.InputType = inputType;
            input.SetTextColor(ResColor(Resource.Color.text_primary));
            layout.AddView(input);
            parent.AddView(layout);
        }

        Button CreateButton(string text, Action action, bool primary)
        {
            var button = new Button(this) { Text = text };
            button.SetAllCaps(false);
            button.TextSize = 13;
            if (primary)
            {
                button.SetTextColor(Android.Graphics.Color.White);
                var background = new Android.Graphics.Drawables.GradientDrawable();
                background.SetColor(Android.Graphics.Color.ParseColor("#2F6FED"));
                background.SetCornerRadius(Dp(8));
                button.Background = background;
            }
            button.Click += (_, _) => action();
            return button;
        }

        LinearLayout.LayoutParams WeightedButtonParams()
        {
            var layout = new LinearLayout.LayoutParams(0, Dp(42), 1f);
            layout.RightMargin = Dp(4);
            layout.TopMargin = Dp(4);
            return layout;
        }

        void ToastShow(string message)
            => Android.Widget.Toast.MakeText(this, message, Android.Widget.ToastLength.Short)?.Show();

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
