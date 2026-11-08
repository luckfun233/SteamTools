using System;
using Android.App;
using Android.OS;
using Android.Util;
using Android.Views;
using Android.Widget;
using System.Application.ProxyRules;
using System.Application.Services.Implementation;
using System.Application.Settings;

namespace System.Application.UI.Activities
{
    /// <summary>
    /// 实验性加速设置：DevSidecar 规则、SNI 分片/改写、诊断日志。
    /// </summary>
    [Activity(
        Theme = ManifestConstants.MainTheme2_NoActionBar,
        LaunchMode = LaunchMode.SingleTask,
        ConfigurationChanges = ManifestConstants.ConfigurationChanges)]
    internal sealed class ExperimentalSettingsActivity : Activity
    {
        LinearLayout? container;

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            var scroll = new ScrollView(this);
            container = new LinearLayout(this) { Orientation = Orientation.Vertical };
            container.SetPadding(Dp(16), Dp(16), Dp(16), Dp(24));
            scroll.AddView(container);
            SetContentView(scroll);

            AddTitle("实验性加速设置");
            AddSwitch("启用 DevSidecar 兼容规则", ProxySettings.EnableDevSidecarRules);
            AddSwitch("启动时同步 DevSidecar 配置", ProxySettings.SyncDevSidecarConfigOnStartup);
            AddText("DevSidecar 配置地址", ProxySettings.DevSidecarConfigUrl);
            AddSwitch("免证书 SNI 分片", ProxySettings.EnableSniFragment);
            AddSwitch("免证书 SNI 改写（实验）", ProxySettings.EnableSniRewrite);
            AddText("SNI 改写目标", ProxySettings.SniRewriteHost);
            AddText("SNI 改写域名（分号分隔）", ProxySettings.SniRewriteDomains);
            AddNumber("分片大小（字节）", ProxySettings.SniFragmentChunkSize, 1, 1024);
            AddNumber("分片延迟（毫秒）", ProxySettings.SniFragmentDelayMilliseconds, 0, 1000);
            AddNumber("Sidecar 端口", ProxySettings.SniFragmentPortId, 1024, 65535);
            AddSwitch("写入代理诊断日志", ProxySettings.EnableProxyDiagnostics);
            AddSwitch("增强模式仅浏览器走 VPN", ProxySettings.EnableBrowserOnlyVpn);
            AddNumber("日志保留天数", ProxySettings.ProxyDiagnosticsRetentionDays, 1, 365);
            AddNumber("单日志文件上限（KB）", ProxySettings.ProxyDiagnosticsMaxFileSizeKB, 64, 1024 * 1024);

            AddButton("应用并重载规则", async () =>
            {
                SettingsHost.Save();
                ProxyDiagnostics.Initialize();
                await ProxyRuleEngine.ReloadAsync();
                SniSidecarService.Stop();
                SniSidecarService.Start();
                Toast.MakeText(this, "已应用", ToastLength.Short)?.Show();
            });

            AddButton("打开日志目录说明", () =>
            {
                Toast.MakeText(this, ProxyDiagnostics.LogDirectory, ToastLength.Long)?.Show();
            });

            AddButton("清理代理日志", () =>
            {
                ProxyDiagnostics.Clear();
                Toast.MakeText(this, "日志已清理", ToastLength.Short)?.Show();
            });
        }

        void AddTitle(string text)
        {
            var view = new TextView(this)
            {
                Text = text,
                TextSize = 20,
            };
            view.SetPadding(0, 0, 0, Dp(8));
            container!.AddView(view);
        }

        void AddSwitch(string label, SerializableProperty<bool> property)
        {
            var view = new CheckBox(this)
            {
                Text = label,
                Checked = property.Value,
            };
            view.CheckedChange += (_, e) =>
            {
                property.Value = e.IsChecked;
                SettingsHost.Save();
            };
            container!.AddView(view);
        }

        void AddText(string label, SerializableProperty<string> property)
        {
            var title = new TextView(this) { Text = label };
            title.SetPadding(0, Dp(8), 0, 0);
            container!.AddView(title);
            var input = new EditText(this) { Text = property.Value };
            input.TextChanged += (_, e) =>
            {
                property.Value = e.Text?.ToString() ?? string.Empty;
                SettingsHost.Save();
            };
            container!.AddView(input);
        }

        void AddNumber(string label, SerializableProperty<int> property, int min, int max)
        {
            var title = new TextView(this) { Text = label };
            title.SetPadding(0, Dp(8), 0, 0);
            container!.AddView(title);
            var input = new EditText(this)
            {
                Text = property.Value.ToString(),
                InputType = Android.Text.InputTypes.ClassNumber,
            };
            input.TextChanged += (_, e) =>
            {
                if (int.TryParse(e.Text?.ToString(), out var value))
                {
                    property.Value = Math.Min(max, Math.Max(min, value));
                    SettingsHost.Save();
                }
            };
            container!.AddView(input);
        }

        void AddButton(string text, Action action)
        {
            var button = new Button(this) { Text = text };
            button.Click += (_, _) => action();
            container!.AddView(button);
        }

        int Dp(int value)
            => (int)TypedValue.ApplyDimension(ComplexUnitType.Dip, value, Resources.DisplayMetrics);
    }
}
