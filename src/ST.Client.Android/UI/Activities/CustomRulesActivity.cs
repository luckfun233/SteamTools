using System;
using System.Collections.Generic;
using System.Linq;
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
using ClipboardManager = Android.Content.ClipboardManager;
using Color = Android.Graphics.Color;
using Orientation = Android.Widget.Orientation;
using System.Application.ProxyRules;
using System.Application.Services.Implementation;

namespace System.Application.UI.Activities
{
    /// <summary>
    /// 自定义 DevSidecar 规则编辑：校验、保存、示例、快速添加、删除规则。
    /// 保存后的规则会和远程规则合并，并优先匹配。
    /// </summary>
    [Activity(
        Theme = ManifestConstants.MainTheme2_NoActionBar,
        LaunchMode = LaunchMode.SingleTask,
        ConfigurationChanges = ManifestConstants.ConfigurationChanges)]
    internal sealed class CustomRulesActivity : Activity
    {
        EditText? editor;
        TextView? summaryView;

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            var root = new LinearLayout(this) { Orientation = Orientation.Vertical };
            root.SetBackgroundColor(ResColor(Resource.Color.grey_window_background));
            AddHeader(root);

            var scroll = new ScrollView(this)
            {
                LayoutParameters = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1f),
            };
            var container = new LinearLayout(this) { Orientation = Orientation.Vertical };
            container.SetPadding(Dp(14), 0, Dp(14), Dp(28));
            scroll.AddView(container);
            root.AddView(scroll);
            SetContentView(root);

            BuildUi(container);
            LoadText();
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
                Text = "自定义规则",
                TextSize = 19,
                Typeface = Android.Graphics.Typeface.DefaultBold,
                Gravity = GravityFlags.Center,
            };
            title.SetTextColor(ResColor(Resource.Color.text_primary));
            header.AddView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

            var save = new TextView(this)
            {
                Text = "保存",
                TextSize = 15,
                Gravity = GravityFlags.CenterVertical,
            };
            save.SetTextColor(ResColor(Resource.Color.text_link));
            save.Click += (_, _) => SaveRules();
            header.AddView(save, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WrapContent, Dp(40)));

            root.AddView(header);
        }

        void BuildUi(LinearLayout container)
        {
            var info = AddSection(container, "格式说明",
                "与 DevSidecar 的 intercepts 相同，可省略 server 包装，支持注释、单引号和尾随逗号。\n" +
                "支持：sni、verifyHost、redirect、proxy、backup、abort、desc、requestReplace.headers、responseReplace.headers。\n" +
                "自定义规则始终叠加在远程规则之前；带 Authorization/Cookie 的请求不会进入第三方镜像。");

            var actions = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            actions.AddView(CreateButton("校验", ValidateRules, false), WeightedButtonParams());
            actions.AddView(CreateButton("快速添加", ShowQuickAdd, true), WeightedButtonParams());
            info.AddView(actions);

            var actions2 = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            actions2.AddView(CreateButton("删除规则", ShowDeleteRule, false), WeightedButtonParams());
            actions2.AddView(CreateButton("插入示例", InsertSample, false), WeightedButtonParams());
            info.AddView(actions2);

            var actions3 = new LinearLayout(this) { Orientation = Orientation.Horizontal };
            actions3.AddView(CreateButton("复制", CopyText, false), WeightedButtonParams());
            actions3.AddView(CreateButton("清空文件", ClearFile, false), WeightedButtonParams());
            info.AddView(actions3);

            var editorCard = AddSection(container, "规则内容",
                "保存前会先校验；解析失败不会覆盖现有规则文件。");
            editor = new EditText(this)
            {
                TextSize = 12,
                Gravity = GravityFlags.Top,
                Typeface = Android.Graphics.Typeface.Monospace,
                Hint = "在此粘贴 DevSidecar 规则…",
            };
            editor.SetTextColor(ResColor(Resource.Color.text_primary));
            editor.SetHintTextColor(ResColor(Resource.Color.text_secondary));
            editor.SetSingleLine(false);
            editor.SetMinLines(12);
            editor.SetTextIsSelectable(true);
            editorCard.AddView(editor);

            var summaryCard = AddSection(container, "解析结果", "域名和路径会在保存后立即生效，无需重启代理。");
            summaryView = new TextView(this)
            {
                TextSize = 11,
                Typeface = Android.Graphics.Typeface.Monospace,
            };
            summaryView.SetTextColor(ResColor(Resource.Color.text_primary));
            summaryView.SetPadding(0, Dp(8), 0, Dp(8));
            summaryCard.AddView(summaryView);

            var saveButton = CreateButton("保存并应用", SaveRules, true);
            saveButton.LayoutParameters = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MatchParent, Dp(48));
            container.AddView(saveButton);

            var note = new TextView(this)
            {
                Text = "提示：如果“启用自定义规则”开关关闭，保存后不会参与匹配。自定义规则只在 MITM/规则链路或免证书 sidecar 中生效。",
                TextSize = 11,
            };
            note.SetTextColor(ResColor(Resource.Color.text_secondary));
            note.SetPadding(Dp(4), Dp(12), Dp(4), 0);
            container.AddView(note);
        }

        void LoadText()
        {
            if (editor == null) return;
            editor.Text = CustomProxyRules.GetText();
            UpdateSummary();
        }

        void ValidateRules()
        {
            if (editor == null) return;
            if (CustomProxyRules.TryValidate(editor.Text ?? string.Empty, out _, out var error))
            {
                UpdateSummary();
                ToastShow("校验通过");
            }
            else
            {
                ShowTextDialog("校验失败", error ?? "未知错误");
            }
        }

        void SaveRules()
        {
            if (editor == null) return;
            var text = editor.Text ?? string.Empty;
            if (!CustomProxyRules.Save(text, out var rules, out var error))
            {
                ShowTextDialog("保存失败", error ?? "未知错误");
                return;
            }

            ProxyRuleEngine.SetCustom(rules, error);
            UpdateSummary();
            ToastShow($"已保存并应用 {rules.Rules.Count} 条自定义规则");
        }

        void InsertSample()
        {
            if (editor == null) return;
            var dialog = new AlertDialog.Builder(this)
                .SetTitle("插入示例")
                .SetMessage("会替换编辑器内容为示例规则，保存后才会生效。")
                .SetPositiveButton("插入", (_, _) =>
                {
                    editor.Text = CustomProxyRules.SampleJson;
                    UpdateSummary();
                })
                .SetNegativeButton("取消", (_, _) => { })
                .Create();
            dialog.Show();
        }

        void ClearFile()
        {
            var dialog = new AlertDialog.Builder(this)
                .SetTitle("清空自定义规则")
                .SetMessage("会删除自定义规则文件，并立即停止使用这些规则。")
                .SetPositiveButton("清空", (_, _) =>
                {
                    CustomProxyRules.Delete();
                    ProxyRuleEngine.SetCustom(ProxyRuleSet.Empty);
                    if (editor != null) editor.Text = string.Empty;
                    UpdateSummary();
                    ToastShow("已清空自定义规则");
                })
                .SetNegativeButton("取消", (_, _) => { })
                .Create();
            dialog.Show();
        }

        void CopyText()
        {
            if (editor == null) return;
            try
            {
                _ = Xamarin.Essentials.Clipboard.SetTextAsync(editor.Text ?? string.Empty);
                ToastShow("已复制");
            }
            catch (Exception ex)
            {
                ToastShow("复制失败: " + ex.Message);
            }
        }

        void ShowQuickAdd()
        {
            if (editor == null) return;
            if (!CustomProxyRules.TryValidate(editor.Text ?? string.Empty, out var current, out var error))
            {
                ShowTextDialog("当前规则无法解析", error ?? "请先修正现有规则");
                return;
            }

            var layout = new LinearLayout(this) { Orientation = Orientation.Vertical };
            layout.SetPadding(Dp(20), Dp(8), Dp(20), Dp(8));

            var domain = AddDialogInput(layout, "域名（支持 * 通配符）", "example.com");
            var path = AddDialogInput(layout, "路径正则（留空或 .* 表示全部）", ".*");
            var action = AddDialogSpinner(layout, "动作", new[] { "SNI 伪装", "镜像重定向", "第三方反代", "阻断" });
            var value = AddDialogInput(layout, "值（SNI 目标 / 镜像地址 / 反代地址；阻断留空）", "baidu.com");
            var desc = AddDialogInput(layout, "备注（可选）", "自定义规则");
            var presetIps = AddDialogInput(layout, "预置 IP（可选，逗号分隔）", string.Empty);

            var dialog = new AlertDialog.Builder(this)
                .SetTitle("快速添加规则")
                .SetView(layout)
                .SetPositiveButton("添加", (_, _) =>
                {
                    var rule = BuildRule(
                        domain.Text,
                        path.Text,
                        action.SelectedItemPosition,
                        value.Text,
                        desc.Text);
                    if (rule == null)
                    {
                        ToastShow("域名不能为空");
                        return;
                    }

                    var rules = new List<ProxyRule>(current.Rules) { rule };
                    var preset = new Dictionary<string, IReadOnlyList<string>>(current.PresetIps);
                    var ips = SplitIps(presetIps.Text);
                    if (ips.Count > 0)
                    {
                        preset[rule.DomainPattern] = ips;
                    }

                    var combined = new ProxyRuleSet(rules, current.ExcludePatterns, preset);
                    editor.Text = CustomProxyRules.Serialize(combined);
                    UpdateSummary();
                    ToastShow("已添加到编辑器，记得保存");
                })
                .SetNegativeButton("取消", (_, _) => { })
                .Create();
            dialog.Show();
        }

        static ProxyRule? BuildRule(
            string? domain,
            string? path,
            int action,
            string? value,
            string? description)
        {
            if (string.IsNullOrWhiteSpace(domain)) return null;

            var pathPattern = string.IsNullOrWhiteSpace(path) ? null : path.Trim();
            if (string.Equals(pathPattern, ".*", StringComparison.Ordinal)) pathPattern = null;

            return new ProxyRule
            {
                DomainPattern = domain.Trim(),
                PathPattern = pathPattern,
                Group = ProxyRuleGroups.Custom,
                Sni = action == 0 ? value?.Trim() : null,
                Redirect = action == 1 ? value?.Trim() : null,
                Proxy = action == 2 ? value?.Trim() : null,
                Block = action == 3,
                Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            };
        }

        static IReadOnlyList<string> SplitIps(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return Array.Empty<string>();
            return value.Split(new[] { ',', ';', ' ', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .Where(x => x.Length > 0)
                .ToArray();
        }

        void ShowDeleteRule()
        {
            if (editor == null) return;
            if (!CustomProxyRules.TryValidate(editor.Text ?? string.Empty, out var current, out var error))
            {
                ShowTextDialog("当前规则无法解析", error ?? "请先修正现有规则");
                return;
            }

            if (current.Rules.Count == 0)
            {
                ToastShow("没有可删除的规则");
                return;
            }

            var items = current.Rules.Select(DescribeRule).ToArray();
            var dialog = new AlertDialog.Builder(this)
                .SetTitle("选择要删除的规则")
                .SetItems(items, (_, e) =>
                {
                    var rules = new List<ProxyRule>(current.Rules);
                    var removed = rules[e.Which];
                    rules.RemoveAt(e.Which);

                    var preset = new Dictionary<string, IReadOnlyList<string>>(current.PresetIps);
                    if (!rules.Any(x => string.Equals(x.DomainPattern, removed.DomainPattern, StringComparison.OrdinalIgnoreCase)))
                    {
                        preset.Remove(removed.DomainPattern);
                    }

                    var combined = new ProxyRuleSet(rules, current.ExcludePatterns, preset);
                    editor.Text = CustomProxyRules.Serialize(combined);
                    UpdateSummary();
                    ToastShow("已删除，记得保存");
                })
                .SetNegativeButton("取消", (_, _) => { })
                .Create();
            dialog.Show();
        }

        static string DescribeRule(ProxyRule rule)
        {
            var action = rule.Block ? "阻断"
                : !string.IsNullOrEmpty(rule.Sni) ? "SNI " + rule.Sni
                : !string.IsNullOrEmpty(rule.Redirect) ? "镜像 " + rule.Redirect
                : !string.IsNullOrEmpty(rule.Proxy) ? "反代 " + rule.Proxy
                : "其它";

            return $"{rule.DomainPattern}  {rule.PathPattern ?? ".*"}  →  {action}";
        }

        void UpdateSummary()
        {
            if (summaryView == null || editor == null) return;

            if (CustomProxyRules.TryValidate(editor.Text ?? string.Empty, out var rules, out var error))
            {
                var lines = new List<string>
                {
                    $"规则: {rules.Rules.Count} 条，排除: {rules.ExcludePatterns.Count} 条，预置 IP: {rules.PresetIps.Count} 组",
                };
                foreach (var rule in rules.Rules.Take(20))
                {
                    lines.Add("  " + DescribeRule(rule));
                }
                if (rules.Rules.Count > 20) lines.Add($"  … 其余 {rules.Rules.Count - 20} 条");
                summaryView.Text = string.Join(Environment.NewLine, lines);
            }
            else
            {
                summaryView.Text = "解析失败: " + (error ?? "未知错误");
            }
        }

        TextView AddDialogInput(LinearLayout parent, string hint, string defaultValue)
        {
            var title = new TextView(this) { Text = hint, TextSize = 12 };
            title.SetTextColor(ResColor(Resource.Color.text_secondary));
            title.SetPadding(0, Dp(8), 0, 0);
            parent.AddView(title);

            var input = new EditText(this)
            {
                Text = defaultValue,
                TextSize = 13,
            };
            input.SetSingleLine(true);
            input.SetTextColor(ResColor(Resource.Color.text_primary));
            parent.AddView(input);
            return input;
        }

        Spinner AddDialogSpinner(LinearLayout parent, string title, string[] options)
        {
            var view = new TextView(this) { Text = title, TextSize = 12 };
            view.SetTextColor(ResColor(Resource.Color.text_secondary));
            view.SetPadding(0, Dp(8), 0, 0);
            parent.AddView(view);

            var spinner = new Spinner(this);
            var adapter = new ArrayAdapter<string>(this, Android.Resource.Layout.SimpleSpinnerItem, options);
            adapter.SetDropDownViewResource(Android.Resource.Layout.SimpleSpinnerDropDownItem);
            spinner.Adapter = adapter;
            parent.AddView(spinner);
            return spinner;
        }

        LinearLayout AddSection(LinearLayout container, string title, string description)
        {
            var titleView = new TextView(this)
            {
                Text = title,
                TextSize = 16,
                Typeface = Android.Graphics.Typeface.DefaultBold,
            };
            titleView.SetTextColor(ResColor(Resource.Color.text_primary));
            titleView.SetPadding(Dp(4), Dp(20), Dp(4), Dp(2));
            container.AddView(titleView);

            var descView = new TextView(this)
            {
                Text = description,
                TextSize = 12,
            };
            descView.SetTextColor(ResColor(Resource.Color.text_secondary));
            descView.SetPadding(Dp(4), 0, Dp(4), Dp(8));
            container.AddView(descView);

            var card = new LinearLayout(this) { Orientation = Orientation.Vertical };
            var background = new Android.Graphics.Drawables.GradientDrawable();
            background.SetColor(IsNightMode
                ? Android.Graphics.Color.ParseColor("#1E1E1E")
                : Android.Graphics.Color.White);
            background.SetCornerRadius(Dp(12));
            background.SetStroke(Dp(1), IsNightMode
                ? Android.Graphics.Color.ParseColor("#33FFFFFF")
                : Android.Graphics.Color.ParseColor("#1F000000"));
            card.Background = background;
            card.SetPadding(Dp(14), Dp(6), Dp(14), Dp(10));
            container.AddView(card);
            return card;
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

        void ShowTextDialog(string title, string text)
        {
            var view = new TextView(this)
            {
                Text = text,
                TextSize = 11,
                Typeface = Android.Graphics.Typeface.Monospace,
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

        void ToastShow(string message)
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
