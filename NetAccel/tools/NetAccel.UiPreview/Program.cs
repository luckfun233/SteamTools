using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Threading;
using NetAccel.App;

// 无显示器环境下的界面截图与布局冒烟测试：
// 用 Avalonia.Headless + Skia 渲染真实窗口，逐页截图并检查关键控件尺寸。
var outputDir = args.Length > 0 ? args[0] : "ui-preview";
Directory.CreateDirectory(outputDir);

AppBuilder.Configure<App>()
    .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
    .UseSkia()
    .SetupWithoutStarting();

var window = new MainWindow
{
    Width = 1140,
    Height = 780,
};

window.Show();
Pump();

var tabs = window.FindControl<TabControl>("RootTabs")
           ?? throw new InvalidOperationException("找不到 RootTabs");

var pages = new (string Name, string Control)[]
{
    ("accel", "TabAccel"),
    ("rules", "TabRules"),
    ("lab", "TabLab"),
    ("settings", "TabSettings"),
    ("log", "TabLog"),
};

var failed = false;

foreach (var (name, controlName) in pages)
{
    var tab = window.FindControl<TabItem>(controlName)
              ?? throw new InvalidOperationException("找不到 " + controlName);
    tabs.SelectedItem = tab;
    Pump();

    var file = Path.Combine(outputDir, $"ui-{name}.png");
    var frame = window.CaptureRenderedFrame();
    if (frame == null)
    {
        Console.Error.WriteLine($"[FAIL] {name}: 没有渲染帧");
        failed = true;
        continue;
    }
    frame.Save(file);
    Console.WriteLine($"[OK] {name}: {Path.GetFullPath(file)}");
}

Check(window, "StatusTitle", ref failed);
Check(window, "StartStopButton", ref failed);
Check(window, "SocksAddressText", ref failed);
Check(window, "HttpAddressText", ref failed);
Check(window, "GroupPanel", ref failed);
Check(window, "CustomRulesBox", ref failed);
Check(window, "LabReportBox", ref failed);
Check(window, "LogBox", ref failed);
Check(window, "StrategyCombo", ref failed);

return failed ? 1 : 0;

static void Pump()
{
    Dispatcher.UIThread.RunJobs();
    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
    Dispatcher.UIThread.RunJobs();
}

static void Check(Window window, string name, ref bool failed)
{
    var control = window.FindControl<Control>(name);
    if (control == null)
    {
        Console.Error.WriteLine($"[FAIL] 缺少控件 {name}");
        failed = true;
        return;
    }

    var bounds = control.Bounds;
    var visible = control.IsVisible;
    if (bounds.Width < 1 || bounds.Height < 1)
    {
        Console.Error.WriteLine($"[FAIL] {name} 尺寸异常: {bounds.Width}x{bounds.Height}");
        failed = true;
        return;
    }

    Console.WriteLine($"[OK] {name}: {bounds.Width:0}x{bounds.Height:0} visible={visible}");
}
