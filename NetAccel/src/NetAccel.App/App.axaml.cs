using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using NetAccel.Core.Models;

namespace NetAccel.App;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        try
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.MainWindow = new MainWindow();
            }
        }
        catch (Exception ex)
        {
            CrashReporter.Write(ex, "OnFrameworkInitializationCompleted");

            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.MainWindow = BuildErrorWindow(ex);
            }
        }

        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>
    /// 启动失败时的兜底窗口。全部用代码构建，避免再次依赖 XAML 资源。
    /// </summary>
    static Window BuildErrorWindow(Exception exception)
    {
        var logPath = AppPaths.CrashLogFile;
        var text = new TextBlock
        {
            Text = "NetAccel 启动失败\n\n" + exception.Message + "\n\n崩溃日志：" + logPath,
            TextWrapping = TextWrapping.Wrap,
            FontSize = 14,
        };

        var panel = new StackPanel
        {
            Spacing = 16,
            Margin = new Thickness(24),
            Children =
            {
                new TextBlock
                {
                    Text = "启动出现异常",
                    FontSize = 22,
                    FontWeight = FontWeight.Bold,
                    Foreground = Brushes.White,
                },
                text,
            },
        };

        return new Window
        {
            Title = "NetAccel - 启动失败",
            Width = 640,
            Height = 320,
            Background = new SolidColorBrush(Color.Parse("#0B0E1A")),
            Content = panel,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
        };
    }
}
