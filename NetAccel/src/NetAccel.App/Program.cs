using Avalonia;
using NetAccel.Core.Models;

namespace NetAccel.App;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // 所有未处理异常都落盘，避免“闪退且没有任何提示”。
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            CrashReporter.Write(e.ExceptionObject as Exception, "AppDomain");
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            CrashReporter.Write(e.Exception, "TaskScheduler");
            e.SetObserved();
        };

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            CrashReporter.Write(ex, "Main");
            Console.Error.WriteLine("NetAccel 启动失败: " + ex.Message);
            Console.Error.WriteLine("崩溃日志: " + AppPaths.CrashLogFile);
        }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}

internal static class CrashReporter
{
    static readonly object sync = new();

    public static void Write(Exception? exception, string source)
    {
        if (exception == null) return;
        try
        {
            lock (sync)
            {
                Directory.CreateDirectory(AppPaths.Home);
                var text = $"""
                    ===== {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} [{source}] =====
                    {exception}
                    """;
                File.AppendAllText(AppPaths.CrashLogFile, text + Environment.NewLine);
            }
        }
        catch
        {
            // 连日志都写不了时只能放弃
        }
    }
}
