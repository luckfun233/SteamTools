using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Android.Runtime;
using AndroidApplication = Android.App.Application;
using AndroidLog = Android.Util.Log;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 把未处理异常写到应用外部文件目录，便于在无法打开 App 时取日志。
    /// </summary>
    public static class AndroidCrashLogger
    {
        const string TAG = "SteamToolsCrash";

        static bool installed;

        /// <summary>
        /// 最近一次崩溃日志文件，通常位于 Android/data/net.steampp.app/files/last-crash.txt。
        /// </summary>
        public static string? CrashFilePath { get; private set; }

        public static void Install(AndroidApplication app)
        {
            if (installed) return;
            installed = true;

            try
            {
                var dir = app.GetExternalFilesDir(null)?.AbsolutePath ?? app.FilesDir?.AbsolutePath;
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                    CrashFilePath = Path.Combine(dir, "last-crash.txt");
                }
            }
            catch
            {
                // 外部存储不可用时仍然写 Android log
            }

            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                Write("AppDomain", e.ExceptionObject?.ToString());

            AndroidEnvironment.UnhandledExceptionRaiser += (_, e) =>
                Write("AndroidEnvironment", e.Exception?.ToString());

            TaskScheduler.UnobservedTaskException += (_, e) =>
                Write("TaskScheduler", e.Exception?.ToString());

            Write("Install", $"CrashLogger ready: {CrashFilePath}");
        }

        public static void Write(string source, string? detail)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {source}");
                sb.AppendLine($"Device: {Android.OS.Build.Manufacturer} {Android.OS.Build.Model} / API {(int)Android.OS.Build.VERSION.SdkInt}");
                sb.AppendLine(detail ?? "unknown");
                sb.AppendLine();

                var text = sb.ToString();
                AndroidLog.Error(TAG, text);

                if (!string.IsNullOrEmpty(CrashFilePath))
                {
                    File.AppendAllText(CrashFilePath!, text);
                }
            }
            catch
            {
                // 日志本身失败时不能再抛异常
            }
        }
    }
}
