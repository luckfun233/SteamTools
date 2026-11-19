using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using Android.Content;
using AndroidX.AppCompat.App;
using System.Application.UI.Activities;
using AndroidApplication = Android.App.Application;
using XEPlatform = Xamarin.Essentials.Platform;

namespace System.Application.Services.Implementation
{
    internal sealed partial class AndroidPlatformServiceImpl : IPlatformService
    {
        static bool IsDarkMode => DarkModeUtil.IsDarkMode(AndroidApplication.Context);

        public bool? IsLightOrDarkTheme => !IsDarkMode;

        public void SetLightOrDarkThemeFollowingSystem(bool enable)
        {
            if (enable)
            {
                AppCompatDelegate.DefaultNightMode = AppCompatDelegate.ModeNightFollowSystem;
            }
            else
            {
                AppCompatDelegate.DefaultNightMode = AppCompatDelegate.ModeNightAutoBattery;
            }
        }

        async ValueTask<bool?> IPlatformService.TrustRootCertificate(string filePath)
        {
            try
            {
                var activity = XEPlatform.CurrentActivity;
                if (activity == null) return false;

                // Android 无法静默信任用户 CA。这里打开内置引导页：
                // 导出 .cer 后跳系统安全设置，由用户手动安装。
                activity.StartActivity(new Intent(activity, typeof(GuideCACertActivity)));
                await Task.CompletedTask;
                return true;
            }
            catch
            {
                return false;
            }
        }

        void IPlatformService.OpenFileByTextReader(string filePath)
        {
            var activity = XEPlatform.CurrentActivity;
            if (filePath.StartsWith(IOPath.AppDataDirectory) || filePath.StartsWith(IOPath.CacheDirectory))
            {
                OpenFileByTextReaderByTextBlockActivity();
                return;
            }
            var result = GoToPlatformPages.OpenFile(
                activity,
                new(filePath),
                MediaTypeNames.TXT);
            if (!result)
            {
                OpenFileByTextReaderByTextBlockActivity();
            }

            void OpenFileByTextReaderByTextBlockActivity()
            {
                TextBlockActivity.StartActivity(activity, new() { FilePath = filePath });
            }
        }
    }
}
