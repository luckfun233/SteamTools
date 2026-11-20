using System.IO;
using Android.App.Admin;
using Android.Content;
using AndroidContent = Android.Content.Context;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// Android 证书安装辅助。
    /// 说明：Android 13 的系统 CA 存储在只读 /system 分区，Shizuku 只有 shell 权限，
    /// 无法写入系统 CA。设备所有者可以通过 DPM 静默安装“用户 CA”（Chrome 信任，
    /// 普通 App 默认不信任）。
    /// </summary>
    public static class AndroidCertificateInstaller
    {
        public const string AdminComponent = "net.steampp.app/.SteamToolsDeviceAdminReceiver";

        public static string ShizukuCommand =>
            $"rish -c \"dpm set-device-owner net.steampp.app/.SteamToolsDeviceAdminReceiver\"";

        public static bool IsDeviceOwner(Context context)
        {
            var dpm = GetDevicePolicyManager(context);
            return dpm != null && dpm.IsDeviceOwnerApp(context.PackageName!);
        }

        public static bool InstallUserCa(Context context, string cerFilePath)
        {
            try
            {
                var dpm = GetDevicePolicyManager(context);
                if (dpm == null || !dpm.IsDeviceOwnerApp(context.PackageName!)) return false;
                if (!File.Exists(cerFilePath)) return false;

                var bytes = File.ReadAllBytes(cerFilePath);
                return dpm.InstallCaCert(null, bytes);
            }
            catch
            {
                return false;
            }
        }

        public static bool RemoveUserCa(Context context, string cerFilePath)
        {
            try
            {
                var dpm = GetDevicePolicyManager(context);
                if (dpm == null || !dpm.IsDeviceOwnerApp(context.PackageName!)) return false;
                if (!File.Exists(cerFilePath)) return false;

                var bytes = File.ReadAllBytes(cerFilePath);
                dpm.UninstallCaCert(null, bytes);
                return true;
            }
            catch
            {
                return false;
            }
        }

        static DevicePolicyManager? GetDevicePolicyManager(Context context)
            => context.GetSystemService(AndroidContent.DevicePolicyService) as DevicePolicyManager;
    }
}
