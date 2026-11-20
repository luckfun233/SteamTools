using Android.App;
using Android.App.Admin;
using Android.Runtime;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 设备所有者/设备管理员入口。设置设备所有者后可以静默安装用户 CA（仍不是系统 CA）。
    /// </summary>
    [Register("net.steampp.app.SteamToolsDeviceAdminReceiver")]
    [BroadcastReceiver(
        Name = "net.steampp.app.SteamToolsDeviceAdminReceiver",
        Permission = "android.permission.BIND_DEVICE_ADMIN",
        Exported = true,
        Enabled = true)]
    [IntentFilter(new[] { "android.app.action.DEVICE_ADMIN_ENABLED" })]
    [MetaData("android.app.device_admin", Resource = "@xml/device_admin")]
    public sealed class SteamToolsDeviceAdminReceiver : DeviceAdminReceiver
    {
    }
}
