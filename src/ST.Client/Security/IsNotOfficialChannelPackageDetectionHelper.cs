using System.Application.Models;
using System.Application.UI.Resx;
using APIConst = System.Application.Services.CloudService.Constants;

namespace System.Application.Security
{
    public static class IsNotOfficialChannelPackageDetectionHelper
    {
        /// <summary>
        /// <see cref="AppSettings.IsOfficialChannelPackage"/>
        /// </summary>
        /// <param name="showMessageBox"></param>
        /// <returns></returns>
        public static bool Check(bool showMessageBox = true)
        {
#if SELF_BUILT_BUILD
            // 自建包不适用于官方渠道校验，直接放行，避免误导性弹窗。
            return true;
#endif
            var value = AppSettings.IsOfficialChannelPackage;
            if (!value)
            {
                static void IsNotOfficialChannelPackageWarning()
                {
                    var text = APIConst.IsNotOfficialChannelPackageWarning;
                    var title = AppResources.Warning;
                    MessageBox.Show(text, title, MessageBox.Button.OK, MessageBox.Image.Warning);
                }
                if (showMessageBox) IsNotOfficialChannelPackageWarning();
            }
            return value;
        }
    }
}