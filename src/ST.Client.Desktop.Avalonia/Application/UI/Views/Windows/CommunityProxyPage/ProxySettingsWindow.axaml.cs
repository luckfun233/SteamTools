using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using System.Application.ProxyRules;
using System.Application.UI.ViewModels;
using System.IO;

namespace System.Application.UI.Views.Windows
{
    public class ProxySettingsWindow : FluentWindow<ProxySettingsWindowViewModel>
    {
        public ProxySettingsWindow() : base()
        {
            InitializeComponent();
#if DEBUG
            this.AttachDevTools();
#endif
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        async void OnSyncRulesClick(object? sender, RoutedEventArgs e)
        {
            if (DataContext is not ProxySettingsWindowViewModel vm) return;
            try
            {
                await vm.SyncRulesAsync();
                Toast.Show(vm.RuleStatusText);
            }
            catch (Exception ex)
            {
                Toast.Show(ex.Message);
            }
        }

        void OnEditCustomRulesClick(object? sender, RoutedEventArgs e)
        {
            try
            {
                var path = CustomProxyRules.FilePath;
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                if (!File.Exists(path)) File.WriteAllText(path, CustomProxyRules.SampleJson);

                if (OperatingSystem2.IsLinux())
                {
                    Process2.StartPath("xdg-open", path);
                }
                else if (OperatingSystem2.IsMacOS())
                {
                    Process2.StartPath("open", path);
                }
                else
                {
                    Process2.StartPath("explorer.exe", path);
                }
            }
            catch (Exception ex)
            {
                Toast.Show(ex.Message);
            }
        }
    }
}
