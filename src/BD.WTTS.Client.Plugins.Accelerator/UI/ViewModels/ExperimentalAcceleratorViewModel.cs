using System.Reactive;

// ReSharper disable once CheckNamespace
namespace BD.WTTS.UI.ViewModels;

/// <summary>
/// 加速设置页中的「实验性加速」区域，对应 <see cref="ExperimentalAcceleratorOptions"/>。
/// </summary>
public sealed class ExperimentalAcceleratorViewModel : ReactiveObject
{
    readonly ExperimentalAcceleratorOptions options = ExperimentalAcceleratorSettings.Current;

    public bool EnableBuiltInGroups
    {
        get => options.EnableBuiltInGroups;
        set
        {
            if (options.EnableBuiltInGroups == value) return;
            options.EnableBuiltInGroups = value;
            SaveAndNotify();
        }
    }

    public bool EnableDevSidecarRules
    {
        get => options.EnableDevSidecarRules;
        set
        {
            if (options.EnableDevSidecarRules == value) return;
            options.EnableDevSidecarRules = value;
            SaveAndNotify();
        }
    }

    public string DevSidecarConfigUrl
    {
        get => options.DevSidecarConfigUrl;
        set
        {
            value ??= string.Empty;
            if (options.DevSidecarConfigUrl == value) return;
            options.DevSidecarConfigUrl = value;
            SaveAndNotify();
        }
    }

    public bool SyncDevSidecarOnStartup
    {
        get => options.SyncDevSidecarOnStartup;
        set
        {
            if (options.SyncDevSidecarOnStartup == value) return;
            options.SyncDevSidecarOnStartup = value;
            SaveAndNotify();
        }
    }

    public string ConfigFilePath => ExperimentalAcceleratorSettings.ConfigFilePath;

    public ReactiveCommand<Unit, Unit> RefreshGroupsCommand { get; }

    public ReactiveCommand<Unit, Unit> OpenConfigFolderCommand { get; }

    public ExperimentalAcceleratorViewModel()
    {
        RefreshGroupsCommand = ReactiveCommand.CreateFromTask(async () =>
        {
            await ProxyService.Current.InitializeAccelerateAsync();
        });

        OpenConfigFolderCommand = ReactiveCommand.Create(() =>
        {
            var dir = Path.GetDirectoryName(ConfigFilePath);
            if (!string.IsNullOrEmpty(dir))
            {
                IPlatformService.Instance.OpenFolder(dir);
            }
        });
    }

    void SaveAndNotify()
    {
        ExperimentalAcceleratorSettings.Save();
        this.RaisePropertyChanged(string.Empty);
    }
}
