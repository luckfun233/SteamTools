using DynamicData;
using DynamicData.Binding;
using MessagePack;
using ReactiveUI;
using System.Application.Models;
using System.Application.Properties;
using System.Application.ProxyRules;
using System.Application.Services.Implementation;
using System.Application.Settings;
using System.Application.UI;
using System.Application.UI.Resx;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Properties;
using System.Reactive.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable SA1306 // Field names should begin with lower-case letter
#pragma warning disable SA1309 // Field names should not begin with underscore

// ReSharper disable once CheckNamespace
namespace System.Application.Services
{
    public sealed class ProxyService : ReactiveObject, IDisposable
    {
        static ProxyService? mCurrent;

        public static ProxyService Current => mCurrent ?? new();

        readonly IReverseProxyService reverseProxyService = IReverseProxyService.Instance;
        readonly IScriptManager scriptManager = IScriptManager.Instance;
        readonly IHostsFileService hostsFileService = IHostsFileService.Instance;
        readonly IPlatformService platformService = IPlatformService.Instance;

        private ProxyService()
        {
            mCurrent = this;

            ProxyDomains = new SourceList<AccelerateProjectGroupDTO>();
            ProxyScripts = new SourceList<ScriptDTO>();

            ProxyDomains
                .Connect()
                .ObserveOn(RxApp.MainThreadScheduler)
                .Sort(SortExpressionComparer<AccelerateProjectGroupDTO>.Ascending(x => x.Order).ThenBy(x => x.Name))
                .Bind(out _ProxyDomainsList)
                .Subscribe(_ => SelectGroup = ProxyDomains.Items.FirstOrDefault());

            this.WhenValueChanged(x => x.ProxyStatus, false)
                .Subscribe(async x =>
                {
                    if (x)
                    {
                        reverseProxyService.ProxyDomains = EnableProxyDomains;
                        reverseProxyService.IsEnableScript = ProxySettings.IsEnableScript.Value;
                        reverseProxyService.IsCertificateLessMode = ProxySettings.IsCertificateLessMode.Value;
                        reverseProxyService.OnlyEnableProxyScript = ProxySettings.OnlyEnableProxyScript.Value;

                        if (reverseProxyService.IsEnableScript)
                        {
                            await EnableProxyScripts.ContinueWith(e =>
                            {
                                reverseProxyService.Scripts = e.Result?.ToImmutableArray();
                            });
                        }

                        if (IApplication.IsDesktopPlatform)
                        {
#pragma warning disable CA1416 // 验证平台兼容性
                            reverseProxyService.IsOnlyWorkSteamBrowser = ProxySettings.IsOnlyWorkSteamBrowser.Value;
                            reverseProxyService.ProxyMode = ProxySettings.ProxyModeValue;
                            reverseProxyService.IsProxyGOG = ProxySettings.IsProxyGOG.Value;
#pragma warning restore CA1416 // 验证平台兼容性
                        }
                        else
                        {
                            reverseProxyService.ProxyMode = ProxyMode.System;
                        }

                        reverseProxyService.ProxyIp = IPAddress2.TryParse(ProxySettings.SystemProxyIp.Value, out var ip) ? ip : IPAddress.Any;

                        // macOS\Linux 上目前因权限问题仅支持 0.0.0.0(IPAddress.Any)
                        if ((OperatingSystem2.IsMacOS() || OperatingSystem2.IsLinux()) && IPAddress.IsLoopback(IReverseProxyService.Instance.ProxyIp))
                        {
                            reverseProxyService.ProxyIp = IPAddress.Any;
                        }

                        // Android VPN 模式使用 tun2socks
                        reverseProxyService.Socks5ProxyEnable = ProxySettings.Socks5ProxyEnable.Value || (OperatingSystem2.IsAndroid() && ProxySettings.ProxyModeValue == ProxyMode.VPN);
                        reverseProxyService.Socks5ProxyPortId = ProxySettings.Socks5ProxyPortId.Value;
                        if (!ModelValidatorProvider.IsPortId(reverseProxyService.Socks5ProxyPortId)) reverseProxyService.Socks5ProxyPortId = ProxySettings.DefaultSocks5ProxyPortId;

                        //reverseProxyService.HostProxyPortId = ProxySettings.HostProxyPortId;
                        reverseProxyService.TwoLevelAgentEnable = ProxySettings.TwoLevelAgentEnable.Value;

                        reverseProxyService.TwoLevelAgentProxyType = (EExternalProxyType)ProxySettings.TwoLevelAgentProxyType.Value;
                        if (!reverseProxyService.TwoLevelAgentProxyType.IsDefined()) reverseProxyService.TwoLevelAgentProxyType = IReverseProxyService.DefaultTwoLevelAgentProxyType;

                        reverseProxyService.TwoLevelAgentIp = IPAddress2.TryParse(ProxySettings.TwoLevelAgentIp.Value, out var ip_t) ? ip_t.ToString() : IPAddress.Loopback.ToString();
                        reverseProxyService.TwoLevelAgentPortId = ProxySettings.TwoLevelAgentPortId.Value;
                        if (!ModelValidatorProvider.IsPortId(reverseProxyService.TwoLevelAgentPortId)) reverseProxyService.TwoLevelAgentPortId = ProxySettings.DefaultTwoLevelAgentPortId;
                        reverseProxyService.TwoLevelAgentUserName = ProxySettings.TwoLevelAgentUserName.Value;
                        reverseProxyService.TwoLevelAgentPassword = ProxySettings.TwoLevelAgentPassword.Value;

                        reverseProxyService.ProxyDNS = IPAddress2.TryParse(ProxySettings.ProxyMasterDns.Value, out var dns) ? dns : null;
                        reverseProxyService.EnableHttpProxyToHttps = ProxySettings.EnableHttpProxyToHttps.Value;

                        this.RaisePropertyChanged(nameof(EnableProxyDomains));
                        this.RaisePropertyChanged(nameof(EnableProxyScripts));

                        if (reverseProxyService.ProxyMode == ProxyMode.Hosts)
                        {
                            const ushort httpsPort = 443;
                            var inUse = reverseProxyService.PortInUse(httpsPort);
                            if (inUse)
                            {
                                string? error_CommunityFix_StartProxyFaild443 = null;
                                if (OperatingSystem2.IsWindows())
                                {
#pragma warning disable CA1416 // 验证平台兼容性
                                    var p = SocketHelper.GetProcessByTcpPort(httpsPort);
#pragma warning restore CA1416 // 验证平台兼容性
                                    if (p != null)
                                    {
                                        error_CommunityFix_StartProxyFaild443 = AppResources.CommunityFix_StartProxyFaild443___.Format(httpsPort, p.ProcessName, p.Id);
                                    }
                                }
                                error_CommunityFix_StartProxyFaild443 ??= AppResources.CommunityFix_StartProxyFaild443_.Format(httpsPort);
                                if (OperatingSystem2.IsLinux())
                                {
                                    Browser2.Open(string.Format(UrlConstants.OfficialWebsite_UnixHostAccess_, WebUtility.UrlEncode(IApplication.ProgramPath)));
                                }
                                Toast.Show(error_CommunityFix_StartProxyFaild443);
                                return;
                            }
                        }
                        else if (reverseProxyService.ProxyMode == ProxyMode.System)
                        {
                            var proxyip = reverseProxyService.ProxyIp;
                            if (OperatingSystem2.IsWindows() && IReverseProxyService.Instance.ProxyIp.Equals(IPAddress.Any))
                            {
                                proxyip = IPAddress.Loopback;
                            }
                            if (!platformService.SetAsSystemProxy(true, proxyip, reverseProxyService.ProxyPort))
                            {
                                Toast.Show("系统代理开启失败");
                                return;
                            }
                        }
                        else if (reverseProxyService.ProxyMode == ProxyMode.PAC)
                        {
                            var proxyip = reverseProxyService.ProxyIp;
                            if (OperatingSystem2.IsWindows() && IReverseProxyService.Instance.ProxyIp.Equals(IPAddress.Any))
                            {
                                proxyip = IPAddress.Loopback;
                            }
                            if (!platformService.SetAsSystemPACProxy(true, $"http://{proxyip}:{reverseProxyService.ProxyPort}/pac"))
                            {
                                Toast.Show("PAC代理开启失败");
                                return;
                            }
                        }

                        var isRun = await reverseProxyService.StartProxy();

                        if (isRun)
                        {
                            if (reverseProxyService.ProxyMode == ProxyMode.Hosts)
                            {
                                if (reverseProxyService.ProxyDomains.Any_Nullable())
                                {
                                    var localhost = IPAddress.Any.Equals(reverseProxyService.ProxyIp) ? IPAddress.Loopback.ToString() : reverseProxyService.ProxyIp.ToString();

                                    var hosts = reverseProxyService.ProxyDomains!.SelectMany(s =>
                                    {
                                        if (s == null) return default!;

                                        return s.HostsArray.Select(host =>
                                        {
                                            if (host.Contains(' '))
                                            {
                                                var h = host.Split(' ');
                                                return KeyValuePair.Create(h[1], h[0]);
                                            }
                                            return KeyValuePair.Create(host, localhost);
                                        });
                                    }).ToDictionaryIgnoreRepeat(x => x.Key, y => y.Value);

                                    if (reverseProxyService.IsEnableScript)
                                    {
                                        hosts.TryAdd(IReverseProxyService.LocalDomain, localhost);
                                    }

                                    var r = hostsFileService.UpdateHosts(hosts);

                                    if (r.ResultType != OperationResultType.Success)
                                    {
                                        if (OperatingSystem2.IsMacOS())
                                        {
                                            Browser2.Open(UrlConstants.OfficialWebsite_UnixHostAccess);
                                            //platformService.RunShell($" \\cp \"{Path.Combine(IOPath.CacheDirectory, "hosts")}\" \"{platformService.HostsFilePath}\"");
                                        }
                                        Toast.Show(AppResources.OperationHostsError_.Format(r.Message));
                                        await reverseProxyService.StopProxy();
                                        return;
                                    }
                                }
                            }
                            _StartAccelerateTime = DateTimeOffset.Now;
                            StartTimer();
                            Toast.Show(AppResources.CommunityFix_StartProxySuccess);
                        }
                        else
                        {
                            ProxyStatus = false;
                            MessageBox.Show(AppResources.CommunityFix_StartProxyFaild);
                        }
                    }
                    else
                    {
                        await reverseProxyService.StopProxy();
                        StopTimer();
                        reverseProxyService.Scripts = null;
                        void OnStopRemoveHostsByTag()
                        {
                            if (!IApplication.IsDesktopPlatform) return;
                            var needClear = hostsFileService.ContainsHostsByTag();
                            if (needClear)
                            {
                                var r = hostsFileService.RemoveHostsByTag();

                                if (r.ResultType != OperationResultType.Success)
                                {
                                    Toast.Show(AppResources.OperationHostsError_.Format(r.Message));

                                    if (OperatingSystem2.IsMacOS() || (OperatingSystem2.IsLinux() && !platformService.IsAdministrator))
                                    {
                                        Browser2.Open(UrlConstants.OfficialWebsite_UnixHostAccess);
                                    }
                                    //return;
                                    //if (OperatingSystem2.IsMacOS() && !ProxySettings.EnableWindowsProxy.Value)
                                    //{
                                    //    //platformService.RunShell($" \\cp \"{Path.Combine(IOPath.CacheDirectory, "hosts")}\" \"{platformService.HostsFilePath}\"", true);
                                    //}
                                }
                            }
                        }

                        if (reverseProxyService.ProxyMode == ProxyMode.Hosts)
                        {
                            OnStopRemoveHostsByTag();
                        }
                        else if (reverseProxyService.ProxyMode == ProxyMode.System)
                        {
                            platformService.SetAsSystemProxy(false);
                        }
                        else if (reverseProxyService.ProxyMode == ProxyMode.PAC)
                        {
                            platformService.SetAsSystemPACProxy(false);
                        }
                    }
                });
        }

        public SourceList<AccelerateProjectGroupDTO> ProxyDomains { get; }

        private readonly ReadOnlyObservableCollection<AccelerateProjectGroupDTO> _ProxyDomainsList;

        public ReadOnlyObservableCollection<AccelerateProjectGroupDTO> ProxyDomainsList => _ProxyDomainsList;

        bool _IsLoading;

        public bool IsLoading
        {
            get => _IsLoading;
            set => this.RaiseAndSetIfChanged(ref _IsLoading, value);
        }

        private AccelerateProjectGroupDTO? _SelectGroup;

        public AccelerateProjectGroupDTO? SelectGroup
        {
            get => _SelectGroup;
            set => this.RaiseAndSetIfChanged(ref _SelectGroup, value);
        }

        public SourceList<ScriptDTO> ProxyScripts { get; }

        public IEnumerable<AccelerateProjectDTO>? GetEnableProxyDomains()
        {
            if (!ProxyDomains.Items.Any_Nullable())
                return null;
            var data = ProxyDomains.Items
                .Where(x => x.Items != null)
                .SelectMany(s => s.Items!.Where(w => w.Enable));
            //return data.Concat(data.SelectMany(s => GetProxyDomainsItems(s)));
            return data;
        }

        public IReadOnlyCollection<AccelerateProjectDTO>? EnableProxyDomains => GetEnableProxyDomains()?.ToArray();

        //static IEnumerable<AccelerateProjectDTO>? GetProxyDomainsItems(AccelerateProjectDTO accelerates)
        //{
        //    return accelerates.Items.Where(w => w.Enable).SelectMany(GetProxyDomainsItems);
        //}

        static void EnableProxyDomainsItems(AccelerateProjectDTO accelerates)
        {
            if (accelerates.Items != null)
            {
                foreach (var item in accelerates.Items)
                {
                    item.Enable = accelerates.Enable;
                    EnableProxyDomainsItems(item);
                }
            }
        }

        public IEnumerable<ScriptDTO>? GetEnableProxyScripts()
        {
            //if (!IsEnableScript)
            //return null;
            if (!ProxyScripts.Items.Any_Nullable())
                return null;
            return ProxyScripts.Items!.Where(w => w.Enable).OrderBy(x => x.Order);
        }

        public Task<IEnumerable<ScriptDTO>?> EnableProxyScripts => scriptManager.LoadingScriptContent(GetEnableProxyScripts());

        private DateTimeOffset _StartAccelerateTime;

        private TimeSpan _AccelerateTime;

        public TimeSpan AccelerateTime
        {
            get => _AccelerateTime;
            set => this.RaiseAndSetIfChanged(ref _AccelerateTime, value);
        }

        public bool IsEnableScript
        {
            get => ProxySettings.IsEnableScript.Value;
            set
            {
                ProxySettings.IsEnableScript.Value = value;
                reverseProxyService.IsEnableScript = value;
                this.RaisePropertyChanged();
                this.RaisePropertyChanged(nameof(EnableProxyScripts));
            }
        }

        public bool IsOnlyWorkSteamBrowser
        {
            get
            {
                if (OperatingSystem2.IsAndroid() || OperatingSystem2.IsIOS()) return false;
#pragma warning disable CA1416 // 验证平台兼容性
                return ProxySettings.IsOnlyWorkSteamBrowser.Value;
#pragma warning restore CA1416 // 验证平台兼容性
            }

            set
            {
                if (OperatingSystem2.IsAndroid() || OperatingSystem2.IsIOS()) return;
#pragma warning disable CA1416 // 验证平台兼容性
                if (ProxySettings.IsOnlyWorkSteamBrowser.Value != value)
                {
                    ProxySettings.IsOnlyWorkSteamBrowser.Value = value;
                    reverseProxyService.IsOnlyWorkSteamBrowser = value;
                    this.RaisePropertyChanged();
                }
#pragma warning restore CA1416 // 验证平台兼容性
            }
        }

        #region HOSTS_PROXY_RUNNING_STATUS

        //const string KEY_HOSTS_PROXY_RUNNING_STATUS = "KEY_HOSTS_PROXY_RUNNING_STATUS";
        //static async void SaveHostsProxyStatus(bool value)
        //{
        //    await ISecureStorage.Instance.SetAsync<bool>(KEY_HOSTS_PROXY_RUNNING_STATUS, value);
        //}

        //public static async Task<bool> GetHostsProxyStatusAsync()
        //{
        //    var r = await ISecureStorage.Instance.GetAsync<bool>(KEY_HOSTS_PROXY_RUNNING_STATUS);
        //    return r;
        //}

        #endregion

        #region 代理状态启动退出
        private bool _ProxyStatus;

        public bool ProxyStatus
        {
            get { return _ProxyStatus; }
            set => this.RaiseAndSetIfChanged(ref _ProxyStatus, value);
        }
        #endregion

        bool IsProgramStartupRunProxy()
        {
            if (IApplication.Instance.ProgramHost is
                IApplication.IDesktopStartupArgs desktopStartupArgs &&
                desktopStartupArgs.IsProxy &&
                    (desktopStartupArgs.ProxyStatus == EOnOff.On ||
                    desktopStartupArgs.ProxyStatus == EOnOff.Toggle))
                return true;
            if (ProxySettings.ProgramStartupRunProxy.Value) return true;
            return false;
        }

        public async Task Initialize()
        {
            //reverseProxyService.StopProxy();
            try
            {
                await InitializeAccelerate();
            }
            catch (Exception ex)
            {
                Log.Error(nameof(ProxyService), ex, "初始化加速项目失败");
            }

            try
            {
                await InitializeScript();
            }
            catch (Exception ex)
            {
                // 脚本服务依赖云端接口，未登录/离线时不能影响加速页和本地规则。
                Log.Warn(nameof(ProxyService), "初始化脚本数据失败", ex);
            }

            if (IsProgramStartupRunProxy())
            {
                if (platformService.UsePlatformForegroundService)
                {
                    await platformService.StartOrStopForegroundServiceAsync(nameof(ProxyService), true);
                }
                else
                {
                    ProxyStatus = true;
                }
            }
        }

        /// <summary>
        /// 是否使用 <see cref="IHttpService"/> 加载确认物品图片 <see cref="Stream"/>
        /// </summary>
        static bool IsLoadImage
        {
            get
            {
                // 此页面当前使用 Square.Picasso 库加载图片
                if (OperatingSystem2.IsAndroid()) return false;
                return true;
            }
        }

        public Task InitializeAccelerate()
        {
            // 旧版本的 SNI 默认策略是“SNI 边界”，对能重组 TCP 的 DPI 无效。
            // 这里只做一次迁移，之后用户在设置页的选择会被保留。
            ProxySettings.MigrateExperimentalDefaults();

            // 加速规则统一来自 DevSidecar 远程配置 / 本地缓存。
            // 不再请求 Steam++ 云端的 Accelerate 接口：未登录或服务端返回异常格式时，
            // 会反复弹出 “客户端错误 1006 - Failed to deserialize ...”，加速页也会空白。
            if (ProxySettings.EnableDevSidecarRules.Value)
            {
                ProxyRuleEngine.LoadFromCache();
                if (ProxySettings.SyncDevSidecarConfigOnStartup.Value)
                {
                    _ = SyncDevSidecarInBackgroundAsync();
                }
            }
            else
            {
                ProxyRuleEngine.Clear();
            }

            // 自定义规则与远程规则合并，远程规则关闭时也要加载。
            ProxyRuleEngine.ReloadCustom();

            // 提前启动免证书 SNI sidecar 与本地 DNS 代理，避免 VPN/tun2socks 启动时端口还没就绪。
            SniSidecarService.Start();
            DnsProxyService.Start();
            StartDevSidecarAutoSync();
            return Task.CompletedTask;
        }

        public static bool IsChangeSupportProxyServicesStatus { get; set; }

        Timer? devSidecarSyncTimer;

        async Task SyncDevSidecarInBackgroundAsync()
        {
            try
            {
                await ProxyRuleEngine.ReloadAsync().ConfigureAwait(false);
                ProxyDiagnostics.Info("Rules", "启动后台同步 DevSidecar 配置完成");
            }
            catch (Exception ex)
            {
                ProxyDiagnostics.Warn("Rules", $"启动后台同步 DevSidecar 配置失败: {ex.Message}");
            }
        }

        void StartDevSidecarAutoSync()
        {
            devSidecarSyncTimer?.Dispose();
            devSidecarSyncTimer = null;

            var hours = ProxySettings.DevSidecarAutoSyncHours.Value;
            if (hours <= 0 || !ProxySettings.EnableDevSidecarRules.Value) return;

            var interval = TimeSpan.FromHours(Math.Max(1, Math.Min(168, hours)));
            devSidecarSyncTimer = new Timer(_ =>
            {
                if (!ProxySettings.EnableDevSidecarRules.Value) return;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await ProxyRuleEngine.ReloadAsync().ConfigureAwait(false);
                        ProxyDiagnostics.Info("Rules", "后台自动同步 DevSidecar 配置完成");
                    }
                    catch (Exception ex)
                    {
                        ProxyDiagnostics.Warn("Rules", $"后台自动同步 DevSidecar 配置失败: {ex.Message}");
                    }
                });
            }, null, interval, interval);
        }

        private Timer? timer;

        public void StartTimer()
        {
            if (timer == null)
            {
                timer = new Timer(_ => AccelerateTime = DateTimeOffset.Now - _StartAccelerateTime, nameof(AccelerateTime), 0, 1000);
            }
        }

        public void StopTimer()
        {
            if (timer != null)
            {
                timer.Dispose();
                timer = null;
            }
        }

        public static void OnExitRestoreHosts()
        {
            var s = DI.Get_Nullable<IHostsFileService>();
            if (s != null)
            {
                var needClear = s.ContainsHostsByTag();
                if (needClear)
                {
                    s.OnExitRestoreHosts();
                }
            }
        }

        #region 脚本相关

        /// <summary>
        /// 初始化脚本数据
        /// </summary>
        /// <returns></returns>
        public async Task InitializeScript()
        {
            #region 加载脚本数据

            var scriptList = await scriptManager.GetAllScriptAsync();

            ProxyScripts.AddRange(scriptList);

            //拉取 GM.js
            await BasicsInfoAsync();
            reverseProxyService.IsEnableScript = IsEnableScript;

            this.WhenAnyValue(v => v.ProxyScripts)
                  .Subscribe(script => script?
                  .Connect()
                  .AutoRefresh(x => x.Enable)
                  .WhenPropertyChanged(x => x.Enable, false)
                  .Subscribe(async item =>
                  {
                      item.Sender.Enable = item.Value;
                      await scriptManager.SaveEnableScript(item.Sender);
                      //ProxySettings.ScriptsStatus.Value = EnableProxyScripts?.Where(w => w?.LocalId > 0).Select(k => k.LocalId).ToImmutableHashSet();
                      //ProxySettings.ScriptsStatus.Value = ProxyScripts.Items.Where(x => x?.LocalId > 0).Select(k => k.LocalId).ToImmutableHashSet();
                      if (reverseProxyService.ProxyRunning)
                      {

                          await EnableProxyScripts.ContinueWith(e =>
                          {
                              reverseProxyService.Scripts = e.Result?.ToImmutableArray();
                          });
                          this.RaisePropertyChanged(nameof(EnableProxyScripts));
                      }
                  }));
            #endregion
        }

        /// <summary>
        /// 找不到 GM.js 下载，有多个删除全部重新下载。
        /// </summary>
        public async Task BasicsInfoAsync()
        {
            var basicsItems = ProxyScripts.Items.Where(x => x.Id == Guid.Parse("00000000-0000-0000-0000-000000000001")).ToArray();
            var count = basicsItems.Length;
            if (count == 1)
                return;
            else if (count > 1)
            {
                foreach (var item in basicsItems)
                {
                    await scriptManager.DeleteScriptAsync(item);
                    ProxyScripts.Remove(item);
                }
            }
            var basicsInfo = await ICloudServiceClient.Instance.Script.Basics(AppResources.Script_UpdateError);
            if (basicsInfo.Code == ApiResponseCode.OK && basicsInfo.Content != null)
            {
                var jspath = await scriptManager.DownloadScriptAsync(basicsInfo.Content.UpdateLink);
                if (jspath.IsSuccess)
                {
                    var build = await scriptManager.AddScriptAsync(jspath.Content!, build: false, order: 1, deleteFile: true, pid: basicsInfo.Content.Id, ignoreCache: true);
                    if (build.IsSuccess)
                    {
                        if (build.Content != null)
                        {
                            build.Content.IsBasics = true;
                            ProxyScripts.Insert(0, build.Content);
                        }
                    }
                    else
                        Toast.Show(build.Message);
                }
                else
                    Toast.Show(jspath.GetMessageByFormat(AppResources.Download_ScriptError_));
            }
        }

        public async Task AddNewScript(string filename)
        {
            var fileInfo = new FileInfo(filename);
            if (fileInfo.Exists)
            {
                ScriptDTO.TryParse(filename, out ScriptDTO? info);
                if (info != null)
                {
                    var scriptItem = ProxyScripts.Items.FirstOrDefault(x => x.Name == info.Name);
                    if (scriptItem != null)
                    {
                        var result = MessageBox.ShowAsync(AppResources.Script_ReplaceTips, button: MessageBox.Button.OKCancel).ContinueWith(async (s) =>
                         {
                             if (s.Result == MessageBox.Result.OK)
                             {
                                 await AddNewScript(fileInfo, info, scriptItem);
                             }
                         });
                    }
                    else
                    {
                        await AddNewScript(fileInfo, info);
                    }
                }
                else
                {
                    await AddNewScript(fileInfo, info);
                }
            }
            else
            {
                var msg = AppResources.Script_FileError.Format(filename); // $"文件不存在:{filePath}";
                Toast.Show(msg);
            }
        }

        public async Task AddNewScript(FileInfo fileInfo, ScriptDTO? info, ScriptDTO? oldInfo = null)
        {
            IsLoading = true;
            bool isbuild = true;
            int order = 10;
            if (oldInfo != null)
            {
                isbuild = oldInfo.IsBuild;
                order = oldInfo.Order;
            }
            var item = await scriptManager.AddScriptAsync(fileInfo, info, oldInfo, build: isbuild, order: order);
            if (item.IsSuccess)
            {
                if (item.Content != null)
                {
                    if (oldInfo == null)
                    {
                        ProxyScripts.Add(item.Content);
                    }
                    else
                    {
                        ProxyScripts.Replace(oldInfo, item.Content);
                    }
                }
            }
            IsLoading = false;
            Toast.Show(item.Message);
            RefreshScript();
        }

        /// <summary>
        /// 刷新脚本列表
        /// </summary>
        public async void RefreshScript()
        {
            var scriptList = await scriptManager.GetAllScriptAsync();
            ProxyScripts.Clear();
            ProxyScripts.AddRange(scriptList);

            CheckScriptUpdate();
        }

        /// <summary>
        /// 下载或更新JS 直接替换或新增进列表不需要刷新
        /// </summary>
        /// <param name="model"></param>
        public async void DownloadScript(ScriptDTO model)
        {
            model.IsLoading = true;
            var jspath = await scriptManager.DownloadScriptAsync(model.UpdateLink);
            if (jspath.IsSuccess)
            {
                var build = await scriptManager.AddScriptAsync(jspath.Content!, model, build: model.IsBuild, order: model.Order, deleteFile: true, pid: model.Id);
                if (build.IsSuccess)
                {
                    if (build.Content != null)
                    {
                        model.IsUpdate = false;
                        model.IsExist = true;
                        build.Content.IsUpdate = false;
                        build.Content.IsExist = true;
                        var basicsItem = Current.ProxyScripts.Items.IndexOf(model);
                        if (basicsItem > -1)
                        {
                            ProxyScripts.ReplaceAt(basicsItem, build.Content);
                        }
                        else
                        {
                            ProxyScripts.Add(build.Content);
                        }
                        Toast.Show(AppResources.Download_ScriptOk);
                    }
                }
                else
                {
                    Toast.Show(build.Message);
                }
            }
            else
            {
                Toast.Show(jspath.GetMessageByFormat(AppResources.Download_ScriptError_));
            }
            model.IsLoading = false;
        }

        /// <summary>
        /// 检查 JS 更新
        /// </summary>
        public async void CheckScriptUpdate()
        {
            var items = ProxyScripts.Items.Where(x => x.Id.HasValue).Select(x => x.Id!.Value).ToList();
            var client = ICloudServiceClient.Instance.Script;
            var response = await client.ScriptUpdateInfo(items, AppResources.Script_UpdateError);
            if (response.Code == ApiResponseCode.OK && response.Content != null)
            {
                foreach (var item in ProxyScripts.Items)
                {
                    var newItem = response.Content.FirstOrDefault(x => x.Id == item.Id);
                    if (newItem != null && item.Version != newItem.Version)
                    {
                        item.NewVersion = newItem.Version;
                        item.UpdateLink = newItem.UpdateLink;
                        item.IsUpdate = true;
                        ProxyScripts.Replace(item, item);
                    }
                }
            }
        }
        #endregion

        public async void FixNetwork()
        {
            OnExitRestoreHosts();

            if (OperatingSystem2.IsWindows())
            {
                await reverseProxyService.StopProxy();
                platformService.SetAsSystemProxy(false);
                platformService.SetAsSystemPACProxy(false);
                Process.Start("cmd.exe", "netsh winsock reset");
            }

            Toast.Show(AppResources.FixNetworkComplete);
        }

        public async void Dispose()
        {
            await Exit();
        }

        public async Task Exit()
        {
            if (ProxyStatus)
            {
                await reverseProxyService.StopProxy();
                if (reverseProxyService.ProxyMode == ProxyMode.Hosts)
                {
                    OnExitRestoreHosts();
                }
                else if (reverseProxyService.ProxyMode == ProxyMode.System)
                {
                    platformService.SetAsSystemProxy(false);
                }
                else if (reverseProxyService.ProxyMode == ProxyMode.PAC)
                {
                    platformService.SetAsSystemPACProxy(false);
                }
            }
            reverseProxyService.Dispose();
            SniSidecarService.Stop();
            DnsProxyService.Stop();
            devSidecarSyncTimer?.Dispose();
            devSidecarSyncTimer = null;
        }

        public IPAddress ProxyIp => reverseProxyService.ProxyIp;

        public int ProxyPort => reverseProxyService.ProxyPort;

        public int Socks5ProxyPortId => reverseProxyService.Socks5ProxyPortId;
    }
}
#pragma warning restore SA1309 // Field names should not begin with underscore
#pragma warning restore SA1306 // Field names should begin with lower-case letter