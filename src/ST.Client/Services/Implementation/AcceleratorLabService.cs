using System;
using System.Application.ProxyRules;
using System.Application.Settings;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.Services.Implementation
{
    public sealed class LabTestResult
    {
        public LabTestResult(string name, bool success, long elapsedMs, string detail, bool informational = false)
        {
            Name = name;
            Success = success;
            ElapsedMs = elapsedMs;
            Detail = detail;
            Informational = informational;
        }

        public string Name { get; }

        public bool Success { get; }

        public long ElapsedMs { get; }

        public string Detail { get; }

        public bool Informational { get; }

        public string ToLine()
        {
            var status = Informational ? "INFO" : Success ? "PASS" : "FAIL";
            return $"[{status}] {Name} ({ElapsedMs}ms) {Detail}";
        }
    }

    /// <summary>
    /// Android 加速实验室：把只能在真机上验证的项目集中到一次运行里。
    /// 只做连通性/配置检查，不修改代理状态。
    /// </summary>
    public static class AcceleratorLabService
    {
        public const string DefaultHost = "github.com";

        public static async Task<IReadOnlyList<LabTestResult>> RunAllAsync(
            string host,
            string deviceInfo,
            Func<CancellationToken, Task<LabTestResult>>? proxyTest = null,
            CancellationToken cancellationToken = default)
        {
            host = string.IsNullOrWhiteSpace(host) ? DefaultHost : host.Trim();
            var results = new List<LabTestResult>();

            results.Add(CheckRules());
            results.Add(CheckSettings());
            results.Add(await CheckSystemDnsAsync(host, cancellationToken).ConfigureAwait(false));
            results.Add(await CheckDohAsync(host, cancellationToken).ConfigureAwait(false));
            results.Add(await CheckTcpAsync(host, 443, cancellationToken).ConfigureAwait(false));

            var direct = await SniConnectivityTester.ProbeDirectAsync(
                host, 443, 8, cancellationToken).ConfigureAwait(false);
            results.Add(new LabTestResult(
                "直连 TLS 握手",
                direct.Success,
                direct.ElapsedMs,
                direct.Success ? "成功" : direct.Error ?? "失败"));

            var wasRunning = SniSidecarService.IsRunning;
            if (!wasRunning) SniSidecarService.Start(force: true);
            if (SniSidecarService.IsRunning)
            {
                var viaSidecar = await SniConnectivityTester.ProbeViaSidecarAsync(
                    host, 443, SniSidecarService.ActivePort, 8, cancellationToken).ConfigureAwait(false);
                results.Add(new LabTestResult(
                    "Sidecar TLS 握手",
                    viaSidecar.Success,
                    viaSidecar.ElapsedMs,
                    viaSidecar.Success ? $"成功（策略 {SniConnectivityTester.GetStrategyName(ProxySettings.SniFragmentStrategy.Value)}）" : viaSidecar.Error ?? "失败"));
            }
            else
            {
                results.Add(new LabTestResult("Sidecar TLS 握手", false, 0, "本地 sidecar 未启动，可能端口被占用"));
            }
            if (!wasRunning) SniSidecarService.Stop();

            if (proxyTest != null)
            {
                try
                {
                    results.Add(await proxyTest(cancellationToken).ConfigureAwait(false));
                }
                catch (Exception ex)
                {
                    results.Add(new LabTestResult("Titanium 代理 HTTP", false, 0, ex.Message));
                }
            }

            results.Add(await CheckUdpAsync(host, cancellationToken).ConfigureAwait(false));
            results.Add(CheckCertificate());
            results.Add(CheckDevice(deviceInfo));

            return results;
        }

        static LabTestResult CheckRules()
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var current = ProxyRuleEngine.Current;
                var customActive = ProxySettings.EnableCustomRules.Value ? ProxyRuleEngine.CustomRuleCount : 0;
                var remoteActive = Math.Max(0, current.Rules.Count - customActive);
                var detail =
                    $"自定义 {ProxyRuleEngine.CustomRuleCount} 条，远程启用 {remoteActive} 条，" +
                    $"排除 {current.ExcludePatterns.Count} 条，预置 IP {current.PresetIps.Count} 组";
                if (!string.IsNullOrEmpty(ProxyRuleEngine.LastCustomError))
                {
                    detail += $"；自定义规则错误: {ProxyRuleEngine.LastCustomError}";
                }
                return new LabTestResult(
                    "规则集",
                    current.Rules.Count > 0 || current.PresetIps.Count > 0,
                    sw.ElapsedMilliseconds,
                    detail,
                    informational: current.Rules.Count == 0);
            }
            catch (Exception ex)
            {
                return new LabTestResult("规则集", false, sw.ElapsedMilliseconds, ex.Message);
            }
        }

        static LabTestResult CheckSettings()
        {
            var detail =
                $"模式={ProxySettings.ProxyModeValue}，免证书={ProxySettings.IsCertificateLessMode.Value}，" +
                $"SNI 分片={ProxySettings.EnableSniFragment.Value}，策略={SniConnectivityTester.GetStrategyName(ProxySettings.SniFragmentStrategy.Value)}，" +
                $"DoH={ProxySettings.EnableDoh.Value}，中继={ProxySettings.EnableSniUpstreamRelay.Value}";
            return new LabTestResult("当前设置", true, 0, detail, informational: true);
        }

        static async Task<LabTestResult> CheckSystemDnsAsync(string host, CancellationToken cancellationToken)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var task = Dns.GetHostAddressesAsync(host);
                var completed = await Task.WhenAny(task, Task.Delay(6000, cancellationToken)).ConfigureAwait(false);
                if (completed != task)
                {
                    return new LabTestResult("系统 DNS", false, sw.ElapsedMilliseconds, "解析超时");
                }

                var addresses = await task.ConfigureAwait(false);
                var text = string.Join(", ", addresses.Take(4).Select(x => x.ToString()));
                return new LabTestResult("系统 DNS", addresses.Length > 0, sw.ElapsedMilliseconds, text);
            }
            catch (Exception ex)
            {
                return new LabTestResult("系统 DNS", false, sw.ElapsedMilliseconds, ex.Message);
            }
        }

        static async Task<LabTestResult> CheckDohAsync(string host, CancellationToken cancellationToken)
        {
            if (!ProxySettings.EnableDoh.Value)
            {
                return new LabTestResult("DoH 解析", true, 0, "未启用", informational: true);
            }

            var sw = Stopwatch.StartNew();
            try
            {
                var addresses = await DohResolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
                var text = addresses.Count == 0 ? "无结果" : string.Join(", ", addresses.Take(4));
                return new LabTestResult("DoH 解析", addresses.Count > 0, sw.ElapsedMilliseconds, text);
            }
            catch (Exception ex)
            {
                return new LabTestResult("DoH 解析", false, sw.ElapsedMilliseconds, ex.Message);
            }
        }

        static async Task<LabTestResult> CheckTcpAsync(string host, int port, CancellationToken cancellationToken)
        {
            var sw = Stopwatch.StartNew();
            using var client = new TcpClient();
            try
            {
                var connectTask = client.ConnectAsync(host, port);
                var completed = await Task.WhenAny(connectTask, Task.Delay(6000, cancellationToken)).ConfigureAwait(false);
                if (completed != connectTask)
                {
                    return new LabTestResult($"TCP {port}", false, sw.ElapsedMilliseconds, "连接超时");
                }
                await connectTask.ConfigureAwait(false);
                return new LabTestResult($"TCP {port}", true, sw.ElapsedMilliseconds, client.Client.RemoteEndPoint?.ToString() ?? "已连接");
            }
            catch (Exception ex)
            {
                return new LabTestResult($"TCP {port}", false, sw.ElapsedMilliseconds, ex.Message);
            }
        }

        static async Task<LabTestResult> CheckUdpAsync(string host, CancellationToken cancellationToken)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                var address = addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
                if (address == null)
                {
                    return new LabTestResult("UDP 443 探测", true, sw.ElapsedMilliseconds, "没有 IPv4 地址，跳过", informational: true);
                }

                using var udp = new UdpClient(address.AddressFamily);
                await udp.SendAsync(new byte[] { 0x00 }, 1, new IPEndPoint(address, 443)).ConfigureAwait(false);
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);

                // UDP 无连接，收不到回应是正常的；这里只能证明本机可以发出 UDP。
                return new LabTestResult(
                    "UDP 443 探测",
                    true,
                    sw.ElapsedMilliseconds,
                    "已发送探测包；UDP 无连接，无法据此判断是否被阻断",
                    informational: true);
            }
            catch (Exception ex)
            {
                return new LabTestResult("UDP 443 探测", false, sw.ElapsedMilliseconds, ex.Message);
            }
        }

        static LabTestResult CheckCertificate()
        {
            try
            {
                var installed = IReverseProxyService.Instance.CertificateManager.IsRootCertificateInstalled;
                return new LabTestResult(
                    "根证书",
                    true,
                    0,
                    installed ? "已安装，可使用 MITM/镜像/SNI 伪装" : "未安装，只能使用免证书隧道或 IP/预置 IP",
                    informational: true);
            }
            catch (Exception ex)
            {
                return new LabTestResult("根证书", false, 0, ex.Message);
            }
        }

        static LabTestResult CheckDevice(string deviceInfo)
            => new LabTestResult("设备", true, 0, string.IsNullOrWhiteSpace(deviceInfo) ? "未知" : deviceInfo, informational: true);

        public static string BuildSettingsSnapshot()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"代理模式: {ProxySettings.ProxyModeValue}");
            sb.AppendLine($"免证书模式: {ProxySettings.IsCertificateLessMode.Value}");
            sb.AppendLine($"DevSidecar 规则: {ProxySettings.EnableDevSidecarRules.Value}（组: {ProxySettings.DevSidecarRuleGroups.Value}）");
            sb.AppendLine($"自定义规则: {ProxySettings.EnableCustomRules.Value}，{ProxyRuleEngine.CustomRuleCount} 条");
            sb.AppendLine($"SNI 分片: {ProxySettings.EnableSniFragment.Value}，策略: {SniConnectivityTester.GetStrategyName(ProxySettings.SniFragmentStrategy.Value)}");
            sb.AppendLine($"分片参数: 大小 {ProxySettings.SniFragmentChunkSize.Value}B，段数 {ProxySettings.SniSplitPieces.Value}，延迟 {ProxySettings.SniFragmentDelayMilliseconds.Value}ms，抖动 {ProxySettings.SniFragmentJitterMilliseconds.Value}ms");
            sb.AppendLine($"分片域名: {ProxySettings.SniFragmentDomains.Value}");
            sb.AppendLine($"分片回退: {ProxySettings.EnableSniFragmentFallback.Value}，探测 {ProxySettings.SniFragmentFallbackProbeMilliseconds.Value}ms，缓存 {ProxySettings.SniFragmentFallbackCacheMinutes.Value} 分钟");
            sb.AppendLine($"SNI 改写: {ProxySettings.EnableSniRewrite.Value}，目标: {ProxySettings.SniRewriteHost.Value}");
            sb.AppendLine($"Sidecar 端口: {ProxySettings.SniFragmentPortId.Value}");
            sb.AppendLine($"上游中继: {ProxySettings.EnableSniUpstreamRelay.Value}，{ProxySettings.SniUpstreamRelayHost.Value}:{ProxySettings.SniUpstreamRelayPort.Value}，域名: {(string.IsNullOrWhiteSpace(ProxySettings.SniUpstreamRelayDomains.Value) ? "全部" : ProxySettings.SniUpstreamRelayDomains.Value)}");
            sb.AppendLine($"DoH: {ProxySettings.EnableDoh.Value}，{ProxySettings.DohEndpoint.Value}，回退系统 DNS: {ProxySettings.DohFallbackToSystem.Value}");
            sb.AppendLine($"诊断日志: {ProxySettings.EnableProxyDiagnostics.Value}，级别 {ProxySettings.ProxyDiagnosticsMinimumLevel.Value}，保留 {ProxySettings.ProxyDiagnosticsRetentionDays.Value} 天");
            sb.AppendLine($"仅浏览器 VPN: {ProxySettings.EnableBrowserOnlyVpn.Value}");
            return sb.ToString();
        }

        public static string BuildReport(
            string deviceInfo,
            IReadOnlyList<LabTestResult> results,
            bool includeLog = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Watt Toolkit 加速实验室报告");
            sb.AppendLine($"时间: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
            sb.AppendLine($"设备: {deviceInfo}");
            sb.AppendLine();

            sb.AppendLine("== 设置快照 ==");
            sb.AppendLine(BuildSettingsSnapshot());

            sb.AppendLine("== 测试结果 ==");
            foreach (var result in results)
            {
                sb.AppendLine(result.ToLine());
            }

            sb.AppendLine();
            sb.AppendLine("== 运行统计 ==");
            sb.AppendLine(SniSidecarStats.ToDisplayString());
            sb.AppendLine("策略命中: " + SniSidecarStats.GetStrategySummary());
            sb.AppendLine("回退域名: " + SniSidecarStats.GetHostFallbackSummary());
            sb.AppendLine($"回退缓存条目: {FragmentFallbackCache.Count}");

            if (includeLog)
            {
                sb.AppendLine();
                sb.AppendLine("== 最近诊断日志 ==");
                var log = ProxyDiagnostics.GetRecentLogText();
                sb.AppendLine(string.IsNullOrEmpty(log) ? "(无日志)" : log);
            }

            return sb.ToString();
        }
    }
}
