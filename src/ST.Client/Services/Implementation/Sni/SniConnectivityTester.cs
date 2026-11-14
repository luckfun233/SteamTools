using System;
using System.Application.Settings;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// SNI 分片连通性自测：分别用直连和本地 sidecar 建立 TLS 握手，比较结果。
    /// 只能说明“当前网络 + 当前设置”下是否成功，不能证明某个 DPI 设备一定被绕过。
    /// </summary>
    public static class SniConnectivityTester
    {
        public static async Task<string> RunAsync(
            string host,
            int port = 443,
            int timeoutSeconds = 8,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return "请输入要测试的域名。";
            }

            host = host.Trim();
            if (port <= 0 || port > 65535) port = 443;
            timeoutSeconds = Math.Max(2, Math.Min(30, timeoutSeconds));

            var report = new StringBuilder();
            report.AppendLine($"测试目标: {host}:{port}");
            report.AppendLine($"SNI 分片: {(ProxySettings.EnableSniFragment.Value ? "已开启" : "未开启")}，策略: {GetStrategyName(ProxySettings.SniFragmentStrategy.Value)}");
            report.AppendLine($"DoH: {(ProxySettings.EnableDoh.Value ? ProxySettings.DohEndpoint.Value : "未开启")}");
            report.AppendLine($"上游中继: {(ProxySettings.EnableSniUpstreamRelay.Value ? $"{ProxySettings.SniUpstreamRelayHost.Value}:{ProxySettings.SniUpstreamRelayPort.Value}" : "未开启")}");
            report.AppendLine();

            var direct = await ProbeDirectAsync(host, port, timeoutSeconds, cancellationToken).ConfigureAwait(false);
            report.AppendLine($"直连 TLS: {direct}");

            var wasRunning = SniSidecarService.IsRunning;
            if (!wasRunning)
            {
                SniSidecarService.Start(force: true);
            }

            SniProbeResult? viaSidecar = null;
            if (SniSidecarService.IsRunning)
            {
                viaSidecar = await ProbeViaSidecarAsync(
                    host,
                    port,
                    SniSidecarService.ActivePort,
                    timeoutSeconds,
                    cancellationToken).ConfigureAwait(false);
                report.AppendLine($"Sidecar TLS: {viaSidecar}");
            }
            else
            {
                report.AppendLine("Sidecar TLS: 未能启动本地 SOCKS5（端口可能被占用）");
            }

            if (!wasRunning)
            {
                SniSidecarService.Stop();
            }

            report.AppendLine();
            report.AppendLine(GetConclusion(direct.Success, viaSidecar?.Success == true));
            report.AppendLine();
            report.AppendLine("运行统计: " + SniSidecarStats.ToDisplayString());
            report.AppendLine("策略命中: " + SniSidecarStats.GetStrategySummary());
            report.AppendLine("回退域名: " + SniSidecarStats.GetHostFallbackSummary());
            report.AppendLine("说明: 若直连失败而 Sidecar 成功，SNI 分片/预置 IP/中继很可能在当前网络生效；");
            report.AppendLine("若两者都成功，说明当前网络没有阻断该目标，无法据此判断分片是否绕过 DPI。");

            return report.ToString();
        }

        /// <summary>
        /// 在当前网络下依次尝试每种分片策略，每种跑多次，用于比较稳定性和延迟。
        /// 会临时修改全局策略设置，结束后恢复。
        /// </summary>
        public static async Task<string> RunStrategyMatrixAsync(
            string host,
            int port = 443,
            int timeoutSeconds = 8,
            int runs = 3,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(host)) return "请输入要测试的域名。";
            host = host.Trim();
            if (port <= 0 || port > 65535) port = 443;
            timeoutSeconds = Math.Max(2, Math.Min(30, timeoutSeconds));
            runs = Math.Max(1, Math.Min(10, runs));

            var wasRunning = SniSidecarService.IsRunning;
            var originalStrategy = ProxySettings.SniFragmentStrategy.Value;
            var originalEnabled = ProxySettings.EnableSniFragment.Value;

            if (!wasRunning) SniSidecarService.Start(force: true);
            if (!SniSidecarService.IsRunning) return "无法启动本地 sidecar，请检查端口是否被占用。";

            var report = new StringBuilder();
            report.AppendLine($"分片策略矩阵: {host}:{port}，每种 {runs} 次");
            report.AppendLine($"DoH: {(ProxySettings.EnableDoh.Value ? ProxySettings.DohEndpoint.Value : "未开启")}；中继: {(ProxySettings.EnableSniUpstreamRelay.Value ? "开启" : "关闭")}");
            report.AppendLine();

            try
            {
                ProxySettings.EnableSniFragment.Value = true;

                var baseline = await ProbeViaSidecarAsync(
                    host, port, SniSidecarService.ActivePort, timeoutSeconds, cancellationToken).ConfigureAwait(false);
                report.AppendLine($"不分片基准: {FormatProbe(baseline)}");

                foreach (var strategy in new[]
                {
                    TlsFragmentStrategy.SniBoundary,
                    TlsFragmentStrategy.SniPieces,
                    TlsFragmentStrategy.TlsRecordSplit,
                    TlsFragmentStrategy.Fixed,
                    TlsFragmentStrategy.Record,
                    TlsFragmentStrategy.Random,
                })
                {
                    ProxySettings.SniFragmentStrategy.Value = (int)strategy;

                    var successes = 0;
                    var times = new List<long>();
                    string? lastError = null;
                    for (var i = 0; i < runs; i++)
                    {
                        var result = await ProbeViaSidecarAsync(
                            host, port, SniSidecarService.ActivePort, timeoutSeconds, cancellationToken).ConfigureAwait(false);
                        if (result.Success)
                        {
                            successes++;
                            times.Add(result.ElapsedMs);
                        }
                        else
                        {
                            lastError = result.Error;
                        }
                    }

                    times.Sort();
                    var median = times.Count == 0 ? 0 : times[times.Count / 2];
                    report.AppendLine(
                        $"{GetStrategyName((int)strategy),-16} 成功 {successes}/{runs} 中位 {median}ms" +
                        (lastError == null ? string.Empty : $"，最后错误: {lastError}"));
                }
            }
            finally
            {
                ProxySettings.SniFragmentStrategy.Value = originalStrategy;
                ProxySettings.EnableSniFragment.Value = originalEnabled;
                if (!wasRunning) SniSidecarService.Stop();
            }

            report.AppendLine();
            report.AppendLine("运行统计: " + SniSidecarStats.ToDisplayString());
            report.AppendLine("策略命中: " + SniSidecarStats.GetStrategySummary());
            report.AppendLine("说明: 全部成功通常说明当前网络没有阻断该目标；部分成功说明策略不稳定；");
            report.AppendLine("记录型 DPI 只能被 TLS record 分片或中继绕过，TCP 分段对它无效。");
            return report.ToString();
        }

        static string FormatProbe(SniProbeResult result)
            => result.Success ? $"成功 ({result.ElapsedMs}ms)" : $"失败: {result.Error}";

        public static string GetStrategyName(int value) => value switch
        {
            ProxySettings.SniFragmentStrategyFixed => "固定大小",
            ProxySettings.SniFragmentStrategyRecord => "TLS 记录头",
            ProxySettings.SniFragmentStrategySniPieces => "SNI 多段",
            ProxySettings.SniFragmentStrategyTlsRecordSplit => "TLS record 拆分",
            ProxySettings.SniFragmentStrategyRandom => "随机分片",
            _ => "SNI 边界",
        };

        public static async Task<SniProbeResult> ProbeDirectAsync(
            string host,
            int port,
            int timeoutSeconds,
            CancellationToken cancellationToken)
        {
            using var client = new TcpClient();
            var sw = Stopwatch.StartNew();
            try
            {
                using var timeout = CreateTimeout(cancellationToken, timeoutSeconds);
                await ConnectWithTimeoutAsync(client, host, port, timeout.Token).ConfigureAwait(false);
                if (!await HandshakeAsync(client.GetStream(), host, timeoutSeconds, cancellationToken).ConfigureAwait(false))
                {
                    return SniProbeResult.Fail(sw.ElapsedMilliseconds, "TLS 握手失败");
                }
                return SniProbeResult.Ok(sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                return SniProbeResult.Fail(sw.ElapsedMilliseconds, Describe(ex));
            }
        }

        public static async Task<SniProbeResult> ProbeViaSidecarAsync(
            string host,
            int port,
            int sidecarPort,
            int timeoutSeconds,
            CancellationToken cancellationToken)
        {
            using var client = new TcpClient();
            var sw = Stopwatch.StartNew();
            try
            {
                using var timeout = CreateTimeout(cancellationToken, timeoutSeconds);
                await ConnectWithTimeoutAsync(client, IPAddress.Loopback.ToString(), sidecarPort, timeout.Token).ConfigureAwait(false);
                var stream = client.GetStream();

                if (!await SocksConnectAsync(stream, host, port, timeout.Token).ConfigureAwait(false))
                {
                    return SniProbeResult.Fail(sw.ElapsedMilliseconds, "SOCKS5 连接被拒绝");
                }

                if (!await HandshakeAsync(stream, host, timeoutSeconds, cancellationToken).ConfigureAwait(false))
                {
                    return SniProbeResult.Fail(sw.ElapsedMilliseconds, "TLS 握手失败");
                }
                return SniProbeResult.Ok(sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                return SniProbeResult.Fail(sw.ElapsedMilliseconds, Describe(ex));
            }
        }

        static async Task<bool> HandshakeAsync(
            System.IO.Stream stream,
            string host,
            int timeoutSeconds,
            CancellationToken cancellationToken)
        {
            using var ssl = new SslStream(stream, true, (_, _, _, _) => true);
            using var timeout = CreateTimeout(cancellationToken, timeoutSeconds);
            var task = ssl.AuthenticateAsClientAsync(host);
            var completed = await Task.WhenAny(task, Task.Delay(Timeout.Infinite, timeout.Token)).ConfigureAwait(false);
            if (completed != task) throw new TimeoutException();
            await task.ConfigureAwait(false);
            return ssl.IsAuthenticated;
        }

        static async Task<bool> SocksConnectAsync(
            NetworkStream stream,
            string host,
            int port,
            CancellationToken cancellationToken)
        {
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, 0, 3, cancellationToken).ConfigureAwait(false);
            var greeting = new byte[2];
            if (!await ReadExactAsync(stream, greeting, cancellationToken).ConfigureAwait(false)) return false;
            if (greeting[0] != 0x05 || greeting[1] != 0x00) return false;

            byte[] request;
            if (IPAddress.TryParse(host, out var ip))
            {
                var address = ip.GetAddressBytes();
                request = new byte[4 + address.Length + 2];
                request[3] = ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
                address.CopyTo(request, 4);
            }
            else
            {
                var hostBytes = Encoding.ASCII.GetBytes(host);
                if (hostBytes.Length > 255) return false;
                request = new byte[5 + hostBytes.Length + 2];
                request[3] = 0x03;
                request[4] = (byte)hostBytes.Length;
                hostBytes.CopyTo(request, 5);
            }

            request[0] = 0x05;
            request[1] = 0x01;
            request[2] = 0x00;
            request[^2] = (byte)(port >> 8);
            request[^1] = (byte)(port & 0xFF);
            await stream.WriteAsync(request, 0, request.Length, cancellationToken).ConfigureAwait(false);

            var reply = new byte[4];
            if (!await ReadExactAsync(stream, reply, cancellationToken).ConfigureAwait(false)) return false;
            if (reply[0] != 0x05 || reply[1] != 0x00) return false;

            var skip = reply[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => await ReadOneAsync(stream, cancellationToken).ConfigureAwait(false),
                _ => 0,
            };
            var tail = new byte[skip + 2];
            return tail.Length == 0 || await ReadExactAsync(stream, tail, cancellationToken).ConfigureAwait(false);
        }

        static async Task<int> ReadOneAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var buffer = new byte[1];
            return await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false) ? buffer[0] : 0;
        }

        static async Task<bool> ReadExactAsync(
            NetworkStream stream,
            byte[] buffer,
            CancellationToken cancellationToken)
        {
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer, total, buffer.Length - total, cancellationToken).ConfigureAwait(false);
                if (read <= 0) return false;
                total += read;
            }
            return true;
        }

        static CancellationTokenSource CreateTimeout(CancellationToken cancellationToken, int seconds)
        {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(seconds));
            return cts;
        }

        static async Task ConnectWithTimeoutAsync(
            TcpClient client,
            string host,
            int port,
            CancellationToken cancellationToken)
        {
            var connectTask = client.ConnectAsync(host, port);
            var delayTask = Task.Delay(Timeout.Infinite, cancellationToken);
            var completed = await Task.WhenAny(connectTask, delayTask).ConfigureAwait(false);
            if (completed != connectTask) throw new TimeoutException();
            await connectTask.ConfigureAwait(false);
        }

        static string GetConclusion(bool directOk, bool sidecarOk)
        {
            if (!directOk && sidecarOk)
            {
                return "结论: 直连失败、Sidecar 成功。可能是 SNI 分片、预置 IP 或 DoH 的效果；可关闭分片后复测以区分。";
            }
            if (!directOk && !sidecarOk)
            {
                return "结论: 两者都失败。目标 IP 可能不可达、TLS 被重置，或分片策略不足以绕过当前 DPI；可尝试预置 IP、DoH 或上游中继。";
            }
            if (directOk && !sidecarOk)
            {
                return "结论: 直连成功但 Sidecar 失败。请检查 sidecar 端口、规则范围、上游中继与日志。";
            }
            return "结论: 两者都成功。当前网络未阻断该目标，无法据此判断分片是否有效。";
        }

        static string Describe(Exception ex)
        {
            if (ex is OperationCanceledException) return "超时/已取消";
            if (ex is TimeoutException) return "超时";
            if (ex is SocketException socket) return $"网络错误 {socket.SocketErrorCode}";
            if (ex is System.Security.Authentication.AuthenticationException) return "TLS 认证失败";
            return ex.Message;
        }

        public sealed class SniProbeResult
        {
            SniProbeResult(bool success, long elapsedMs, string? error)
            {
                Success = success;
                ElapsedMs = elapsedMs;
                Error = error;
            }

            public bool Success { get; }

            public long ElapsedMs { get; }

            public string? Error { get; }

            public static SniProbeResult Ok(long elapsedMs) => new(true, elapsedMs, null);

            public static SniProbeResult Fail(long elapsedMs, string error) => new(false, elapsedMs, error);

            public override string ToString()
                => Success ? $"成功 ({ElapsedMs}ms)" : $"失败 ({ElapsedMs}ms): {Error}";
        }
    }
}
