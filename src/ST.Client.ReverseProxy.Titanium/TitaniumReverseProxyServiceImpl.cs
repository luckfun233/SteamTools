using System.Application.Models;
using System.Application.ProxyRules;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;
using Titanium.Web.Proxy.Network;
using Titanium.Web.Proxy.StreamExtended.Models;
using static System.Application.Services.IReverseProxyService;

namespace System.Application.Services.Implementation;

sealed class TitaniumReverseProxyServiceImpl : ReverseProxyServiceImpl, IReverseProxyService
{
    public override EReverseProxyEngine ReverseProxyEngine => EReverseProxyEngine.Titanium;

    readonly ProxyServer proxyServer = new();

    private static bool IsIpv6Support = false;

    public TitaniumReverseProxyServiceImpl(
        IPlatformService platformService,
        IDnsAnalysisService dnsAnalysis) : base(platformService, dnsAnalysis)
    {
        //if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        //    proxyServer.CertificateManager.CertificateEngine = CertificateEngine.DefaultWindows;
        //else
        proxyServer.ExceptionFunc = OnException;

        proxyServer.EnableHttp2 = true;
        proxyServer.EnableConnectionPool = true;
        proxyServer.CheckCertificateRevocation = X509RevocationMode.NoCheck;

        CertificateManager = new TitaniumCertificateManagerImpl(platformService, this, proxyServer.CertificateManager);
        //proxyServer.ThreadPoolWorkerThread = Environment.ProcessorCount * 8;
    }

    public IPAddress[] DefaultDnsServers => IDnsAnalysisService.DNS_Alis;

    public override ICertificateManager CertificateManager { get; }

    protected override void OnException(Exception exception)
    {
        base.OnException(exception);
        ProxyDiagnostics.Error("Proxy", exception.ToString());
    }

    public override bool ProxyRunning => proxyServer.ProxyRunning;

    static IList<HttpHeader> JsHeader => new List<HttpHeader>() { new HttpHeader("Content-Type", "text/javascript;charset=UTF-8") };

    static async Task HttpRequest(SessionEventArgs e)
    {
        //IHttpService.Instance.SendAsync<object>();
        var url = Web.HttpUtility.UrlDecode(e.HttpClient.Request.RequestUri.Query.Replace("?request=", ""));
        var cookie = e.HttpClient.Request.Headers.GetFirstHeader("cookie-steamTool")?.Value ??
            e.HttpClient.Request.Headers.GetFirstHeader("Cookie")?.Value;
        var headrs = new List<HttpHeader>()
            {
                new("Access-Control-Allow-Origin", e.HttpClient.Request.Headers.GetFirstHeader("Origin")?.Value ?? "*"),
                new("Access-Control-Allow-Headers", "*"),
                new("Access-Control-Allow-Methods", "*"),
                new("Access-Control-Allow-Credentials", "true"),
            };
        //if (cookie != null)
        //    headrs.Add(new HttpHeader("Cookie", cookie));
        if (e.HttpClient.Request.ContentType != null)
            headrs.Add(new HttpHeader("Content-Type", e.HttpClient.Request.ContentType));
        switch (e.HttpClient.Request.Method.ToUpperInvariant())
        {
            case "GET":
                var body = await IHttpService.Instance.GetAsync<string>(url, cookie: cookie);
                e.Ok(body ?? "500", headrs);
                return;
            case "POST":
                try
                {
                    if (e.HttpClient.Request.ContentLength > 0)
                    {
                        var conext = await IHttpService.Instance.SendAsync<string>(url, () =>
                        {
                            using var sw = new MemoryStream().GetWriter(leaveOpen: true);
                            sw.Write(e.HttpClient.Request.BodyString);
                            var req = new HttpRequestMessage
                            {
                                Method = HttpMethod.Post,
                                Content = new StreamContent(sw.BaseStream),
                            };
                            req.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(e.HttpClient.Request.ContentType);
                            req.Content.Headers.ContentLength = e.HttpClient.Request.BodyString.Length;
                            return req;
                        }, null/*, false*/, default);
                        e.Ok(conext ?? "500", headrs);
                    }
                    else
                    {
                        e.Ok("500", headrs);
                    }
                }
                catch (Exception error)
                {
                    e.Ok(error.Message ?? "500", headrs);
                }
                return;
        }
        //e.Ok(respone, new List<HttpHeader>() { new HttpHeader("Access-Control-Allow-Origin", e.HttpClient.Request.Headers.GetFirstHeader("Origin")?.Value ?? "*") });
    }

    async Task<IPAddress?> GetReverseProxyIp(string url, IPAddress? proxyDns, bool isDomain = false)
    {
        if (isDomain || !IPAddress.TryParse(url, out var ip))
        {
            if (proxyDns != null)
            {
                ip = await DnsAnalysis.AnalysisDomainIpAsync(url, new[] { proxyDns }, IsIpv6Support).FirstOrDefaultAsync();
            }
            else
            {
                if (!OperatingSystem2.IsWindows() && ProxyMode is ProxyMode.Hosts)
                {
                    // 非 windows 环境 hosts 加速下不能使用系统默认 DNS 解析代理，会解析到 hosts 上无限循环
                    ip = await DnsAnalysis.AnalysisDomainIpAsync(url, DefaultDnsServers, IsIpv6Support).FirstOrDefaultAsync();
                }
                else
                {
                    ip = await DnsAnalysis.AnalysisDomainIpAsync(url, IsIpv6Support).FirstOrDefaultAsync();
                }
            }
        }
        return ip;
    }

    /// <summary>
    /// 请求是否携带认证、会话 Cookie 或签名参数。
    /// </summary>
    static bool HasSensitiveCredentials(Request request)
    {
        if (request.Headers.GetFirstHeader("Authorization") != null)
            return true;

        var cookie = request.Headers.GetFirstHeader("Cookie")?.Value;
        if (!string.IsNullOrEmpty(cookie) &&
            (cookie.Contains("user_session", StringComparison.OrdinalIgnoreCase) ||
             cookie.Contains("_gh_sess", StringComparison.OrdinalIgnoreCase) ||
             cookie.Contains("dotcom_user", StringComparison.OrdinalIgnoreCase)))
            return true;

        var query = request.RequestUri.Query;
        return query.Contains("sig=", StringComparison.OrdinalIgnoreCase) ||
               query.Contains("signature=", StringComparison.OrdinalIgnoreCase) ||
               query.Contains("x-amz-signature", StringComparison.OrdinalIgnoreCase) ||
               query.Contains("jwt=", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 带凭证的请求不能走公共镜像或第三方加速节点，否则私有仓库会 404，凭据也可能泄露。
    /// 但同源 SNI/IP 伪装（Local）仍然允许，因为流量最终仍然到原始站点。
    /// </summary>
    static bool ShouldBypassThirdParty(AccelerateProjectDTO item, Request request)
    {
        if (!HasSensitiveCredentials(request))
            return false;
        return item.Redirect || item.ProxyType == ProxyType.ServerAccelerate;
    }

    /// <summary>
    /// 只替换 authority，保留原始 path/query，避免字符串替换误伤参数。
    /// </summary>
    static Uri? BuildRedirectUri(Uri original, AccelerateProjectDTO item)
    {
        var forward = item.ForwardDomainName;
        if (string.IsNullOrWhiteSpace(forward))
            return null;

        if (forward.Contains("{path}", StringComparison.Ordinal) ||
            forward.Contains("{args}", StringComparison.Ordinal))
        {
            var url = forward.Replace("{path}", original.AbsolutePath)
                             .Replace("{args}", original.Query);
            return Uri.TryCreate(url, UriKind.Absolute, out var templateUri) ? templateUri : null;
        }

        if (!Uri.TryCreate(forward, UriKind.Absolute, out var forwardUri))
        {
            if (!Uri.TryCreate($"{original.Scheme}://{forward}", UriKind.Absolute, out forwardUri))
                return null;
        }

        if (forwardUri.AbsolutePath.Length > 1)
        {
            var prefix = forward.TrimEnd('/');
            var prefixed = prefix + original.PathAndQuery;
            return Uri.TryCreate(prefixed, UriKind.Absolute, out var prefixUri) ? prefixUri : null;
        }

        return new UriBuilder(original)
        {
            Scheme = forwardUri.Scheme,
            Host = forwardUri.Host,
            Port = forwardUri.IsDefaultPort
                ? (forwardUri.Scheme == Uri.UriSchemeHttps ? 443 : 80)
                : forwardUri.Port,
        }.Uri;
    }

    async Task<bool> TryApplyRuleAsync(SessionEventArgs e, ProxyRule rule)
    {
        var request = e.HttpClient.Request;
        var host = request.RequestUri.Host;
        var sensitive = HasSensitiveCredentials(request);

        ProxyDiagnostics.Info("Rule", $"{host}{request.RequestUri.PathAndQuery} -> {rule.Description ?? rule.DomainPattern}");

        if (rule.Block)
        {
            e.TerminateSession();
            return true;
        }

        if (!string.IsNullOrEmpty(rule.Redirect))
        {
            if (sensitive)
            {
                ProxyDiagnostics.Info("Rule", $"跳过镜像（凭证）: {host}");
                return false;
            }

            var uri = BuildRuleRedirectUri(request.RequestUri, rule.Redirect);
            if (uri != null)
            {
                request.RequestUri = uri;
                ProxyDiagnostics.Info("Rule", $"重定向: {host} -> {uri.Host}");
                return true;
            }
        }

        if (!string.IsNullOrEmpty(rule.Proxy))
        {
            if (sensitive)
            {
                ProxyDiagnostics.Info("Rule", $"跳过第三方反代（凭证）: {host}");
                return false;
            }

            var proxyHost = GetHost(rule.Proxy);
            var ip = await GetReverseProxyIp(proxyHost, ProxyDNS, true);
            if (ip != null && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any))
            {
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(ip, 443);
                ApplySniOverride(e, rule.Sni ?? rule.VerifyHost ?? proxyHost);
                return true;
            }
        }

        if (!string.IsNullOrEmpty(rule.Sni) || !string.IsNullOrEmpty(rule.VerifyHost))
        {
            if (rule.PresetIps.Count > 0)
            {
                var presetIp = await PresetIpSelector.PickAsync(rule.PresetIps, 443, TimeSpan.FromMilliseconds(800));
                if (presetIp != null)
                {
                    e.HttpClient.UpStreamEndPoint = new IPEndPoint(presetIp, 443);
                }
            }
            ApplySniOverride(e, rule.Sni ?? rule.VerifyHost);
            return true;
        }

        if (rule.PresetIps.Count > 0 && !sensitive)
        {
            var presetIp = await PresetIpSelector.PickAsync(rule.PresetIps, 443, TimeSpan.FromMilliseconds(800));
            if (presetIp != null)
            {
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(presetIp, 443);
                return true;
            }
        }

        return false;
    }

    static string GetHost(string value)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri)) return uri.Host;
        return value.Split('/')[0];
    }

    static Uri? BuildRuleRedirectUri(Uri original, string target)
    {
        if (target.Contains("{path}", StringComparison.Ordinal))
        {
            target = target.Replace("{path}", original.AbsolutePath);
        }
        if (target.Contains("{args}", StringComparison.Ordinal))
        {
            target = target.Replace("{args}", original.Query);
        }
        if (!target.Contains("://", StringComparison.Ordinal))
        {
            target = "https://" + target.TrimStart('/');
        }
        if (!Uri.TryCreate(target, UriKind.Absolute, out var baseUri)) return null;
        if (target.Contains("{path}", StringComparison.Ordinal) ||
            target.Contains("{args}", StringComparison.Ordinal))
        {
            return baseUri;
        }
        var combined = target.TrimEnd('/') + original.PathAndQuery;
        return Uri.TryCreate(combined, UriKind.Absolute, out var result) ? result : baseUri;
    }

    static void ApplySniOverride(SessionEventArgs e, string? sni)
    {
        if (string.IsNullOrEmpty(sni)) return;
        var extensions = e.HttpClient.ConnectRequest?.ClientHelloInfo?.Extensions;
        if (extensions == null) return;
        var current = extensions["server_name"];
        if (current == null) return;
        extensions["server_name"] = new SslExtension(current.Value, current.Name, sni, current.Position);
    }

    async Task OnRequest(object sender, SessionEventArgs e)
    {
#if DEBUG
        Debug.WriteLine("OnRequest " + e.HttpClient.Request.RequestUri.AbsoluteUri);
        Debug.WriteLine("OnRequest HTTP " + e.HttpClient.Request.HttpVersion);
        Debug.WriteLine("ClientRemoteEndPoint " + e.ClientRemoteEndPoint.ToString());
#endif
        if (e.HttpClient.Request.Host == null) return;

        if (e.HttpClient.Request.Host.Contains(LocalDomain, StringComparison.OrdinalIgnoreCase))
        {
            if (e.HttpClient.Request.Method.ToUpperInvariant() == "OPTIONS")
            {
                e.Ok("", new List<HttpHeader>()
                    {
                        new HttpHeader("Access-Control-Allow-Origin", e.HttpClient.Request.Headers.GetFirstHeader("Origin")?.Value ?? "*"),
                        new HttpHeader("Access-Control-Allow-Headers", "*"),
                        new HttpHeader("Access-Control-Allow-Methods", "*"),
                        new HttpHeader("Access-Control-Allow-Credentials", "true"),
                    });
                return;
            }
            var type = e.HttpClient.Request.Headers.GetFirstHeader("requestType")?.Value;
            switch (type)
            {
                case "xhr":
                    await HttpRequest(e);
                    return;
                default:
                    e.Ok(Scripts?.FirstOrDefault(x => x.JsPathUrl == e.HttpClient.Request.RequestUri.LocalPath)?.Content ?? "404", JsHeader);
                    return;
            }
        }

        //host模式下不启用加速会出现无限循环问题
        if (ProxyRuleEngine.Current.IsExcluded(e.HttpClient.Request.RequestUri.Host))
        {
            return;
        }
        if (ProxyDomains is null || TwoLevelAgentEnable || (OnlyEnableProxyScript && ProxyMode == ProxyMode.Hosts))
        {
            var hostRule = ProxyRuleEngine.Current.Match(e.HttpClient.Request.RequestUri.Host, e.HttpClient.Request.RequestUri.AbsolutePath);
            if (hostRule != null && await TryApplyRuleAsync(e, hostRule))
            {
                return;
            }
            return;
        }

        var devSidecarRule = ProxyRuleEngine.Current.Match(e.HttpClient.Request.RequestUri.Host, e.HttpClient.Request.RequestUri.AbsolutePath);
        if (devSidecarRule != null && await TryApplyRuleAsync(e, devSidecarRule))
        {
            return;
        }

        //var item = ProxyDomains.FirstOrDefault(f => f.DomainNamesArray.Any(h => e.HttpClient.Request.RequestUri.AbsoluteUri.Contains(h, StringComparison.OrdinalIgnoreCase)));

        //if (item != null)
        //{

        //e.HttpClient.Request.Headers.AddHeader("User-Agent", "Watt Toolkit Proxy/" + ThisAssembly.Version);

        foreach (var item in ProxyDomains)
        {
            foreach (var host in item.DomainNamesArray)
            {
                if (e.HttpClient.Request.RequestUri.AbsoluteUri.IsDomainPattern(host, RegexOptions.IgnoreCase))
                {
                    if (ShouldBypassThirdParty(item, e.HttpClient.Request))
                    {
                        // 镜像/第三方节点不能接触凭证；SNI/IP 伪装仍然可以用于私有仓库。
                        return;
                    }

                    if (!e.HttpClient.IsHttps)
                    {
                        e.HttpClient.Request.RequestUri = new Uri(e.HttpClient.Request.RequestUri.AbsoluteUri.Remove(0, 4).Insert(0, Uri.UriSchemeHttps));
                        //e.Redirect(e.HttpClient.Request.RequestUri.AbsoluteUri.Remove(0, 4).Insert(0, Uri.UriSchemeHttps));
                        //return;
                    }

                    if (item.Redirect)
                    {
                        var redirectUri = BuildRedirectUri(e.HttpClient.Request.RequestUri, item);
                        if (redirectUri != null)
                        {
                            e.HttpClient.Request.RequestUri = redirectUri;
                        }
                        return;
                    }

                    if (e.HttpClient.UpStreamEndPoint == null)
                    {
                        var addres = item.ForwardDomainIsNameOrIP ? item.ForwardDomainName : item.ForwardDomainIP;
                        var ip = await GetReverseProxyIp(addres, ProxyDNS, item.ForwardDomainIsNameOrIP);
                        if (ip == null || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any))
                            goto exit;
                        e.HttpClient.UpStreamEndPoint = new IPEndPoint(ip, item.PortId > 0 ? item.PortId : 443);
                    }

                    if (!string.IsNullOrEmpty(item.UserAgent))
                    {
                        var oldua = e.HttpClient.Request.Headers.GetFirstHeader("User-Agent")?.Value;
                        e.HttpClient.Request.Headers.RemoveHeader("User-Agent");
                        var newUA = item.UserAgent.Replace("${origin}", oldua);
                        e.HttpClient.Request.Headers.AddHeader("User-Agent", newUA);
                    }

                    if (e.HttpClient.ConnectRequest?.ClientHelloInfo?.Extensions != null)
                    {
#if DEBUG
                        //Logger.Info("ClientHelloInfo Info: " + e.HttpClient.ConnectRequest.ClientHelloInfo);
                        Debug.WriteLine("ClientHelloInfo Info: " + e.HttpClient.ConnectRequest.ClientHelloInfo);
#endif
                        if (!string.IsNullOrEmpty(item.ServerName))
                        {
                            var sni = e.HttpClient.ConnectRequest.ClientHelloInfo.Extensions["server_name"];
                            if (sni != null)
                            {
                                e.HttpClient.ConnectRequest.ClientHelloInfo.Extensions["server_name"] =
                                    new SslExtension(sni.Value, sni.Name, item.ServerName, sni.Position);
                            }
                        }
                        else
                        {
                            e.HttpClient.ConnectRequest.ClientHelloInfo.Extensions.Remove("server_name");
                        }
                    }
                    return;
                }
            }
        }
    //}

    exit:
        //部分运营商将奇怪的域名解析到127.0.0.1 再此排除这些不支持的代理域名
        if (IPAddress.IsLoopback(e.ClientRemoteEndPoint.Address))
        {
            var ip = await DnsAnalysis.AnalysisDomainIpAsync(e.HttpClient.Request.Host, DefaultDnsServers).FirstOrDefaultAsync();
            if (ip == null || IPAddress.IsLoopback(ip))
            {
                e.TerminateSession();
                Log.Info(TAG, "IsLoopback OnRequest: " + e.HttpClient.Request.RequestUri.AbsoluteUri);
            }
            else
            {
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(ip, e.ClientRemoteEndPoint.Port);
            }
        }
        return;
    }

    async Task OnResponse(object sender, SessionEventArgs e)
    {
#if DEBUG
        Debug.WriteLine("OnResponse" + e.HttpClient.Request.RequestUri.AbsoluteUri);
        Log.Info(TAG, "OnResponse" + e.HttpClient.Request.RequestUri.AbsoluteUri);
#endif
        if (Scripts is null)
        {
            return;
        }
        if (IsEnableScript &&
            e.HttpClient.Request.Method == "GET" &&
            e.HttpClient.Response.StatusCode == 200 &&
            e.HttpClient.Response.ContentType?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true)
        {
            if (IsOnlyWorkSteamBrowser)
            {
                var ua = e.HttpClient.Request.Headers.GetHeaders("User-Agent");
                if (ua?.FirstOrDefault()?.Value.Contains("Valve Steam") == false)
                {
                    return;
                }
            }

            StringBuilder scriptHtml = new();

            foreach (var script in Scripts)
            {
                if (script.ExcludeDomainNamesArray.Any_Nullable(s => e.HttpClient.Request.RequestUri.AbsoluteUri.IsWildcard(s, RegexOptions.IgnoreCase)))
                {
                    continue;
                }

                foreach (var host in script.MatchDomainNamesArray)
                {
                    var state = host.IndexOf("/") == 0;
                    if (state)
                        state = Regex.IsMatch(e.HttpClient.Request.RequestUri.AbsoluteUri, host[1..], RegexOptions.IgnoreCase);
                    else
                        state = e.HttpClient.Request.RequestUri.AbsoluteUri.IsWildcard(host, RegexOptions.IgnoreCase);
                    if (state)
                    {
                        var t = e.HttpClient.Response.Headers.GetFirstHeader("Content-Security-Policy");
                        if (!string.IsNullOrEmpty(t?.Value))
                        {
                            e.HttpClient.Response.Headers.RemoveHeader(t);
                        }

                        if (script.JsPathUrl == null)
                            script.JsPathUrl = $"/{Guid.NewGuid()}";
                        var temp = $"<script type=\"text/javascript\" src=\"https://{IReverseProxyService.LocalDomain}{script.JsPathUrl}\"></script>";

                        scriptHtml.AppendLine(temp);
                    }
                }
            }

            if (scriptHtml.Length > 0)
            {
                var doc = await e.GetResponseBodyAsString();
                var index = doc.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
                if (index == -1)
                    index = doc.LastIndexOf("</head>", StringComparison.OrdinalIgnoreCase);
                if (index > -1)
                {
                    doc = doc.Insert(index, scriptHtml.ToString());
                    e.SetResponseBodyString(doc);
                }
            }
        }
    }

    // 允许重写默认的证书验证逻辑
    static Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
    {
        // 根据证书错误，设置IsValid为真/假
        //if (e.SslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
        e.IsValid = true;
        return Task.CompletedTask;
    }

    // 允许在相互身份验证期间重写默认客户端证书选择逻辑
    static Task OnCertificateSelection(object sender, CertificateSelectionEventArgs e)
    {
        // set e.clientCertificate to override
        return Task.CompletedTask;
    }

    protected override async Task<bool> StartProxyImpl()
    {
        #region 启动代理

        proxyServer.BeforeRequest += OnRequest;
        proxyServer.BeforeResponse += OnResponse;
        proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
        //proxyServer.ClientCertificateSelectionCallback += OnCertificateSelection;

        try
        {
            if (PortInUse(ProxyPort)) ProxyPort = GetRandomUnusedPort();
            var explicitProxyEndPoint = new ExplicitProxyEndPoint(ProxyIp, ProxyPort, true)
            {
                // 通过不启用为每个http的域创建证书来优化性能
                //GenericCertificate = proxyServer.CertificateManager.RootCertificate
            };
            explicitProxyEndPoint.BeforeTunnelConnectRequest += ExplicitProxyEndPoint_BeforeTunnelConnectRequest;

            if (ProxyMode == ProxyMode.System)
            {
                //explicit endpoint 是客户端知道代理存在的地方
                proxyServer.AddEndPoint(explicitProxyEndPoint);
            }
            else
            {
                //if (PortInUse(443))
                //{
                //    return false;
                //}

                TransparentProxyEndPoint transparentProxyEndPoint;

                transparentProxyEndPoint = new TransparentProxyEndPoint(ProxyIp, 443, true)
                {
                    // 通过不启用为每个http的域创建证书来优化性能
                    //GenericCertificate = proxyServer.CertificateManager.RootCertificate
                };
                //transparentProxyEndPoint.BeforeSslAuthenticate += TransparentProxyEndPoint_BeforeSslAuthenticate;
                proxyServer.AddEndPoint(transparentProxyEndPoint);

                try
                {
                    if (EnableHttpProxyToHttps && PortInUse(80) == false)
                        proxyServer.AddEndPoint(new TransparentProxyEndPoint(ProxyIp, 80, false));
                }
                catch { }
            }

            if (Socks5ProxyEnable)
            {
                var socks5 = new SocksProxyEndPoint(ProxyIp, Socks5ProxyPortId, true);
                socks5.BeforeSslAuthenticate += TransparentProxyEndPoint_BeforeSslAuthenticate;
                proxyServer.AddEndPoint(socks5);
            }

            if (TwoLevelAgentEnable && TwoLevelAgentIp != null)
            {
                proxyServer.UpStreamHttpsProxy = new ExternalProxy(TwoLevelAgentIp, TwoLevelAgentPortId)
                {
                    ProxyDnsRequests = true,
                    BypassLocalhost = true,
                    ProxyType = (ExternalProxyType)TwoLevelAgentProxyType,
                    UserName = TwoLevelAgentUserName,
                    Password = TwoLevelAgentPassword,
                };
                proxyServer.ForwardToUpstreamGateway = true;
            }

            IsIpv6Support = await DnsAnalysis.GetIsIpv6Support();

            proxyServer.Start();

            ProxyDiagnostics.Initialize();
            ProxyDiagnostics.Info("Proxy", $"启动: mode={ProxyMode}, certless={IsCertificateLessMode}, rootCert={IsRootCertificateInstalled}, socks5={Socks5ProxyEnable}, rules={ProxyRuleEngine.Current.Rules.Count}");
            SniSidecarService.Start();

            if (ProxyMode == ProxyMode.System)
            {
                if (!DesktopBridge.IsRunningAsUwp && OperatingSystem2.IsWindows())
                {
                    proxyServer.SetAsSystemProxy(explicitProxyEndPoint, ProxyProtocolType.AllHttp);
                }
                else
                {
                    if (!IPlatformService.Instance.SetAsSystemProxy(true, explicitProxyEndPoint.IpAddress, explicitProxyEndPoint.Port))
                    {
                        Log.Error(TAG, "系统代理开启失败");
                        return false;
                    }
                }
            }
            if (IsProxyGOG) { WirtePemCertificateToGoGSteamPlugins(); }
        }
        catch (Exception ex)
        {
            Log.Error(TAG, ex, nameof(StartProxy));
            return false;
        }

        #endregion
#if DEBUG
        foreach (var endPoint in proxyServer.ProxyEndPoints)
            Debug.WriteLine("Listening on '{0}' endpoint at Ip {1} and port: {2} ",
                endPoint.GetType().Name, endPoint.IpAddress, endPoint.Port);
#endif
        return true;
    }

    Task TransparentProxyEndPoint_BeforeSslAuthenticate(object sender, BeforeSslAuthenticateEventArgs e)
    {
        e.DecryptSsl = false;
        if (ProxyRuleEngine.Current.IsExcluded(e.SniHostName))
        {
            return Task.CompletedTask;
        }
        if (ProxyDomains is null)
        {
            if (IsRootCertificateInstalled && ProxyRuleEngine.Current.DomainRequiresMitm(e.SniHostName))
            {
                e.DecryptSsl = true;
            }
            return Task.CompletedTask;
        }
        if (e.SniHostName.Contains(LocalDomain, StringComparison.OrdinalIgnoreCase) || TwoLevelAgentEnable)
        {
            e.DecryptSsl = IsRootCertificateInstalled;
            return Task.CompletedTask;
        }
        foreach (var item in ProxyDomains)
        {
            foreach (var host in item.DomainNamesArray)
            {
                if (Uri.TryCreate(host, UriKind.RelativeOrAbsolute, out var u))
                {
                    string h;
                    if (u.IsAbsoluteUri)
                        h = u.Host;
                    else
                        h = u.OriginalString;

                    if (e.SniHostName.IsDomainPattern(h, RegexOptions.IgnoreCase))
                    {
                        // 免证书模式下，IP/服务端中转规则可以在不解密 TLS 的情况下换出口。
                        // 有根证书时不要在这里关闭 MITM，否则 SNI/IP 伪装不会生效。
                        if (!IsRootCertificateInstalled &&
                            (item.ProxyType == ProxyType.Local || item.ProxyType == ProxyType.ServerAccelerate) &&
                            !item.ForwardDomainIsNameOrIP &&
                            !string.IsNullOrEmpty(item.ForwardDomainIP))
                        {
                            e.DecryptSsl = false;
                            e.ForwardHttpsHostName = item.ForwardDomainIP;
                            e.ForwardHttpsPort = item.PortId > 0 ? item.PortId : 443;
                            return Task.CompletedTask;
                        }

                        if (!IsRootCertificateInstalled)
                        {
                            // 没有根证书时不做 MITM，按原始 SNI 透传，避免其他应用断网。
                            return Task.CompletedTask;
                        }

                        // 上游目标与 SNI 伪装统一交给 OnRequest 处理：
                        // 这样带凭证的请求可以在看到 Authorization/Cookie 后再决定是否走第三方节点。
                        e.DecryptSsl = true;
                        return Task.CompletedTask;
                    }
                }
            }
        }
        //var ip = Dns.GetHostAddresses(e.SniHostName).FirstOrDefault();
        //if (IPAddress.IsLoopback(ip))
        //{
        //    e.TerminateSession();
        //    return Task.CompletedTask;
        //}
        if (IsRootCertificateInstalled && ProxyRuleEngine.Current.DomainRequiresMitm(e.SniHostName))
        {
            e.DecryptSsl = true;
            ProxyDiagnostics.Info("Rule", $"TLS MITM(DevSidecar): {e.SniHostName}");
        }
        return Task.CompletedTask;
    }

    async Task ExplicitProxyEndPoint_BeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
    {
        e.DecryptSsl = false;
        if (e.HttpClient?.Request?.Host != null &&
            ProxyRuleEngine.Current.IsExcluded(e.HttpClient.Request.Host))
        {
            return;
        }
        if (ProxyDomains is null || e.HttpClient?.Request?.Host == null)
        {
            if (e.HttpClient?.Request?.Host != null &&
                IsRootCertificateInstalled &&
                ProxyRuleEngine.Current.DomainRequiresMitm(e.HttpClient.Request.Host))
            {
                e.DecryptSsl = true;
            }
            return;
        }
        if (e.HttpClient.Request.Host.Contains(LocalDomain, StringComparison.OrdinalIgnoreCase) || TwoLevelAgentEnable || OnlyEnableProxyScript)
        {
            e.DecryptSsl = IsRootCertificateInstalled;
            return;
        }
        foreach (var item in ProxyDomains)
        {
            foreach (var host in item.DomainNamesArray)
            {
                if (e.HttpClient.Request.Url.IsDomainPattern(host, RegexOptions.IgnoreCase))
                {
                    var isLocalOrServer = item.ProxyType == ProxyType.Local ||
                                          item.ProxyType == ProxyType.ServerAccelerate;

                    // 免证书模式下，IP/服务端中转规则不做 MITM，直接换出口，保留原始 SNI 和请求头。
                    if (!IsRootCertificateInstalled &&
                        isLocalOrServer &&
                        !item.ForwardDomainIsNameOrIP &&
                        !string.IsNullOrEmpty(item.ForwardDomainIP))
                    {
                        var ip = await GetReverseProxyIp(item.ForwardDomainIP, ProxyDNS, false);
                        if (ip != null && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any))
                        {
                            e.DecryptSsl = false;
                            e.HttpClient.UpStreamEndPoint = new IPEndPoint(ip, item.PortId > 0 ? item.PortId : 443);
                        }
                        return;
                    }

                    if (!IsRootCertificateInstalled)
                    {
                        // 没有根证书时不做 MITM，按原始 SNI 透传。
                        return;
                    }

                    e.DecryptSsl = true;
                    if (item.ProxyType == ProxyType.Local)
                    {
                        var addres = item.ForwardDomainIsNameOrIP ? item.ForwardDomainName : item.ForwardDomainIP;
                        var ip = await GetReverseProxyIp(addres, ProxyDNS, item.ForwardDomainIsNameOrIP);
                        if (ip != null && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any))
                        {
                            e.HttpClient.UpStreamEndPoint = new IPEndPoint(ip, item.PortId > 0 ? item.PortId : 443);
                        }
                    }
                    return;
                }
            }
        }
        //var ip = Dns.GetHostAddresses(e.HttpClient.Request.Host).FirstOrDefault();
        //if (IPAddress.IsLoopback(ip))
        //{
        //    e.TerminateSession();
        //    return Task.CompletedTask;
        //}
        if (IsRootCertificateInstalled && ProxyRuleEngine.Current.DomainRequiresMitm(e.HttpClient.Request.Host))
        {
            e.DecryptSsl = true;
            ProxyDiagnostics.Info("Rule", $"TLS MITM(DevSidecar): {e.HttpClient.Request.Host}");
        }
        return;
    }

    public Task StopProxy()
    {
        try
        {
            if (proxyServer.ProxyRunning)
            {
                proxyServer.BeforeRequest -= OnRequest;
                proxyServer.BeforeResponse -= OnResponse;
                proxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;
                proxyServer.ClientCertificateSelectionCallback -= OnCertificateSelection;
                proxyServer.Stop();
            }

            SniSidecarService.Stop();
            ProxyDiagnostics.Info("Proxy", "已停止");

            if (ProxyMode == ProxyMode.System)
            {
                if (DesktopBridge.IsRunningAsUwp || !OperatingSystem2.IsWindows())
                {
                    IPlatformService.Instance.SetAsSystemProxy(false);
                }
                else
                {
                    proxyServer.DisableAllSystemProxies();
                }
            }
        }
        catch (Exception ex)
        {
            ex.LogAndShowT(TAG);
        }
        return Task.CompletedTask;
    }

    protected override void DisposeCore()
    {
        if (proxyServer.ProxyRunning)
        {
            StopProxy();
        }
        proxyServer.Dispose();
    }

    public FlowStatistics? GetFlowStatistics()
    {
        return null;
    }
}
