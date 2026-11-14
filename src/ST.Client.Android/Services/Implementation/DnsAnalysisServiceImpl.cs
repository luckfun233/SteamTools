using Android.Content;
using Android.Net;
using System.Application.Services;
using System.Application.Services.Implementation;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using XEPlatform = Xamarin.Essentials.Platform;

namespace System.Application.Services.Implementation
{
    internal sealed class DnsAnalysisServiceImpl : IDnsAnalysisService
    {
        ///// <summary>
        ///// https://developer.android.google.cn/reference/android/net/ConnectivityManager?hl=zh-cn
        ///// </summary>
        //static ConnectivityManager ConnectivityManager
        //{
        //    get
        //    {
        //        var connectivityManager = XEPlatform.CurrentActivity.GetSystemService<ConnectivityManager>(Context.ConnectivityService);
        //        return connectivityManager;
        //    }
        //}

        //public static List<IPEndPoint> GetDnsServers()
        //{
        //    List<IPEndPoint> endPoints = new();
        //    var connectivityManager = ConnectivityManager;

        //    var activeConnection = connectivityManager.ActiveNetwork;
        //    var linkProperties = connectivityManager.GetLinkProperties(activeConnection);

        //    if (linkProperties != null)
        //    {
        //        foreach (var currentAddress in linkProperties.DnsServers)
        //        {
        //            var endPoint = new IPEndPoint(IPAddress.Parse(currentAddress.HostAddress), 53);
        //            endPoints.Add(endPoint);
        //        }
        //    }

        //    return endPoints;
        //}

        public async Task<int> AnalysisHostnameTime(string url, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(url)) return 0;
            try
            {
                var host = url;
                if (Uri.TryCreate(url, UriKind.Absolute, out var uri)) host = uri.Host;
                var sw = System.Diagnostics.Stopwatch.StartNew();
                await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
                return (int)sw.ElapsedMilliseconds;
            }
            catch
            {
                return -1;
            }
        }
    }
}

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    partial class ServiceCollectionExtensions
    {
        public static IServiceCollection AddDnsAnalysisService(this IServiceCollection services)
        {
            services.AddSingleton<IDnsAnalysisService, DnsAnalysisServiceImpl>();
            return services;
        }
    }
}