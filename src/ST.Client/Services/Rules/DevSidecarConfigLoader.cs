using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 读取并转换 DevSidecar 的 remote_config.json5（只实现代理相关子集）。
    /// </summary>
    public static class DevSidecarConfigLoader
    {
        public const string DefaultConfigUrl = "https://ds-official-config.bestar.de5.net/remote_config.json5";

        static readonly HttpClient httpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(20),
        };

        public static string GetCacheFilePath()
            => Path.Combine(IOPath.AppDataDirectory, "DevSidecar", "remote_config.json5");

        public static async Task<ProxyRuleSet> LoadAsync(
            string? url = null,
            CancellationToken cancellationToken = default)
        {
            var cachePath = GetCacheFilePath();
            url = string.IsNullOrWhiteSpace(url) ? DefaultConfigUrl : url.Trim();

            if (!Uri.TryCreate(url, UriKind.Absolute, out var configUri) ||
                !string.Equals(configUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                Log.Warn("DevSidecarConfig", $"拒绝非 HTTPS 配置地址: {url}");
                try
                {
                    if (File.Exists(cachePath))
                    {
                        return Parse(File.ReadAllText(cachePath));
                    }
                }
                catch (Exception cacheEx)
                {
                    Log.Warn("DevSidecarConfig", cacheEx, "读取 DevSidecar 本地缓存失败");
                }
                return ProxyRuleSet.Empty;
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.TryAddWithoutValidation("User-Agent", "WattToolkit-Android-DevSidecarCompat/1.0");
                using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(json))
                {
                    throw new InvalidDataException("DevSidecar 配置内容为空");
                }

                try
                {
                    var dir = Path.GetDirectoryName(cachePath);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    var tmp = cachePath + ".tmp";
                    File.WriteAllText(tmp, json);
                    if (File.Exists(cachePath)) File.Delete(cachePath);
                    File.Move(tmp, cachePath);
                }
                catch (Exception ex)
                {
                    Log.Warn("DevSidecarConfig", ex, "缓存 DevSidecar 配置失败");
                }

                var rules = Parse(json);
                Log.Info("DevSidecarConfig", $"已加载 {rules.Rules.Count} 条规则: {url}");
                return rules;
            }
            catch (Exception ex)
            {
                Log.Warn("DevSidecarConfig", ex, $"下载 DevSidecar 配置失败，尝试本地缓存: {url}");
                try
                {
                    if (File.Exists(cachePath))
                    {
                        var rules = Parse(File.ReadAllText(cachePath));
                        Log.Info("DevSidecarConfig", $"已加载本地缓存规则 {rules.Rules.Count} 条");
                        return rules;
                    }
                }
                catch (Exception cacheEx)
                {
                    Log.Warn("DevSidecarConfig", cacheEx, "读取 DevSidecar 本地缓存失败");
                }
                return ProxyRuleSet.Empty;
            }
        }

        public static ProxyRuleSet Parse(string json)
            => Parse(json, null);

        public static ProxyRuleSet Parse(string json, string? groupOverride)
        {
            return TryParse(json, groupOverride, out var rules, out _) ? rules : ProxyRuleSet.Empty;
        }

        /// <summary>
        /// 解析配置并返回错误信息，供自定义规则页校验使用。
        /// </summary>
        public static bool TryParse(
            string json,
            string? groupOverride,
            out ProxyRuleSet rules,
            out string? error)
        {
            rules = ProxyRuleSet.Empty;
            error = null;
            try
            {
                var normalized = Json5.ToJson(json);
                using var doc = JsonDocument.Parse(normalized, new JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    CommentHandling = JsonCommentHandling.Skip,
                    MaxDepth = 64,
                });
                rules = Convert(doc.RootElement, groupOverride);
                if (rules.Rules.Count == 0 &&
                    rules.PresetIps.Count == 0 &&
                    rules.ExcludePatterns.Count == 0)
                {
                    error = "没有解析到任何规则，请检查 intercepts 的域名和路径结构。";
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                Log.Warn("DevSidecarConfig", ex, "解析 DevSidecar 配置失败");
                return false;
            }
        }

        static ProxyRuleSet Convert(JsonElement root, string? groupOverride)
        {
            var rules = new List<ProxyRule>();
            var excludes = new List<string>();
            var presetIps = new Dictionary<string, IReadOnlyList<string>>();

            JsonElement intercepts = default;
            var hasIntercepts = false;

            if (TryGetObject(root, "server", out var server))
            {
                if (TryGetObject(server, "preSetIpList", out var preset))
                {
                    ReadPresetIps(preset, presetIps);
                }
                hasIntercepts = TryGetObject(server, "intercepts", out intercepts);
            }
            else
            {
                // 自定义规则允许省略 server 包装，直接写 intercepts / preSetIpList / excludeIpList。
                if (TryGetObject(root, "preSetIpList", out var preset))
                {
                    ReadPresetIps(preset, presetIps);
                }

                if (TryGetObject(root, "intercepts", out var directIntercepts))
                {
                    intercepts = directIntercepts;
                    hasIntercepts = true;
                }
                else if (IsInterceptMap(root))
                {
                    intercepts = root;
                    hasIntercepts = true;
                }
            }

            if (hasIntercepts)
            {
                ConvertIntercepts(intercepts, groupOverride, rules);
            }

            if (TryGetObject(root, "proxy", out var proxy))
            {
                if (TryGetObject(proxy, "excludeIpList", out var exclude))
                {
                    ReadExcludes(exclude, excludes);
                }
            }
            else if (TryGetObject(root, "excludeIpList", out var directExclude))
            {
                ReadExcludes(directExclude, excludes);
            }

            // DevSidecar 的 overwall 中继目标先记录为日志，不自动启用第三方中继。
            if (TryGetObject(root, "plugin", out var plugin) &&
                TryGetObject(plugin, "overwall", out var overwall) &&
                TryGetObject(overwall, "targets", out var targets))
            {
                var count = 0;
                foreach (var ignore in targets.EnumerateObject()) count++;
                if (count > 0)
                {
                    Log.Info("DevSidecarConfig", $"检测到 overwall 中继目标 {count} 条，当前版本不自动启用");
                }
            }

            return new ProxyRuleSet(rules, excludes, presetIps);
        }

        static void ConvertIntercepts(
            JsonElement intercepts,
            string? groupOverride,
            List<ProxyRule> rules)
        {
            foreach (var domainItem in intercepts.EnumerateObject())
            {
                if (IsReservedKey(domainItem.Name)) continue;
                if (domainItem.Value.ValueKind != JsonValueKind.Object) continue;

                var group = groupOverride ?? ProxyRuleGroups.Classify(domainItem.Name);

                foreach (var pathItem in domainItem.Value.EnumerateObject())
                {
                    if (pathItem.Value.ValueKind != JsonValueKind.Object) continue;

                    var action = pathItem.Value;
                    var rule = new ProxyRule
                    {
                        DomainPattern = domainItem.Name,
                        Group = group,
                        PathPattern = pathItem.Name == ".*" ? null : pathItem.Name,
                        Sni = GetString(action, "sni"),
                        VerifyHost = GetString(action, "verifyHost"),
                        Redirect = NormalizeTarget(GetString(action, "redirect")),
                        Proxy = NormalizeTarget(GetString(action, "proxy")),
                        BackupProxies = ReadTargetList(action, "backup"),
                        RequestHeaders = ReadHeaderReplacements(action, "requestReplace"),
                        ResponseHeaders = ReadHeaderReplacements(action, "responseReplace"),
                        UnVerifySsl = GetBool(action, "unVerifySsl"),
                        Description = GetString(action, "desc") ?? GetString(action, "remark"),
                    };

                    if (TryGetBool(action, "abort", out var abort) && abort)
                    {
                        rule = CloneWithBlock(rule);
                    }

                    if (rule.RequiresMitm || rule.Block)
                    {
                        rules.Add(rule);
                    }
                }
            }
        }

        static void ReadPresetIps(
            JsonElement preset,
            Dictionary<string, IReadOnlyList<string>> presetIps)
        {
            foreach (var item in preset.EnumerateObject())
            {
                var ips = ReadIpList(item.Value);
                if (ips.Count > 0) presetIps[item.Name] = ips;
            }
        }

        static void ReadExcludes(JsonElement exclude, List<string> excludes)
        {
            foreach (var item in exclude.EnumerateObject())
            {
                // DevSidecar 里 null/false 表示从排除列表移除，只有 true 才排除。
                if (item.Value.ValueKind == JsonValueKind.True)
                {
                    excludes.Add(item.Name);
                }
            }
        }

        static readonly string[] reservedKeys =
        {
            "server", "proxy", "plugin", "app", "help", "intercepts",
            "preSetIpList", "excludeIpList", "compatible", "ech",
        };

        static bool IsReservedKey(string name)
        {
            foreach (var key in reservedKeys)
            {
                if (string.Equals(name, key, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>
        /// 判断根对象是否直接就是“域名 → 路径 → 动作”的映射。
        /// </summary>
        static bool IsInterceptMap(JsonElement root)
        {
            if (root.ValueKind != JsonValueKind.Object) return false;

            var count = 0;
            foreach (var domain in root.EnumerateObject())
            {
                if (IsReservedKey(domain.Name)) continue;
                if (domain.Value.ValueKind != JsonValueKind.Object) return false;

                foreach (var path in domain.Value.EnumerateObject())
                {
                    if (path.Value.ValueKind != JsonValueKind.Object &&
                        path.Value.ValueKind != JsonValueKind.Null)
                    {
                        return false;
                    }
                }
                count++;
            }
            return count > 0;
        }

        static ProxyRule CloneWithBlock(ProxyRule rule) => new()
        {
            DomainPattern = rule.DomainPattern,
            Group = rule.Group,
            PathPattern = rule.PathPattern,
            Block = true,
            Description = rule.Description,
        };

        static IReadOnlyDictionary<string, string?> ReadHeaderReplacements(JsonElement action, string name)
        {
            var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            if (!TryGetObject(action, name, out var replace)) return result;
            if (!TryGetObject(replace, "headers", out var headers)) return result;

            foreach (var header in headers.EnumerateObject())
            {
                if (header.Value.ValueKind != JsonValueKind.String) continue;
                var value = header.Value.GetString();
                result[header.Name] = string.IsNullOrEmpty(value) ||
                    string.Equals(value, "[remove]", StringComparison.OrdinalIgnoreCase)
                        ? null
                        : value;
            }
            return result;
        }

        static IReadOnlyList<string> ReadTargetList(JsonElement action, string name)
        {
            var result = new List<string>();
            if (!action.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
            {
                return result;
            }

            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String) continue;
                var target = NormalizeTarget(item.GetString());
                if (!string.IsNullOrEmpty(target)) result.Add(target);
            }
            return result;
        }

        static IReadOnlyList<string> ReadIpList(JsonElement element)
        {
            var result = new List<string>();
            if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var ip in element.EnumerateArray())
                {
                    if (ip.ValueKind == JsonValueKind.String)
                    {
                        var value = ip.GetString();
                        if (!string.IsNullOrWhiteSpace(value)) result.Add(value);
                    }
                }
            }
            else if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var ip in element.EnumerateObject())
                {
                    if (ip.Value.ValueKind == JsonValueKind.True ||
                        ip.Value.ValueKind == JsonValueKind.Object)
                    {
                        result.Add(ip.Name);
                    }
                }
            }
            return result;
        }

        static string? NormalizeTarget(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            value = value.Trim();
            if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                Log.Warn("DevSidecarConfig", $"忽略非 HTTPS 目标: {value}");
                return null;
            }
            if (!value.Contains("://", StringComparison.Ordinal))
            {
                value = "https://" + value.TrimStart('/');
            }
            return value;
        }

        static bool TryGetObject(JsonElement element, string name, out JsonElement value)
        {
            if (element.ValueKind == JsonValueKind.Object &&
                element.TryGetProperty(name, out value) &&
                value.ValueKind == JsonValueKind.Object)
            {
                return true;
            }
            value = default;
            return false;
        }

        static string? GetString(JsonElement element, string name)
        {
            if (element.ValueKind == JsonValueKind.Object &&
                element.TryGetProperty(name, out var value) &&
                value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }
            return null;
        }

        static bool GetBool(JsonElement element, string name)
            => TryGetBool(element, name, out var value) && value;

        static bool TryGetBool(JsonElement element, string name, out bool value)
        {
            if (element.ValueKind == JsonValueKind.Object &&
                element.TryGetProperty(name, out var prop))
            {
                if (prop.ValueKind == JsonValueKind.True) { value = true; return true; }
                if (prop.ValueKind == JsonValueKind.False) { value = false; return true; }
            }
            value = false;
            return false;
        }
    }
}
