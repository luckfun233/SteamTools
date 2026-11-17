using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 读取 DevSidecar 配置里的分组注释。
    ///
    /// DevSidecar 2.3.x 的服务分组规则：`//` 注释之后的文字去掉空白后作为组名，
    /// 一个 `// GitHub` 注释会作用于其后的所有服务，直到出现下一个分组注释。
    /// 这里只解析 server.intercepts / server.preSetIpList / server.dns.mapping / server.whiteList
    /// 四个区块的顶层键，注释在更深层（例如某个域名的动作里）时忽略。
    /// </summary>
    public static class DevSidecarCommentGroups
    {
        static readonly string[] sectionKeys = { "intercepts", "preSetIpList", "mapping", "whiteList" };

        public static IReadOnlyDictionary<string, string> Parse(string json5)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(json5)) return result;

            foreach (var section in sectionKeys)
            {
                var block = ExtractNamedBlock(json5, section);
                if (block == null) continue;
                ParseTopLevelKeys(block, result);
            }

            return result;
        }

        static string? ExtractNamedBlock(string text, string key)
        {
            var pattern = @"(?:^|[\s,{])[""']?" + Regex.Escape(key) + @"[""']?\s*:\s*\{";
            var match = Regex.Match(text, pattern, RegexOptions.CultureInvariant);
            if (!match.Success) return null;

            var open = text.IndexOf('{', match.Index, match.Length);
            if (open < 0) return null;
            return ExtractBlock(text, open);
        }

        static string? ExtractBlock(string text, int openBraceIndex)
        {
            var depth = 1;
            var inString = '\0';
            var inLineComment = false;
            var inBlockComment = false;

            for (var i = openBraceIndex + 1; i < text.Length; i++)
            {
                var c = text[i];
                var next = i + 1 < text.Length ? text[i + 1] : '\0';

                if (inLineComment)
                {
                    if (c == '\n') inLineComment = false;
                    continue;
                }
                if (inBlockComment)
                {
                    if (c == '*' && next == '/')
                    {
                        inBlockComment = false;
                        i++;
                    }
                    continue;
                }
                if (inString != '\0')
                {
                    if (c == '\\') { i++; continue; }
                    if (c == inString) inString = '\0';
                    continue;
                }

                if (c == '/' && next == '/') { inLineComment = true; i++; continue; }
                if (c == '/' && next == '*') { inBlockComment = true; i++; continue; }
                if (c == '"' || c == '\'') { inString = c; continue; }
                if (c == '{') depth++;
                else if (c == '}')
                {
                    depth--;
                    if (depth == 0) return text.Substring(openBraceIndex + 1, i - openBraceIndex - 1);
                }
            }
            return null;
        }

        /// <summary>
        /// 扫描区块内容，记录 depth 0 的键和组注释。
        /// </summary>
        static void ParseTopLevelKeys(string block, Dictionary<string, string> result)
        {
            var depth = 0;
            var inString = '\0';
            var inLineComment = false;
            var inBlockComment = false;
            string? currentGroup = null;
            var lineStart = 0;

            for (var i = 0; i < block.Length; i++)
            {
                var c = block[i];
                var next = i + 1 < block.Length ? block[i + 1] : '\0';

                if (inLineComment)
                {
                    if (c == '\n')
                    {
                        inLineComment = false;
                        lineStart = i + 1;
                    }
                    continue;
                }
                if (inBlockComment)
                {
                    if (c == '*' && next == '/') { inBlockComment = false; i++; }
                    if (c == '\n') lineStart = i + 1;
                    continue;
                }
                if (inString != '\0')
                {
                    if (c == '\\') { i++; continue; }
                    if (c == inString) inString = '\0';
                    continue;
                }

                if (c == '"' || c == '\'')
                {
                    // 顶层字符串键
                    if (depth == 0)
                    {
                        var read = ReadQuoted(block, i);
                        if (read != null)
                        {
                            var after = read.Value.Next;
                            while (after < block.Length && (block[after] == ' ' || block[after] == '\t' || block[after] == '\r')) after++;
                            if (after < block.Length && block[after] == ':')
                            {
                                var key = read.Value.Value;
                                var trailing = ReadTrailingComment(block, after + 1);
                                if (trailing != null) result[key] = trailing;
                                else if (currentGroup != null) result[key] = currentGroup;
                                else if (!result.ContainsKey(key)) result[key] = ProxyRuleGroups.Unclassified;
                                i = after;
                                continue;
                            }
                        }
                    }

                    inString = c;
                    continue;
                }

                if (c == '/' && next == '/')
                {
                    var end = block.IndexOf('\n', i);
                    if (end < 0) end = block.Length;
                    var comment = Normalize(block.Substring(i + 2, end - i - 2));
                    var before = block.Substring(lineStart, i - lineStart);
                    if (comment != null && string.IsNullOrWhiteSpace(before) && depth == 0)
                    {
                        currentGroup = comment;
                    }
                    i = end - 1;
                    continue;
                }

                if (c == '/' && next == '*')
                {
                    inBlockComment = true;
                    i++;
                    continue;
                }

                if (c == '{') { depth++; continue; }
                if (c == '}') { depth--; continue; }
                if (c == '\n') { lineStart = i + 1; continue; }

                // 未加引号的键（JSON5 允许）
                if (depth == 0 && (char.IsLetter(c) || c == '_' || c == '$'))
                {
                    var end = i;
                    while (end < block.Length && (char.IsLetterOrDigit(block[end]) || block[end] == '_' || block[end] == '$' || block[end] == '.' || block[end] == '-'))
                    {
                        end++;
                    }
                    var after = end;
                    while (after < block.Length && (block[after] == ' ' || block[after] == '\t' || block[after] == '\r')) after++;
                    if (after < block.Length && block[after] == ':')
                    {
                        var key = block.Substring(i, end - i);
                        var trailing = ReadTrailingComment(block, after + 1);
                        if (trailing != null) result[key] = trailing;
                        else if (currentGroup != null) result[key] = currentGroup;
                        i = after;
                        continue;
                    }
                }
            }
        }

        static (string Value, int Next)? ReadQuoted(string text, int start)
        {
            var quote = text[start];
            var sb = new StringBuilder();
            for (var i = start + 1; i < text.Length; i++)
            {
                var c = text[i];
                if (c == '\\')
                {
                    if (i + 1 >= text.Length) return null;
                    sb.Append(text[i + 1]);
                    i++;
                    continue;
                }
                if (c == quote) return (sb.ToString(), i + 1);
                sb.Append(c);
            }
            return null;
        }

        /// <summary>
        /// 读取键所在行的行尾注释。只扫描到换行，且忽略字符串里的 //。
        /// </summary>
        static string? ReadTrailingComment(string block, int start)
        {
            var inString = '\0';
            for (var i = start; i < block.Length; i++)
            {
                var c = block[i];
                if (c == '\n') return null;
                if (inString != '\0')
                {
                    if (c == '\\') { i++; continue; }
                    if (c == inString) inString = '\0';
                    continue;
                }
                if (c == '"' || c == '\'') { inString = c; continue; }
                if (c == '/' && i + 1 < block.Length && block[i + 1] == '/')
                {
                    return Normalize(block.Substring(i + 2));
                }
            }
            return null;
        }

        static string? Normalize(string comment)
        {
            if (string.IsNullOrWhiteSpace(comment)) return null;
            if (IsJsonLikeComment(comment)) return null;

            var sb = new StringBuilder(comment.Length);
            foreach (var c in comment)
            {
                if (!char.IsWhiteSpace(c) && !char.IsControl(c)) sb.Append(c);
            }
            var value = sb.ToString();
            if (value.Length == 0) return null;
            return value.Length > 64 ? value.Substring(0, 64) : value;
        }

        static bool IsJsonLikeComment(string comment)
        {
            var value = comment.TrimStart();
            if (value.StartsWith("[", StringComparison.Ordinal) ||
                value.StartsWith("{", StringComparison.Ordinal) ||
                value.StartsWith("\"", StringComparison.Ordinal) ||
                value.StartsWith("'", StringComparison.Ordinal) ||
                value.StartsWith("@", StringComparison.Ordinal) ||
                value.StartsWith("}", StringComparison.Ordinal) ||
                value.StartsWith("]", StringComparison.Ordinal))
            {
                return true;
            }
            if (value.Contains("\":", StringComparison.Ordinal) || value.Contains("':", StringComparison.Ordinal))
            {
                return true;
            }
            var punctuation = 0;
            foreach (var c in value)
            {
                if (!char.IsWhiteSpace(c)) punctuation++;
            }
            if (punctuation == 0) return true;
            if (value.Length <= 8 && value.All(c => "{}[],:\"'` ".IndexOf(c) >= 0)) return true;
            return false;
        }
    }
}
