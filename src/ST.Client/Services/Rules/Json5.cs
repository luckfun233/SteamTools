using System;
using System.Text;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 极简 JSON5 → JSON 规整器，只处理 DevSidecar 配置实际使用的语法：
    /// 单行/块注释、单引号字符串、未加引号的属性名、尾随逗号。
    /// 目的是复用 System.Text.Json，而不是实现一个完整的 JSON5 解析器。
    /// </summary>
    public static class Json5
    {
        public static string ToJson(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            if (text[0] == '\uFEFF') text = text.Substring(1);

            var sb = new StringBuilder(text.Length + 256);
            var length = text.Length;
            var i = 0;

            while (i < length)
            {
                var c = text[i];

                if (c == '/' && i + 1 < length)
                {
                    var next = text[i + 1];
                    if (next == '/')
                    {
                        i += 2;
                        while (i < length && text[i] != '\n' && text[i] != '\r') i++;
                        continue;
                    }
                    if (next == '*')
                    {
                        i += 2;
                        while (i + 1 < length && !(text[i] == '*' && text[i + 1] == '/')) i++;
                        i = Math.Min(length, i + 2);
                        continue;
                    }
                }

                if (c == '"' || c == '\'')
                {
                    i = CopyString(text, i, sb);
                    continue;
                }

                if (c == ',')
                {
                    var j = SkipTrivia(text, i + 1);
                    if (j < length && (text[j] == '}' || text[j] == ']'))
                    {
                        // JSON5 允许尾随逗号，JSON 不允许。
                        i++;
                        continue;
                    }
                    sb.Append(c);
                    i++;
                    continue;
                }

                if (IsIdentifierStart(c))
                {
                    var start = i;
                    i++;
                    while (i < length && IsIdentifierPart(text[i])) i++;

                    var j = SkipTrivia(text, i);
                    if (j < length && text[j] == ':')
                    {
                        // 未加引号的属性名。
                        sb.Append('"').Append(text, start, i - start).Append('"');
                    }
                    else
                    {
                        sb.Append(text, start, i - start);
                    }
                    continue;
                }

                sb.Append(c);
                i++;
            }

            return sb.ToString();
        }

        static int CopyString(string text, int start, StringBuilder sb)
        {
            var quote = text[start];
            var i = start + 1;
            var length = text.Length;

            sb.Append('"');
            while (i < length)
            {
                var c = text[i];
                if (c == '\\')
                {
                    if (i + 1 >= length)
                    {
                        i++;
                        break;
                    }

                    var escape = text[i + 1];
                    switch (escape)
                    {
                        case '\n':
                            i += 2;
                            continue;
                        case '\r':
                            i += 2;
                            if (i < length && text[i] == '\n') i++;
                            continue;
                        case '\'' when quote == '\'':
                            sb.Append('\'');
                            i += 2;
                            continue;
                        case '"' when quote == '\'':
                            sb.Append("\\\"");
                            i += 2;
                            continue;
                        case 'x':
                            if (i + 3 < length)
                            {
                                sb.Append("\\u00").Append(text, i + 2, 2);
                                i += 4;
                                continue;
                            }
                            break;
                        case 'v':
                            sb.Append("\\u000b");
                            i += 2;
                            continue;
                        case '0':
                            sb.Append("\\u0000");
                            i += 2;
                            continue;
                    }

                    sb.Append('\\').Append(escape);
                    i += 2;
                    continue;
                }

                if (c == quote)
                {
                    i++;
                    break;
                }

                if (c == '"')
                {
                    sb.Append("\\\"");
                    i++;
                    continue;
                }

                sb.Append(c);
                i++;
            }
            sb.Append('"');
            return i;
        }

        static int SkipTrivia(string text, int i)
        {
            var length = text.Length;
            while (i < length)
            {
                var c = text[i];
                if (char.IsWhiteSpace(c))
                {
                    i++;
                    continue;
                }
                if (c == '/' && i + 1 < length)
                {
                    if (text[i + 1] == '/')
                    {
                        i += 2;
                        while (i < length && text[i] != '\n' && text[i] != '\r') i++;
                        continue;
                    }
                    if (text[i + 1] == '*')
                    {
                        i += 2;
                        while (i + 1 < length && !(text[i] == '*' && text[i + 1] == '/')) i++;
                        i = Math.Min(length, i + 2);
                        continue;
                    }
                }
                break;
            }
            return i;
        }

        static bool IsIdentifierStart(char c)
            => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$';

        static bool IsIdentifierPart(char c)
            => IsIdentifierStart(c) || (c >= '0' && c <= '9');
    }
}
