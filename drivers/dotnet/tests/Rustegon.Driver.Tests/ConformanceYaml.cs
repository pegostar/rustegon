// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Rustegon.Driver.Tests;

/// <summary>
/// Reader of the YAML subset used by <c>drivers/conformance/</c> (README §3/§5: the JSON-compatible
/// subset): block mappings and sequences, flow <c>{…}</c> / <c>[…]</c>, double-quoted scalars with
/// YAML escapes, plain scalars (<c>null</c>/<c>~</c>, booleans, integers, floats, text) and
/// comments. Results: <see cref="Dictionary{TKey,TValue}"/> (string keys, insertion order kept by
/// the list of keys), <see cref="List{T}"/>, <see cref="string"/>, <see cref="long"/>,
/// <see cref="double"/>, <see cref="bool"/> or null. Anything outside the subset throws, so a
/// file using a new YAML feature fails loudly instead of being misread. A test-only helper: the
/// driver itself has no YAML dependency.
/// </summary>
internal static class ConformanceYaml
{
    internal static object? Load(string path) => Parse(File.ReadAllText(path, Encoding.UTF8));

    internal static object? Parse(string text)
    {
        var lines = new List<(int Indent, string Text, int Number)>();
        string[] raw = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        for (int i = 0; i < raw.Length; i++)
        {
            string content = StripComment(raw[i]).TrimEnd();
            if (content.Trim().Length == 0 || content.Trim() == "---")
            {
                continue;
            }

            int indent = content.Length - content.TrimStart(' ').Length;
            if (content[indent] == '\t')
            {
                throw new FormatException($"line {i + 1}: tabs are not allowed in YAML indentation");
            }

            lines.Add((indent, content[indent..], i + 1));
        }

        int pos = 0;
        object? result = lines.Count == 0 ? null : ParseBlock(lines, ref pos, lines[0].Indent);
        if (pos != lines.Count)
        {
            throw new FormatException($"line {lines[pos].Number}: unexpected content");
        }

        return result;
    }

    private static object? ParseBlock(List<(int Indent, string Text, int Number)> lines, ref int pos, int indent)
    {
        return lines[pos].Text.StartsWith("- ", StringComparison.Ordinal) || lines[pos].Text == "-"
            ? ParseSequence(lines, ref pos, indent)
            : ParseMapping(lines, ref pos, indent, null);
    }

    private static List<object?> ParseSequence(List<(int Indent, string Text, int Number)> lines, ref int pos, int indent)
    {
        var list = new List<object?>();
        while (pos < lines.Count && lines[pos].Indent == indent && (lines[pos].Text.StartsWith("- ", StringComparison.Ordinal) || lines[pos].Text == "-"))
        {
            (int _, string text, int number) = lines[pos];
            string item = text.Length > 1 ? text[2..].TrimStart() : string.Empty;
            int itemIndent = indent + (text.Length - item.Length);
            if (item.Length == 0)
            {
                pos++;
                list.Add(pos < lines.Count && lines[pos].Indent > indent ? ParseBlock(lines, ref pos, lines[pos].Indent) : null);
            }
            else if (item[0] is '{' or '[' or '"' || FindMappingColon(item) < 0)
            {
                pos++;
                list.Add(ParseFlowWhole(item, number));
            }
            else
            {
                // `- key: value` opens a mapping whose further keys sit at the item's column.
                lines[pos] = (itemIndent, item, number);
                list.Add(ParseMapping(lines, ref pos, itemIndent, null));
            }
        }

        return list;
    }

    private static Dictionary<string, object?> ParseMapping(List<(int Indent, string Text, int Number)> lines, ref int pos, int indent, Dictionary<string, object?>? into)
    {
        var map = into ?? new Dictionary<string, object?>(StringComparer.Ordinal);
        while (pos < lines.Count && lines[pos].Indent == indent && !lines[pos].Text.StartsWith("- ", StringComparison.Ordinal))
        {
            (int _, string text, int number) = lines[pos];
            int colon = FindMappingColon(text);
            if (colon < 0)
            {
                throw new FormatException($"line {number}: expected 'key: value'");
            }

            string key = ParseKey(text[..colon].Trim(), number);
            string rest = text[(colon + 1)..].Trim();
            pos++;
            object? value;
            if (rest.Length > 0)
            {
                value = ParseFlowWhole(rest, number);
            }
            else if (pos < lines.Count && (lines[pos].Indent > indent
                || (lines[pos].Indent == indent && lines[pos].Text.StartsWith("- ", StringComparison.Ordinal))))
            {
                value = ParseBlock(lines, ref pos, lines[pos].Indent);
            }
            else
            {
                value = null;
            }

            if (!map.TryAdd(key, value))
            {
                throw new FormatException($"line {number}: duplicate key '{key}'");
            }
        }

        return map;
    }

    private static string ParseKey(string key, int number) =>
        key.StartsWith('"') ? (string)ParseFlowWhole(key, number)! : key;

    /// <summary>The colon of <c>key: value</c> outside quotes and brackets, or -1.</summary>
    private static int FindMappingColon(string text)
    {
        bool quoted = false;
        int depth = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quoted)
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == '"')
                {
                    quoted = false;
                }
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c is '{' or '[')
            {
                depth++;
            }
            else if (c is '}' or ']')
            {
                depth--;
            }
            else if (c == ':' && depth == 0 && (i + 1 == text.Length || text[i + 1] == ' '))
            {
                return i;
            }
        }

        return -1;
    }

    private static string StripComment(string line)
    {
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (quoted)
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == '"')
                {
                    quoted = false;
                }
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c == '#' && (i == 0 || line[i - 1] == ' '))
            {
                return line[..i];
            }
        }

        return line;
    }

    private static object? ParseFlowWhole(string text, int number)
    {
        int i = 0;
        object? v = ParseFlow(text, ref i, number, false);
        SkipSpaces(text, ref i);
        return i == text.Length ? v : throw new FormatException($"line {number}: trailing text '{text[i..]}'");
    }

    private static object? ParseFlow(string s, ref int i, int number, bool inFlow)
    {
        SkipSpaces(s, ref i);
        if (i >= s.Length)
        {
            throw new FormatException($"line {number}: missing value");
        }

        switch (s[i])
        {
            case '{':
                {
                    i++;
                    var map = new Dictionary<string, object?>(StringComparer.Ordinal);
                    SkipSpaces(s, ref i);
                    if (i < s.Length && s[i] == '}')
                    {
                        i++;
                        return map;
                    }

                    while (true)
                    {
                        SkipSpaces(s, ref i);
                        string key = s[i] == '"' ? ParseQuoted(s, ref i, number) : ParsePlainText(s, ref i, true, true);
                        SkipSpaces(s, ref i);
                        Expect(s, ref i, ':', number);
                        object? value = ParseFlow(s, ref i, number, true);
                        if (!map.TryAdd(key, value))
                        {
                            throw new FormatException($"line {number}: duplicate key '{key}'");
                        }

                        SkipSpaces(s, ref i);
                        if (i < s.Length && s[i] == ',')
                        {
                            i++;
                            continue;
                        }

                        Expect(s, ref i, '}', number);
                        return map;
                    }
                }

            case '[':
                {
                    i++;
                    var list = new List<object?>();
                    SkipSpaces(s, ref i);
                    if (i < s.Length && s[i] == ']')
                    {
                        i++;
                        return list;
                    }

                    while (true)
                    {
                        list.Add(ParseFlow(s, ref i, number, true));
                        SkipSpaces(s, ref i);
                        if (i < s.Length && s[i] == ',')
                        {
                            i++;
                            continue;
                        }

                        Expect(s, ref i, ']', number);
                        return list;
                    }
                }

            case '"':
                return ParseQuoted(s, ref i, number);
            case '\'':
                throw new FormatException($"line {number}: single-quoted scalars are outside the conformance subset");
            default:
                return PlainScalar(ParsePlainText(s, ref i, inFlow, false));
        }
    }

    private static void Expect(string s, ref int i, char c, int number)
    {
        if (i >= s.Length || s[i] != c)
        {
            throw new FormatException($"line {number}: expected '{c}'");
        }

        i++;
    }

    private static void SkipSpaces(string s, ref int i)
    {
        while (i < s.Length && s[i] == ' ')
        {
            i++;
        }
    }

    private static string ParsePlainText(string s, ref int i, bool inFlow, bool key)
    {
        int start = i;
        while (i < s.Length)
        {
            char c = s[i];
            if (inFlow && (c is ',' or '}' or ']'))
            {
                break;
            }

            if (key && c == ':')
            {
                break;
            }

            i++;
        }

        return s[start..i].TrimEnd();
    }

    private static object? PlainScalar(string text)
    {
        switch (text)
        {
            case "null" or "~" or "Null" or "NULL":
                return null;
            case "true" or "True" or "TRUE":
                return true;
            case "false" or "False" or "FALSE":
                return false;
        }

        if (long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long l))
        {
            return l;
        }

        if ((text.Contains('.', StringComparison.Ordinal) || text.Contains('e', StringComparison.OrdinalIgnoreCase))
            && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
        {
            return d;
        }

        return text;
    }

    private static string ParseQuoted(string s, ref int i, int number)
    {
        i++;
        var sb = new StringBuilder();
        while (true)
        {
            if (i >= s.Length)
            {
                throw new FormatException($"line {number}: unterminated string");
            }

            char c = s[i++];
            if (c == '"')
            {
                return sb.ToString();
            }

            if (c != '\\')
            {
                sb.Append(c);
                continue;
            }

            char e = s[i++];
            switch (e)
            {
                case '"' or '\\' or '/':
                    sb.Append(e);
                    break;
                case '0':
                    sb.Append('\0');
                    break;
                case 'a':
                    sb.Append('\a');
                    break;
                case 'b':
                    sb.Append('\b');
                    break;
                case 't':
                    sb.Append('\t');
                    break;
                case 'n':
                    sb.Append('\n');
                    break;
                case 'v':
                    sb.Append('\v');
                    break;
                case 'f':
                    sb.Append('\f');
                    break;
                case 'r':
                    sb.Append('\r');
                    break;
                case 'e':
                    sb.Append('\u001b');
                    break;
                case ' ':
                    sb.Append(' ');
                    break;
                case 'x':
                    sb.Append((char)int.Parse(s.AsSpan(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                    i += 2;
                    break;
                case 'u':
                    // UTF-16 code units: a surrogate pair written as two \u escapes recombines here.
                    sb.Append((char)int.Parse(s.AsSpan(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                    i += 4;
                    break;
                case 'U':
                    sb.Append(char.ConvertFromUtf32(int.Parse(s.AsSpan(i, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture)));
                    i += 8;
                    break;
                default:
                    throw new FormatException($"line {number}: unknown escape '\\{e}'");
            }
        }
    }
}
