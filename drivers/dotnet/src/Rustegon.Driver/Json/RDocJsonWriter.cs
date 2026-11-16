// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver.Internal.Json;

/// <summary>
/// Canonical / extended JSON output (data-model.md §2), character for character what
/// <c>crates/rustegon-doc/src/json/mod.rs</c> writes: compact, fields in stored order, only
/// <c>"</c>, <c>\</c> and C0 controls escaped, non-ASCII verbatim.
/// </summary>
internal static class RDocJsonWriter
{
    // Largest integer magnitude a JSON number carries without loss in IEEE-double parsers.
    private const ulong MaxSafeInteger = 1UL << 53;

    internal static string WriteDocument(RDocument doc, RDocJsonMode mode)
    {
        var sb = new StringBuilder();
        Document(sb, doc, mode);
        return sb.ToString();
    }

    internal static string WriteValue(RDocValue v, RDocJsonMode mode)
    {
        var sb = new StringBuilder();
        Value(sb, v, mode);
        return sb.ToString();
    }

    private static void Document(StringBuilder sb, RDocument doc, RDocJsonMode mode)
    {
        sb.Append('{');
        bool first = true;
        foreach (KeyValuePair<string, RDocValue> f in doc)
        {
            if (!first)
            {
                sb.Append(',');
            }

            first = false;
            String(sb, f.Key);
            sb.Append(':');
            Value(sb, f.Value, mode);
        }

        sb.Append('}');
    }

    private static void Wrap(StringBuilder sb, string key, string quotedValue) =>
        sb.Append("{\"").Append(key).Append("\":\"").Append(quotedValue).Append("\"}");

    private static void Value(StringBuilder sb, RDocValue v, RDocJsonMode mode)
    {
        CultureInfo inv = CultureInfo.InvariantCulture;
        switch (v.Type)
        {
            case RDocType.Null:
                sb.Append("null");
                break;
            case RDocType.Bool:
                sb.Append(v.AsBoolean() ? "true" : "false");
                break;
            case RDocType.Int64:
                long i = v.AsInt64();
                if (mode == RDocJsonMode.Canonical && (i < 0 ? (ulong)-(i + 1) + 1 : (ulong)i) <= MaxSafeInteger)
                {
                    sb.Append(i.ToString(inv));
                }
                else
                {
                    Wrap(sb, "$int64", i.ToString(inv));
                }

                break;
            case RDocType.Float64:
                Float(sb, v.AsDouble(), mode);
                break;
            case RDocType.Decimal128:
                Wrap(sb, "$decimal", v.AsDecimal128().ToString());
                break;
            case RDocType.String:
                String(sb, v.AsString());
                break;
            case RDocType.Binary:
                sb.Append("{\"$binary\":{\"base64\":\"").Append(Convert.ToBase64String(v.AsBinary().Span))
                  .Append("\",\"subType\":\"").Append(v.BinarySubtypeValue.ToString("x2", inv)).Append("\"}}");
                break;
            case RDocType.DateTime:
                Wrap(sb, "$date", DateTimeText.Format(v.AsUnixTimeMilliseconds()));
                break;
            case RDocType.Timestamp:
                Wrap(sb, "$ts", v.AsTimestamp().ToString());
                break;
            case RDocType.ObjectId:
                Wrap(sb, "$oid", v.AsObjectId().ToString());
                break;
            case RDocType.Uuid:
                Wrap(sb, "$uuid", v.AsGuid().ToString("D"));
                break;
            case RDocType.Array:
                sb.Append('[');
                RDocArray items = v.AsArray();
                for (int k = 0; k < items.Count; k++)
                {
                    if (k > 0)
                    {
                        sb.Append(',');
                    }

                    Value(sb, items[k], mode);
                }

                sb.Append(']');
                break;
            case RDocType.Object:
                Document(sb, v.AsDocument(), mode);
                break;
            case RDocType.VectorF32:
                sb.Append("{\"$vector\":[");
                ReadOnlySpan<float> xs = v.AsVector().Span;
                for (int k = 0; k < xs.Length; k++)
                {
                    if (k > 0)
                    {
                        sb.Append(',');
                    }

                    sb.Append(FloatText.Format(xs[k]));
                }

                sb.Append("]}");
                break;
            case RDocType.Counter:
                sb.Append("{\"$counter\":").Append(v.AsCounter().ToString(inv)).Append('}');
                break;
            case RDocType.MinKey:
                sb.Append("{\"$minKey\":1}");
                break;
            case RDocType.MaxKey:
                sb.Append("{\"$maxKey\":1}");
                break;
            default:
                throw new RDocException(ErrorCodes.InvalidArgument, "a missing value has no JSON form");
        }
    }

    private static void Float(StringBuilder sb, double f, RDocJsonMode mode)
    {
        if (double.IsNaN(f))
        {
            Wrap(sb, "$float", "NaN");
        }
        else if (double.IsInfinity(f))
        {
            Wrap(sb, "$float", f > 0 ? "Infinity" : "-Infinity");
        }
        else if (mode == RDocJsonMode.Canonical)
        {
            sb.Append(FloatText.Format(f));
        }
        else
        {
            Wrap(sb, "$float", FloatText.Format(f));
        }
    }

    /// <summary>Minimal escaping: <c>"</c>, <c>\</c> and C0 controls (short forms where JSON has them).</summary>
    private static void String(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                case < ' ':
                    sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }

        sb.Append('"');
    }
}
