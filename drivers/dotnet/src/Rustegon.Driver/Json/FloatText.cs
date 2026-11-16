// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Globalization;
using System.Text;

namespace Rustegon.Driver.Internal.Json;

/// <summary>
/// Float text of the canonical JSON form: the shortest round-trip digits, printed as Rust's
/// <c>{:?}</c> does (what the server writes, data-model.md §2): plain decimal with at least one
/// fraction digit when 1e-4 ≤ |x| &lt; 1e16 (or x = 0), else <c>d[.ddd]e&lt;exp&gt;</c>
/// (<c>1e300</c>, <c>5e-324</c>, <c>1.5e-7</c>). .NET supplies the shortest digits ("R"); only the
/// layout is converted.
/// </summary>
internal static class FloatText
{
    private const double PlainMinDouble = 1e-4;
    private const double PlainLimitDouble = 1e16;
    private const float PlainMinSingle = 1e-4f;
    private const float PlainLimitSingle = 1e16f;

    /// <summary>Text of a finite float64.</summary>
    internal static string Format(double x)
    {
        double abs = Math.Abs(x);
        bool exponential = abs != 0 && (abs < PlainMinDouble || abs >= PlainLimitDouble);
        return Layout(x.ToString("R", CultureInfo.InvariantCulture), exponential);
    }

    /// <summary>Text of a finite float32 (vector elements).</summary>
    internal static string Format(float x)
    {
        float abs = Math.Abs(x);
        bool exponential = abs != 0 && (abs < PlainMinSingle || abs >= PlainLimitSingle);
        return Layout(x.ToString("R", CultureInfo.InvariantCulture), exponential);
    }

    /// <summary>Re-lays out .NET's shortest round-trip text (<c>[-]d[.d][E[+-]d]</c>).</summary>
    private static string Layout(string r, bool exponential)
    {
        bool negative = r.StartsWith('-');
        ReadOnlySpan<char> s = negative ? r.AsSpan(1) : r.AsSpan();
        int e = s.IndexOfAny('E', 'e');
        int exp = 0;
        if (e >= 0)
        {
            exp = int.Parse(s[(e + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            s = s[..e];
        }

        int point = s.IndexOf('.');
        string digits = point < 0 ? s.ToString() : string.Concat(s[..point], s[(point + 1)..]);
        int intLength = point < 0 ? s.Length : point;

        // value = digits × 10^(exp + intLength − digits.Length); strip zeros on both sides.
        int e10 = exp + intLength - digits.Length;
        string d = digits.TrimStart('0');
        int trimmed = d.Length;
        d = d.TrimEnd('0');
        e10 += trimmed - d.Length;

        var sb = new StringBuilder(32);
        if (negative)
        {
            sb.Append('-');
        }

        if (d.Length == 0)
        {
            return sb.Append("0.0").ToString();
        }

        if (exponential)
        {
            sb.Append(d[0]);
            if (d.Length > 1)
            {
                sb.Append('.').Append(d, 1, d.Length - 1);
            }

            return sb.Append('e').Append((e10 + d.Length - 1).ToString(CultureInfo.InvariantCulture)).ToString();
        }

        if (e10 >= 0)
        {
            return sb.Append(d).Append('0', e10).Append(".0").ToString();
        }

        int pointAt = d.Length + e10;
        if (pointAt > 0)
        {
            return sb.Append(d, 0, pointAt).Append('.').Append(d, pointAt, d.Length - pointAt).ToString();
        }

        return sb.Append("0.").Append('0', -pointAt).Append(d).ToString();
    }
}
