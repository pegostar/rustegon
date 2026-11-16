// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Rustegon.Driver.Internal.Codec;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver.Internal.Json;

/// <summary>
/// JSON / extended-JSON parser (RFC 8259 syntax, semantics of data-model.md §2), a port of
/// <c>crates/rustegon-doc/src/json/parse.rs</c>. A hand-written recursive-descent parser rather
/// than System.Text.Json: it must see duplicate names, keep the integer/float distinction and the
/// exact number text, and stop at the document depth limit before recursing further.
/// </summary>
/// <remarks>
/// Number rules: integers within i64 → int64; integers beyond it → nearest float64; a fraction or
/// exponent → float64; a magnitude beyond the float64 range → RGN-1001. Names: duplicates and
/// <c>$</c>-prefixed names outside a single-key wrapper → RGN-1004, as is <c>{"$counter":…}</c>.
/// </remarks>
internal ref struct RDocJsonReader
{
    private const int UuidTextLength = 36;

    private readonly string _s;
    private int _pos;

    private RDocJsonReader(string s)
    {
        _s = s;
        _pos = 0;
    }

    /// <summary>A number token with its text.</summary>
    private readonly record struct Number(string Text, bool Integral);

    internal static RDocument ParseDocument(string text)
    {
        RDocValue v = ParseValue(text);
        return v.Type == RDocType.Object ? v.AsDocument() : throw new RDocException(ErrorCodes.InvalidArgument, "a document must be a JSON object", 0);
    }

    internal static RDocValue ParseValue(string text)
    {
        var p = new RDocJsonReader(text);
        p.Ws();
        RDocValue v = p.Value(0);
        p.Ws();
        return p._pos == p._s.Length ? v : throw p.Error("trailing characters");
    }

    private readonly RDocException Error(string reason) => new(ErrorCodes.InvalidArgument, reason, _pos);

    private readonly char? Peek() => _pos < _s.Length ? _s[_pos] : null;

    private void Ws()
    {
        while (Peek() is ' ' or '\t' or '\n' or '\r')
        {
            _pos++;
        }
    }

    private void Eat(char c)
    {
        Ws();
        if (Peek() != c)
        {
            throw Error($"expected '{c}'");
        }

        _pos++;
    }

    private RDocValue Literal(string word, RDocValue v)
    {
        if (string.CompareOrdinal(_s, _pos, word, 0, word.Length) != 0)
        {
            throw Error("invalid literal");
        }

        _pos += word.Length;
        return v;
    }

    /// <summary>Parses a value; <paramref name="depth"/> is the depth of the enclosing container (0 at top level).</summary>
    private RDocValue Value(int depth)
    {
        Ws();
        switch (Peek())
        {
            case '{':
                return Object(depth + 1);
            case '[':
                return RDocValue.FromArray(Array(depth + 1));
            case '"':
                return RDocValue.FromString(String());
            case 't':
                return Literal("true", RDocValue.FromBoolean(true));
            case 'f':
                return Literal("false", RDocValue.FromBoolean(false));
            case 'n':
                return Literal("null", RDocValue.Null);
            case '-' or (>= '0' and <= '9'):
                return NumberValue(ScanNumber());
            default:
                throw Error("expected a value");
        }
    }

    private static void CheckDepth(int depth)
    {
        if (depth > 100)
        {
            throw new RDocException(ErrorCodes.NestingTooDeep, "nesting deeper than 100 levels");
        }
    }

    private RDocArray Array(int depth)
    {
        CheckDepth(depth);
        _pos++; // '['
        var items = new RDocArray();
        Ws();
        if (Peek() == ']')
        {
            _pos++;
            return items;
        }

        while (true)
        {
            items.AddUnchecked(Value(depth));
            Ws();
            switch (Peek())
            {
                case ',':
                    _pos++;
                    break;
                case ']':
                    _pos++;
                    return items;
                default:
                    throw Error("expected ',' or ']'");
            }
        }
    }

    private RDocValue Object(int depth)
    {
        CheckDepth(depth);
        _pos++; // '{'
        var doc = new RDocument();
        Ws();
        if (Peek() == '}')
        {
            _pos++;
            return RDocValue.FromDocument(doc);
        }

        while (true)
        {
            Ws();
            if (Peek() != '"')
            {
                throw Error("expected a field name");
            }

            string name = String();
            Eat(':');
            if (doc.Count == 0 && name.StartsWith('$'))
            {
                // A `$` name is legal only as the single key of an extended-JSON wrapper.
                RDocValue w = Wrapper(name);
                Eat('}');
                return w;
            }

            string? nameError = RDocFormat.FieldNameError(name, RDocWriter.Utf8Length(name, fieldName: true));
            if (nameError is not null)
            {
                throw new RDocException(ErrorCodes.InvalidFieldName, nameError, _pos);
            }

            RDocValue v = Value(depth);
            if (!doc.TryAdd(name, v))
            {
                throw new RDocException(ErrorCodes.InvalidFieldName, "duplicate field name", _pos);
            }

            Ws();
            switch (Peek())
            {
                case ',':
                    _pos++;
                    break;
                case '}':
                    _pos++;
                    return RDocValue.FromDocument(doc);
                default:
                    throw Error("expected ',' or '}'");
            }
        }
    }

    private string String()
    {
        _pos++; // opening quote
        var sb = new StringBuilder();
        while (true)
        {
            int start = _pos;
            while (_pos < _s.Length && _s[_pos] != '"' && _s[_pos] != '\\' && _s[_pos] >= ' ')
            {
                _pos++;
            }

            sb.Append(_s, start, _pos - start);
            switch (Peek())
            {
                case '"':
                    _pos++;
                    return sb.ToString();
                case '\\':
                    _pos++;
                    Escape(sb);
                    break;
                case null:
                    throw Error("unterminated string");
                default:
                    throw Error("control character in string");
            }
        }
    }

    private void Escape(StringBuilder sb)
    {
        char c = Peek() ?? throw Error("unterminated escape");
        _pos++;
        switch (c)
        {
            case '"' or '\\' or '/':
                sb.Append(c);
                break;
            case 'b':
                sb.Append('\b');
                break;
            case 'f':
                sb.Append('\f');
                break;
            case 'n':
                sb.Append('\n');
                break;
            case 'r':
                sb.Append('\r');
                break;
            case 't':
                sb.Append('\t');
                break;
            case 'u':
                int hi = Hex4();
                if (hi is >= 0xD800 and < 0xDC00)
                {
                    if (string.CompareOrdinal(_s, _pos, "\\u", 0, 2) != 0)
                    {
                        throw Error("lone surrogate");
                    }

                    _pos += 2;
                    int lo = Hex4();
                    if (lo is < 0xDC00 or >= 0xE000)
                    {
                        throw Error("lone surrogate");
                    }

                    sb.Append((char)hi).Append((char)lo);
                }
                else if (hi is >= 0xDC00 and < 0xE000)
                {
                    throw Error("lone surrogate");
                }
                else
                {
                    sb.Append((char)hi);
                }

                break;
            default:
                throw Error("invalid escape");
        }
    }

    private int Hex4()
    {
        if (_pos + 4 > _s.Length || !int.TryParse(_s.AsSpan(_pos, 4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out int v))
        {
            throw Error("bad \\u escape");
        }

        _pos += 4;
        return v;
    }

    /// <summary>Scans <c>-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?</c>.</summary>
    private Number ScanNumber()
    {
        int start = _pos;
        if (Peek() == '-')
        {
            _pos++;
        }

        int intStart = _pos;
        int n = Digits();
        if (n == 0 || (n > 1 && _s[intStart] == '0'))
        {
            throw Error("invalid number");
        }

        bool integral = true;
        if (Peek() == '.')
        {
            _pos++;
            integral = false;
            if (Digits() == 0)
            {
                throw Error("invalid number fraction");
            }
        }

        if (Peek() is 'e' or 'E')
        {
            _pos++;
            integral = false;
            if (Peek() is '+' or '-')
            {
                _pos++;
            }

            if (Digits() == 0)
            {
                throw Error("invalid number exponent");
            }
        }

        return new Number(_s[start.._pos], integral);
    }

    private int Digits()
    {
        int from = _pos;
        while (Peek() is >= '0' and <= '9')
        {
            _pos++;
        }

        return _pos - from;
    }

    private readonly RDocValue NumberValue(Number n)
    {
        if (n.Integral && long.TryParse(n.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long i))
        {
            return RDocValue.FromInt64(i);
        }

        // .NET float parsing is correctly rounded (IEEE 754) and overflows to infinity, which plain
        // JSON cannot mean, so it is rejected.
        double f = double.Parse(n.Text, NumberStyles.Float, CultureInfo.InvariantCulture);
        return double.IsInfinity(f) ? throw Error("number outside the float64 range") : RDocValue.FromDouble(f);
    }

    private string WrapperString()
    {
        Ws();
        return Peek() == '"' ? String() : throw Error("expected a string");
    }

    /// <summary>Parses the value of an extended-JSON wrapper whose key is <paramref name="key"/>.</summary>
    private RDocValue Wrapper(string key)
    {
        int at = _pos;
        RDocException Bad(string reason) => new(ErrorCodes.InvalidArgument, $"{key}: {reason}", at);
        CultureInfo inv = CultureInfo.InvariantCulture;
        switch (key)
        {
            case "$int64":
                return long.TryParse(WrapperString(), NumberStyles.AllowLeadingSign, inv, out long i)
                    ? RDocValue.FromInt64(i)
                    : throw Bad("not an int64");
            case "$float":
                return RDocValue.FromDouble(FloatWrapper(WrapperString(), Bad));
            case "$decimal":
                return Decimal128.TryParse(WrapperString(), out Decimal128 d)
                    ? RDocValue.FromDecimal128(d)
                    : throw Bad("not an exact decimal128");
            case "$date":
                return DateTimeText.TryParse(WrapperString(), out long ms)
                    ? RDocValue.FromUnixTimeMilliseconds(ms)
                    : throw Bad("invalid $date (expected YYYY-MM-DDTHH:MM:SS.mmmZ)");
            case "$oid":
                return ObjectId.TryParse(WrapperString(), out ObjectId oid) ? RDocValue.FromObjectId(oid) : throw Bad("objectId must be 24 hex digits");
            case "$uuid":
                return ParseUuid(WrapperString(), out RDocValue u) ? u : throw Bad("expected 8-4-4-4-12 hex");
            case "$ts":
                return Timestamp(WrapperString(), Bad);
            case "$binary":
                return Binary();
            case "$vector":
                return Vector();
            case "$minKey" or "$maxKey":
                Ws();
                Number one = ScanNumber();
                return one.Text != "1" ? throw Bad("expected 1") : key == "$minKey" ? RDocValue.MinKey : RDocValue.MaxKey;
            case "$counter":
                throw new RDocException(ErrorCodes.InvalidFieldName, "$counter is a read-only projection, not accepted as input", at);
            default:
                throw new RDocException(ErrorCodes.InvalidFieldName, "field name starts with '$'", at);
        }
    }

    private static double FloatWrapper(string s, Func<string, RDocException> bad)
    {
        switch (s)
        {
            case "NaN":
                return double.NaN;
            case "Infinity":
                return double.PositiveInfinity;
            case "-Infinity":
                return double.NegativeInfinity;
        }

        var p = new RDocJsonReader(s);
        if (s.Length == 0 || !(s[0] == '-' || char.IsAsciiDigit(s[0])))
        {
            throw bad("not a number");
        }

        Number n;
        try
        {
            n = p.ScanNumber();
        }
        catch (RDocException)
        {
            throw bad("not a number");
        }

        // As Rust's `str::parse::<f64>`, an out-of-range magnitude gives ±Infinity here.
        return p._pos == s.Length ? double.Parse(n.Text, NumberStyles.Float, CultureInfo.InvariantCulture) : throw bad("not a number");
    }

    private static RDocValue Timestamp(string s, Func<string, RDocException> bad)
    {
        int dot = s.IndexOf('.', StringComparison.Ordinal);
        if (dot < 0)
        {
            throw bad("expected wall.logical");
        }

        ReadOnlySpan<char> w = s.AsSpan(0, dot);
        ReadOnlySpan<char> l = s.AsSpan(dot + 1);
        if (!AllDigits(w) || !AllDigits(l))
        {
            throw bad("expected wall.logical");
        }

        if (!ulong.TryParse(w, NumberStyles.None, CultureInfo.InvariantCulture, out ulong wall))
        {
            throw bad("wall out of range");
        }

        return uint.TryParse(l, NumberStyles.None, CultureInfo.InvariantCulture, out uint logical)
            ? RDocValue.FromTimestamp(new RDocTimestamp(wall, logical))
            : throw bad("logical out of range");
    }

    private static bool AllDigits(ReadOnlySpan<char> t)
    {
        if (t.IsEmpty)
        {
            return false;
        }

        foreach (char c in t)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary><c>{"base64":"…","subType":"hh"}</c> in either key order; base64 strict (padding, no whitespace, zero unused bits).</summary>
    private RDocValue Binary()
    {
        int at = _pos;
        RDocException Bad(string r) => new(ErrorCodes.InvalidArgument, $"$binary: {r}", at);
        Eat('{');
        byte[]? data = null;
        int subtype = -1;
        for (int i = 0; i < 2; i++)
        {
            if (i > 0)
            {
                Eat(',');
            }

            Ws();
            if (Peek() != '"')
            {
                throw Bad("expected base64 and subType");
            }

            string k = String();
            Eat(':');
            string v = WrapperString();
            if (k == "base64" && data is null)
            {
                data = StrictBase64(v) ?? throw Bad("invalid base64");
            }
            else if (k == "subType" && subtype < 0)
            {
                subtype = v.Length == 2 && byte.TryParse(v, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out byte b)
                    ? b
                    : throw Bad("subType is 2 hex digits");
            }
            else
            {
                throw Bad("expected base64 and subType");
            }
        }

        Eat('}');
        string? error = BinarySubtype.Check((byte)subtype, data!.Length);
        return error is null ? RDocValue.FromOwnedBinary((byte)subtype, data) : throw Bad(error);
    }

    private static byte[]? StrictBase64(string s)
    {
        if (s.Length % 4 != 0)
        {
            return null;
        }

        foreach (char c in s)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='))
            {
                return null;
            }
        }

        byte[] buffer = new byte[s.Length / 4 * 3];
        if (!Convert.TryFromBase64String(s, buffer, out int written))
        {
            return null;
        }

        byte[] data = buffer.AsSpan(0, written).ToArray();
        // Re-encoding gives the one canonical text: this rejects non-zero unused bits and any
        // misplaced padding that the lenient .NET decoder would accept.
        return Convert.ToBase64String(data) == s ? data : null;
    }

    /// <summary><c>[n, …]</c> of numbers, each the nearest f32 (must be finite, RGN-1040).</summary>
    private RDocValue Vector()
    {
        Eat('[');
        var xs = new List<float>();
        Ws();
        if (Peek() == ']')
        {
            _pos++;
            return RDocValue.FromOwnedVector([]);
        }

        while (true)
        {
            Ws();
            if (Peek() is not ('-' or (>= '0' and <= '9')))
            {
                throw Error("invalid number");
            }

            Number n = ScanNumber();
            float x = float.Parse(n.Text, NumberStyles.Float, CultureInfo.InvariantCulture);
            if (!float.IsFinite(x))
            {
                throw new RDocException(ErrorCodes.InvalidVector, "vector element outside the f32 range", _pos);
            }

            xs.Add(x);
            Ws();
            switch (Peek())
            {
                case ',':
                    _pos++;
                    break;
                case ']':
                    _pos++;
                    return RDocValue.FromOwnedVector([.. xs]);
                default:
                    throw Error("expected ',' or ']'");
            }
        }
    }

    /// <summary><c>8-4-4-4-12</c> hex, either case.</summary>
    private static bool ParseUuid(string s, out RDocValue value)
    {
        value = default;
        if (s.Length != UuidTextLength || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-')
        {
            return false;
        }

        string compact = s.Replace("-", string.Empty, StringComparison.Ordinal);
        Span<byte> b = stackalloc byte[16];
        if (compact.Length != 32 || Convert.FromHexString(compact, b, out _, out int written) != System.Buffers.OperationStatus.Done || written != 16)
        {
            return false;
        }

        value = RDocValue.FromUuidBytes(b);
        return true;
    }
}
