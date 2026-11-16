// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Rustegon.Driver;

/// <summary>
/// IEEE 754-2008 decimal128 in the binary integer decimal (BID) encoding (data-model.md §2, tag
/// 0x05). Like IEEE 754, members of a cohort (<c>1.0</c> and <c>1.00</c>) are distinct
/// representations of the same number; this type keeps them distinct (equality is
/// representation equality), so a value survives JSON and RDoc round trips unchanged.
/// </summary>
/// <remarks>
/// Only parsing, formatting, BID packing and exact conversion to and from <see cref="decimal"/>
/// are provided; there is no decimal arithmetic. The algorithms mirror
/// <c>crates/rustegon-doc/src/decimal.rs</c> so both sides produce identical bytes and text.
/// </remarks>
public readonly struct Decimal128 : IEquatable<Decimal128>
{
    /// <summary>Largest coefficient: 34 decimal digits.</summary>
    public static readonly UInt128 MaxCoefficient = UInt128.Parse("9999999999999999999999999999999999", CultureInfo.InvariantCulture);

    /// <summary>Precision in decimal digits.</summary>
    public const int MaxDigits = 34;

    /// <summary>Smallest exponent of the integer coefficient (emin − (p − 1)).</summary>
    public const int MinExponent = -6176;

    /// <summary>Largest exponent of the integer coefficient (emax − (p − 1)).</summary>
    public const int MaxExponent = 6111;

    private const int ExponentBias = 6176;
    private const int MaxSystemDecimalScale = 28;

    // Combination-field patterns (bits 126..122): 11110 infinity, 11111 NaN (quiet, no payload).
    private static readonly UInt128 InfinityBits = (UInt128)0x78 << 120;
    private static readonly UInt128 NaNBits = (UInt128)0x7C << 120;
    private static readonly UInt128 CoefficientMask = (UInt128.One << 113) - 1;
    private static readonly UInt128 MaxSystemDecimalCoefficient = (UInt128.One << 96) - 1;

    private readonly UInt128 _coefficient;
    private readonly short _exponent;
    private readonly Kind _kind;
    private readonly bool _negative;

    private Decimal128(Kind kind, bool negative, UInt128 coefficient, short exponent)
    {
        _kind = kind;
        _negative = negative;
        _coefficient = coefficient;
        _exponent = exponent;
    }

    private enum Kind : byte
    {
        Finite,
        Infinity,
        NaN,
    }

    /// <summary>Positive zero with exponent 0.</summary>
    public static Decimal128 Zero => default;

    /// <summary>NaN (quiet, positive, no payload; sign and payload are never preserved).</summary>
    public static Decimal128 NaN => new(Kind.NaN, false, UInt128.Zero, 0);

    /// <summary>+Infinity.</summary>
    public static Decimal128 PositiveInfinity => new(Kind.Infinity, false, UInt128.Zero, 0);

    /// <summary>−Infinity.</summary>
    public static Decimal128 NegativeInfinity => new(Kind.Infinity, true, UInt128.Zero, 0);

    /// <summary>Whether the value is NaN.</summary>
    public bool IsNaN => _kind == Kind.NaN;

    /// <summary>Whether the value is ±Infinity.</summary>
    public bool IsInfinity => _kind == Kind.Infinity;

    /// <summary>Whether the value is finite.</summary>
    public bool IsFinite => _kind == Kind.Finite;

    /// <summary>The sign bit (negative zero exists, as in IEEE 754); false for NaN.</summary>
    public bool IsNegative => _negative;

    /// <summary>The integer coefficient of a finite value (0 otherwise).</summary>
    public UInt128 Coefficient => _coefficient;

    /// <summary>The exponent of the integer coefficient of a finite value (0 otherwise).</summary>
    public int Exponent => _exponent;

    /// <summary>Creates a finite value <c>(−1)^negative × coefficient × 10^exponent</c>.</summary>
    /// <param name="negative">Sign.</param>
    /// <param name="coefficient">At most <see cref="MaxCoefficient"/>.</param>
    /// <param name="exponent">In <see cref="MinExponent"/>..<see cref="MaxExponent"/>.</param>
    /// <returns>The value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Coefficient or exponent out of range.</exception>
    public static Decimal128 FromParts(bool negative, UInt128 coefficient, int exponent)
    {
        if (coefficient > MaxCoefficient)
        {
            throw new ArgumentOutOfRangeException(nameof(coefficient), "A decimal128 coefficient has at most 34 digits.");
        }

        if (exponent is < MinExponent or > MaxExponent)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), "decimal128 exponent out of range.");
        }

        return new Decimal128(Kind.Finite, negative, coefficient, (short)exponent);
    }

    /// <summary>The exact decimal128 of an integer (exponent 0).</summary>
    /// <param name="value">The integer.</param>
    /// <returns>The value.</returns>
    public static Decimal128 FromInt64(long value) =>
        new(Kind.Finite, value < 0, (UInt128)(value < 0 ? (ulong)-(value + 1) + 1 : (ulong)value), 0);

    /// <summary>The exact decimal128 of a <see cref="decimal"/>, keeping its scale (cohort).</summary>
    /// <param name="value">The value; every <see cref="decimal"/> is representable exactly.</param>
    /// <returns>The value.</returns>
    public static Decimal128 FromDecimal(decimal value)
    {
        Span<int> bits = stackalloc int[4];
        decimal.GetBits(value, bits);
        UInt128 coefficient = ((UInt128)(uint)bits[2] << 64) | ((UInt128)(uint)bits[1] << 32) | (uint)bits[0];
        int scale = (bits[3] >> 16) & 0xFF;
        bool negative = bits[3] < 0;
        return new Decimal128(Kind.Finite, negative, coefficient, (short)-scale);
    }

    /// <summary>
    /// Converts to <see cref="decimal"/> when that is exact: finite, and the value fits 96 bits of
    /// coefficient with a scale of at most 28 (trailing zeros are dropped only when needed).
    /// </summary>
    /// <param name="result">The converted value.</param>
    /// <returns>Whether the conversion is exact.</returns>
    public bool TryToDecimal(out decimal result)
    {
        result = 0m;
        if (_kind != Kind.Finite)
        {
            return false;
        }

        UInt128 c = _coefficient;
        int e = _exponent;
        if (c == UInt128.Zero)
        {
            // Zero is exact at any exponent; keep the scale where decimal can.
            int zeroScale = Math.Clamp(-e, 0, MaxSystemDecimalScale);
            result = new decimal(0, 0, 0, _negative, (byte)zeroScale);
            return true;
        }

        while (e > 0)
        {
            if (c > MaxSystemDecimalCoefficient / 10)
            {
                return false;
            }

            c *= 10;
            e--;
        }

        while (e < -MaxSystemDecimalScale && c % 10 == UInt128.Zero)
        {
            c /= 10;
            e++;
        }

        if (e < -MaxSystemDecimalScale || c > MaxSystemDecimalCoefficient)
        {
            return false;
        }

        result = new decimal((int)(uint)c, (int)(uint)(c >> 32), (int)(uint)(c >> 64), _negative, (byte)-e);
        return true;
    }

    /// <summary>Converts to <see cref="decimal"/>, see <see cref="TryToDecimal"/>.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="OverflowException">The value has no exact <see cref="decimal"/> form.</exception>
    public decimal ToDecimal() =>
        TryToDecimal(out decimal d) ? d : throw new OverflowException("The decimal128 value has no exact System.Decimal representation.");

    /// <summary>Exact conversion from <see cref="decimal"/>.</summary>
    /// <param name="value">The value.</param>
    public static implicit operator Decimal128(decimal value) => FromDecimal(value);

    /// <summary>Exact conversion to <see cref="decimal"/>.</summary>
    /// <param name="value">The value.</param>
    /// <exception cref="OverflowException">No exact <see cref="decimal"/> form.</exception>
    public static explicit operator decimal(Decimal128 value) => value.ToDecimal();

    /// <summary>Canonical BID bits (small-coefficient form, NaN without payload).</summary>
    /// <returns>The 128 bits, as stored little endian in RDoc.</returns>
    public UInt128 ToIeeeBits()
    {
        UInt128 sign = _negative ? UInt128.One << 127 : UInt128.Zero;
        switch (_kind)
        {
            case Kind.NaN:
                return NaNBits;
            case Kind.Infinity:
                return sign | InfinityBits;
            default:
                // The constructors keep the exponent in range, so the biased value is 0..=12287 and
                // fits the 14-bit field without touching the `11` large-form pattern.
                UInt128 biased = (UInt128)(uint)(_exponent + ExponentBias);
                return sign | (biased << 113) | (_coefficient & CoefficientMask);
        }
    }

    /// <summary>Decodes BID bits as IEEE 754 does (non-canonical forms are normalized).</summary>
    /// <param name="bits">The 128 bits.</param>
    /// <returns>The value.</returns>
    public static Decimal128 FromIeeeBits(UInt128 bits) => FromIeeeBits(bits, out _);

    /// <summary>Decodes BID bits and reports whether they are the canonical encoding.</summary>
    internal static Decimal128 FromIeeeBits(UInt128 bits, out bool canonical)
    {
        bool negative = (bits >> 127) == UInt128.One;
        uint combination = (uint)(bits >> 122) & 0x1F;
        if (combination == 0x1F)
        {
            canonical = bits == NaNBits;
            return NaN;
        }

        if (combination == 0x1E)
        {
            canonical = (bits & ((UInt128.One << 122) - 1)) == UInt128.Zero;
            return new Decimal128(Kind.Infinity, negative, UInt128.Zero, 0);
        }

        uint biased;
        UInt128 coefficient;
        if (((uint)(bits >> 125) & 0x3) == 0x3)
        {
            // Large-coefficient form: the implied coefficient is >= 2^113 > MaxCoefficient, so the
            // value is zero and the encoding never canonical.
            biased = (uint)(bits >> 111) & 0x3FFF;
            coefficient = UInt128.Zero;
            canonical = false;
        }
        else
        {
            biased = (uint)(bits >> 113) & 0x3FFF;
            UInt128 c = bits & CoefficientMask;
            canonical = c <= MaxCoefficient;
            coefficient = canonical ? c : UInt128.Zero;
        }

        // The large form can carry a biased exponent above 12287; clamp it (the value is zero).
        int exponent = (int)Math.Min(biased, (uint)(MaxExponent + ExponentBias)) - ExponentBias;
        return new Decimal128(Kind.Finite, negative, coefficient, (short)exponent);
    }

    /// <summary>
    /// Parses the decimal string syntax (<c>[+-]digits[.digits][e[+-]digits]</c>, <c>Infinity</c>,
    /// <c>Inf</c>, <c>NaN</c>, case-insensitive). The value must be exact: trailing zeros are
    /// dropped or added to bring the exponent into range, but nothing is rounded.
    /// </summary>
    /// <param name="s">The text.</param>
    /// <returns>The value.</returns>
    /// <exception cref="FormatException">Syntax error, more than 34 significant digits, or an exponent out of range.</exception>
    public static Decimal128 Parse(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        return TryParse(s, out Decimal128 d, out string? error) ? d : throw new FormatException("decimal128: " + error);
    }

    /// <summary>Tries to parse, see <see cref="Parse"/>.</summary>
    /// <param name="s">The text.</param>
    /// <param name="result">The value, or zero on failure.</param>
    /// <returns>Whether <paramref name="s"/> is a valid exact decimal128.</returns>
    public static bool TryParse([NotNullWhen(true)] string? s, out Decimal128 result) => TryParse(s, out result, out _);

    private static bool TryParse(string? s, out Decimal128 result, out string? error)
    {
        result = default;
        if (s is null)
        {
            error = "null";
            return false;
        }

        ReadOnlySpan<char> body = s;
        bool negative = false;
        if (body.Length > 0 && (body[0] == '-' || body[0] == '+'))
        {
            negative = body[0] == '-';
            body = body[1..];
        }

        if (body.Equals("inf", StringComparison.OrdinalIgnoreCase) || body.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            result = negative ? NegativeInfinity : PositiveInfinity;
            error = null;
            return true;
        }

        if (body.Equals("nan", StringComparison.OrdinalIgnoreCase))
        {
            result = NaN;
            error = null;
            return true;
        }

        var digits = new List<byte>();
        long fracLen = 0;
        bool seenDigit = false;
        int i = 0;
        for (; i < body.Length && char.IsAsciiDigit(body[i]); i++)
        {
            PushSignificant(digits, body[i]);
            seenDigit = true;
        }

        if (i < body.Length && body[i] == '.')
        {
            for (i++; i < body.Length && char.IsAsciiDigit(body[i]); i++)
            {
                PushSignificant(digits, body[i]);
                fracLen++;
                seenDigit = true;
            }
        }

        if (!seenDigit)
        {
            error = "no digits";
            return false;
        }

        long expLit = 0;
        if (i < body.Length && (body[i] == 'e' || body[i] == 'E'))
        {
            i++;
            bool expNegative = false;
            if (i < body.Length && (body[i] == '-' || body[i] == '+'))
            {
                expNegative = body[i] == '-';
                i++;
            }

            int start = i;
            for (; i < body.Length && char.IsAsciiDigit(body[i]); i++)
            {
                // Saturate: anything beyond ±10^12 is out of range whatever the digits are.
                expLit = Math.Min((expLit * 10) + (body[i] - '0'), 1_000_000_000_000);
            }

            if (i == start)
            {
                error = "empty exponent";
                return false;
            }

            if (expNegative)
            {
                expLit = -expLit;
            }
        }

        if (i != body.Length)
        {
            error = "unexpected character";
            return false;
        }

        return FromDigits(negative, digits, expLit - fracLen, out result, out error);
    }

    private static void PushSignificant(List<byte> digits, char ascii)
    {
        byte d = (byte)(ascii - '0');
        if (d != 0 || digits.Count > 0)
        {
            digits.Add(d);
        }
    }

    private static bool FromDigits(bool negative, List<byte> digits, long exponent, out Decimal128 result, out string? error)
    {
        result = default;
        error = null;
        if (digits.Count == 0)
        {
            // Zero: clamping the exponent does not change the value (IEEE 754 does the same).
            result = new Decimal128(Kind.Finite, negative, UInt128.Zero, (short)Math.Clamp(exponent, MinExponent, MaxExponent));
            return true;
        }

        while (digits.Count > MaxDigits && digits[^1] == 0)
        {
            digits.RemoveAt(digits.Count - 1);
            exponent++;
        }

        if (digits.Count > MaxDigits)
        {
            error = "more than 34 significant digits (inexact)";
            return false;
        }

        while (exponent > MaxExponent && digits.Count < MaxDigits)
        {
            digits.Add(0);
            exponent--;
        }

        if (exponent > MaxExponent)
        {
            error = "exponent overflow";
            return false;
        }

        while (exponent < MinExponent && digits[^1] == 0)
        {
            digits.RemoveAt(digits.Count - 1);
            exponent++;
        }

        if (exponent < MinExponent)
        {
            error = "exponent underflow (inexact)";
            return false;
        }

        UInt128 coefficient = UInt128.Zero;
        foreach (byte d in digits)
        {
            coefficient = (coefficient * 10) + d;
        }

        result = new Decimal128(Kind.Finite, negative, coefficient, (short)exponent);
        return true;
    }

    /// <summary>
    /// IEEE 754 / General Decimal Arithmetic "to-scientific-string": plain notation when the
    /// exponent is ≤ 0 and the adjusted exponent ≥ −6, scientific otherwise. Parsing the output
    /// yields the same representation (cohort member included).
    /// </summary>
    /// <returns>The text form.</returns>
    public override string ToString()
    {
        switch (_kind)
        {
            case Kind.NaN:
                return "NaN";
            case Kind.Infinity:
                return _negative ? "-Infinity" : "Infinity";
        }

        var sb = new StringBuilder();
        if (_negative)
        {
            sb.Append('-');
        }

        string digits = _coefficient.ToString(CultureInfo.InvariantCulture);
        long n = digits.Length;
        long exponent = _exponent;
        long adjusted = exponent + n - 1;
        if (exponent <= 0 && adjusted >= -6)
        {
            if (exponent == 0)
            {
                return sb.Append(digits).ToString();
            }

            long point = n + exponent;
            if (point > 0)
            {
                return sb.Append(digits, 0, (int)point).Append('.').Append(digits, (int)point, digits.Length - (int)point).ToString();
            }

            return sb.Append("0.").Append('0', (int)-point).Append(digits).ToString();
        }

        sb.Append(digits[0]);
        if (digits.Length > 1)
        {
            sb.Append('.').Append(digits, 1, digits.Length - 1);
        }

        sb.Append('E').Append(adjusted < 0 ? '-' : '+').Append(Math.Abs(adjusted).ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    /// <summary>Representation equality (cohort members and signed zeros differ; all NaNs are equal).</summary>
    /// <param name="other">The other value.</param>
    /// <returns>Whether both have the same canonical encoding.</returns>
    public bool Equals(Decimal128 other) => ToIeeeBits() == other.ToIeeeBits();

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Decimal128 other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => ToIeeeBits().GetHashCode();

    /// <summary>Representation equality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether both are the same representation.</returns>
    public static bool operator ==(Decimal128 left, Decimal128 right) => left.Equals(right);

    /// <summary>Representation inequality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether the representations differ.</returns>
    public static bool operator !=(Decimal128 left, Decimal128 right) => !left.Equals(right);
}
