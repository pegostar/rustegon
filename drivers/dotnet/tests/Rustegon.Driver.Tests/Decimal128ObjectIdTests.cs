// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using FsCheck.Xunit;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>TC-DRV-NET-005 (FR-DOC-002, data-model.md §2): Decimal128 (BID) and ObjectId.</summary>
public sealed class Decimal128ObjectIdTests
{
    [Theory]
    [InlineData("12.50", "12.50")]
    [InlineData("0", "0")]
    [InlineData("-0", "-0")]
    [InlineData("0.000001", "0.000001")]
    [InlineData("0.0000001", "1E-7")]
    [InlineData("1e3", "1E+3")]
    [InlineData("123e-2", "1.23")]
    [InlineData("1.5E+10", "1.5E+10")]
    [InlineData("0e10", "0E+10")]
    [InlineData("inf", "Infinity")]
    [InlineData("-Infinity", "-Infinity")]
    [InlineData("nan", "NaN")]
    [InlineData("000123.4500", "123.4500")]
    public void tc_drv_net_005_decimal_format_matches_to_scientific_string(string input, string text) =>
        Assert.Equal(text, Decimal128.Parse(input).ToString());

    [Fact]
    public void tc_drv_net_005_decimal_parse_rejects_inexact_and_garbage()
    {
        Assert.False(Decimal128.TryParse("12345678901234567890123456789012345", out _));
        Assert.True(Decimal128.TryParse("1234567890123456789012345678901234", out _));
        Assert.True(Decimal128.TryParse("12345678901234567890123456789012340", out _));
        Assert.True(Decimal128.TryParse("1e6112", out _));
        Assert.True(Decimal128.TryParse("1e6144", out _));
        Assert.False(Decimal128.TryParse("1e6145", out _));
        Assert.True(Decimal128.TryParse("1e-6176", out _));
        Assert.False(Decimal128.TryParse("1e-6177", out _));
        Assert.True(Decimal128.TryParse("10e-6177", out _));
        Assert.True(Decimal128.TryParse("0e-99999", out _));
        foreach (string bad in new[] { string.Empty, "-", ".", "e5", "1e", "1.2.3", "1x", " 1", "--1", "1e+" })
        {
            Assert.False(Decimal128.TryParse(bad, out _), bad);
        }

        Assert.Throws<FormatException>(() => Decimal128.Parse("x"));
    }

    [Fact]
    public void tc_drv_net_005_decimal_bits_round_trip_and_known_values()
    {
        // 1 = coefficient 1, exponent 0: biased exponent 6176 = 0x1820 at bit 113.
        Assert.Equal(((UInt128)0x1820 << 113) | 1, Decimal128.Parse("1").ToIeeeBits());
        foreach (string s in new[] { "1", "-12.50", "0", "-0", "1E+6111", "9.999999999999999999999999999999999E+6144", "1E-6176", "Infinity", "-Infinity", "NaN" })
        {
            Decimal128 d = Decimal128.Parse(s);
            Decimal128 back = Decimal128.FromIeeeBits(d.ToIeeeBits(), out bool canonical);
            Assert.True(canonical, s);
            Assert.Equal(d, back);
        }
    }

    [Fact]
    public void tc_drv_net_005_decimal_non_canonical_bits_are_detected_and_normalized()
    {
        UInt128 nan = (UInt128)0x7C << 120;
        UInt128 inf = (UInt128)0x78 << 120;
        Assert.True(Decimal128.FromIeeeBits(nan | 1, out bool c1).IsNaN);
        Assert.False(c1);
        Assert.Equal(Decimal128.PositiveInfinity, Decimal128.FromIeeeBits(inf | 5, out bool c2));
        Assert.False(c2);
        Decimal128 big = Decimal128.FromIeeeBits(((UInt128)0x1820 << 113) | (Decimal128.MaxCoefficient + 1), out bool c3);
        Assert.False(c3);
        Assert.Equal(UInt128.Zero, big.Coefficient);
        Decimal128.FromIeeeBits((UInt128)0x3 << 125, out bool c4);
        Assert.False(c4);
    }

    [Theory]
    [InlineData("12.50")]
    [InlineData("-0.0000000000000000000000000001")]
    [InlineData("79228162514264337593543950335")]
    [InlineData("-79228162514264337593543950335")]
    [InlineData("0")]
    [InlineData("1.000")]
    public void tc_drv_net_005_system_decimal_round_trip_keeps_the_scale(string text)
    {
        decimal m = decimal.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
        Decimal128 d = m;
        Assert.Equal(d, Decimal128.Parse(text));
        Assert.True(d.TryToDecimal(out decimal back));
        Assert.Equal(m, back);
        Assert.Equal(m.Scale, back.Scale);
    }

    [Fact]
    public void tc_drv_net_005_decimal_to_system_decimal_only_when_exact()
    {
        Assert.Equal(1000m, (decimal)Decimal128.Parse("1E+3"));
        Assert.Equal(1m, (decimal)Decimal128.Parse("1.0000000000000000000000000000000")); // trailing zeros dropped
        Assert.False(Decimal128.Parse("1E+29").TryToDecimal(out _));
        Assert.False(Decimal128.Parse("1E-29").TryToDecimal(out _));
        Assert.False(Decimal128.NaN.TryToDecimal(out _));
        Assert.False(Decimal128.PositiveInfinity.TryToDecimal(out _));
        Assert.Throws<OverflowException>(() => (decimal)Decimal128.Parse("1234567890123456789012345678901234"));
    }

    [Property(MaxTest = 500)]
    public bool tc_drv_net_005_every_system_decimal_round_trips(decimal m)
    {
        Decimal128 d = m;
        return d.TryToDecimal(out decimal back) && back == m && back.Scale == m.Scale && Decimal128.Parse(d.ToString()) == d;
    }

    [Fact]
    public void tc_drv_net_005_object_id_text_bytes_and_order()
    {
        ObjectId id = ObjectId.Parse("65A1B2C3D4E5F60718293A4B");
        Assert.Equal("65a1b2c3d4e5f60718293a4b", id.ToString());
        Assert.Equal(Convert.FromHexString("65a1b2c3d4e5f60718293a4b"), id.ToByteArray());
        Assert.Equal(0x65A1B2C3u, id.Seconds);
        Assert.Equal(id, new ObjectId(id.ToByteArray()));
        Assert.False(ObjectId.TryParse("65a1b2c3d4e5f60718293a4", out _));
        Assert.False(ObjectId.TryParse("65a1b2c3d4e5f60718293a4g", out _));
        Assert.False(ObjectId.TryParse(null, out _));
        Assert.True(ObjectId.Parse("000000000000000000000001") < ObjectId.Parse("000000000000000000000100"));
        Assert.Throws<ArgumentException>(() => new ObjectId(new byte[11]));
    }

    [Fact]
    public void tc_drv_net_005_generated_object_ids_are_unique_ordered_by_second_and_share_the_process_part()
    {
        var t = new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
        var ids = new HashSet<ObjectId>();
        for (int i = 0; i < 10_000; i++)
        {
            ObjectId id = ObjectId.NewObjectId(t);
            Assert.True(ids.Add(id));
            Assert.Equal((uint)t.ToUnixTimeSeconds(), id.Seconds);
        }

        Assert.Single(ids.Select(i => Convert.ToHexString(i.ToByteArray()[4..9])).Distinct());
        Assert.True(ObjectId.NewObjectId(t) < ObjectId.NewObjectId(t.AddSeconds(1)));
        Assert.Equal(t, ObjectId.NewObjectId(t).CreationTime);
    }
}
