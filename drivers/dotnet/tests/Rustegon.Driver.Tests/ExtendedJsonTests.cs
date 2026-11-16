// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Text.Json;
using Rustegon.Driver.Internal.Json;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// TC-DRV-NET-004 (FR-DOC-003): canonical and extended JSON, character for character as the server
/// writes it (cases ported from <c>crates/rustegon-doc/src/json/*.rs</c>).
/// </summary>
public sealed class ExtendedJsonTests
{
    private static int Code(string json) => Assert.Throws<RDocException>(() => RDocValue.FromJson(json)).Code;

    [Fact]
    public void tc_drv_net_004_canonical_json_of_every_type()
    {
        var d = new RDocument
        {
            { "n", RDocValue.Null },
            { "b", true },
            { "i", -5 },
            { "big", (1L << 53) + 1 },
            { "f", 1.0 },
            { "nan", double.NaN },
            { "dec", Decimal128.Parse("12.50") },
            { "s", "a\"\\\n\u0001é" },
            { "bin", RDocValue.FromBinary(0x80, [1, 2, 3]) },
            { "dt", RDocValue.FromUnixTimeMilliseconds(0) },
            { "ts", new RDocTimestamp(7, 2) },
            { "oid", new ObjectId(new byte[] { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }) },
            { "u", RDocValue.FromGuid(Guid.Parse("abababab-abab-abab-abab-abababababab")) },
            { "a", new RDocArray { 1, RDocValue.MinKey, RDocValue.MaxKey } },
            { "v", RDocValue.FromVector([0.5f, -1.0f]) },
            { "c", RDocValue.FromCounter(3) },
        };
        const string expected =
            "{\"n\":null,\"b\":true,\"i\":-5,\"big\":{\"$int64\":\"9007199254740993\"},\"f\":1.0," +
            "\"nan\":{\"$float\":\"NaN\"},\"dec\":{\"$decimal\":\"12.50\"},\"s\":\"a\\\"\\\\\\n\\u0001é\"," +
            "\"bin\":{\"$binary\":{\"base64\":\"AQID\",\"subType\":\"80\"}}," +
            "\"dt\":{\"$date\":\"1970-01-01T00:00:00.000Z\"},\"ts\":{\"$ts\":\"7.2\"}," +
            "\"oid\":{\"$oid\":\"111111111111111111111111\"}," +
            "\"u\":{\"$uuid\":\"abababab-abab-abab-abab-abababababab\"}," +
            "\"a\":[1,{\"$minKey\":1},{\"$maxKey\":1}],\"v\":{\"$vector\":[0.5,-1.0]},\"c\":{\"$counter\":3}}";
        Assert.Equal(expected, d.ToJson());
        Assert.Equal("{\"$int64\":\"1\"}", RDocValue.FromInt64(1).ToJson(RDocJsonMode.Extended));
        Assert.Equal("{\"$float\":\"1e300\"}", RDocValue.FromDouble(1e300).ToJson(RDocJsonMode.Extended));
    }

    [Theory]
    [InlineData(0.1, "0.1")]
    [InlineData(1.0, "1.0")]
    [InlineData(-0.0, "-0.0")]
    [InlineData(0.0, "0.0")]
    [InlineData(1.5, "1.5")]
    [InlineData(123.456, "123.456")]
    [InlineData(0.0001, "0.0001")]
    [InlineData(0.00001, "1e-5")]
    [InlineData(1e15, "1000000000000000.0")]
    [InlineData(1e16, "1e16")]
    [InlineData(1.5e-7, "1.5e-7")]
    [InlineData(5e-324, "5e-324")]
    [InlineData(1.7976931348623157e308, "1.7976931348623157e308")]
    [InlineData(-2.5e20, "-2.5e20")]
    [InlineData(9007199254740993.0, "9007199254740992.0")]
    public void tc_drv_net_004_float_text_matches_rust_debug_format(double value, string text)
    {
        Assert.Equal(text, FloatText.Format(value));
        Assert.Equal(BitConverter.DoubleToInt64Bits(value), BitConverter.DoubleToInt64Bits(RDocValue.FromJson(text).AsDouble()));
    }

    [Fact]
    public void tc_drv_net_004_json_numbers_map_to_types()
    {
        Assert.Equal(RDocValue.FromInt64(5), RDocValue.FromJson("5"));
        Assert.Equal(RDocValue.FromInt64(0), RDocValue.FromJson("-0"));
        Assert.Equal(RDocValue.FromDouble(5.0), RDocValue.FromJson("5.0"));
        Assert.Equal(RDocValue.FromDouble(5.0), RDocValue.FromJson("5e0"));
        Assert.Equal(RDocValue.FromInt64(long.MaxValue), RDocValue.FromJson("9223372036854775807"));
        Assert.Equal(RDocValue.FromDouble(9_223_372_036_854_775_808.0), RDocValue.FromJson("9223372036854775808"));
        Assert.Equal(1001, Code("1e400"));
        foreach (string bad in new[] { "01", "1.", ".5", "-", "1e", "+1", "0x1", "NaN" })
        {
            Assert.Equal(1001, Code(bad));
        }
    }

    [Fact]
    public void tc_drv_net_004_strings_and_wrappers()
    {
        Assert.Equal(RDocValue.FromString("😀é/"), RDocValue.FromJson("\"\\ud83d\\ude00é\\/\""));
        Assert.Equal(1001, Code("\"\\ud83d\""));
        Assert.Equal(1001, Code("\"a\u0001\""));
        Assert.Equal(RDocValue.FromInt64(-7), RDocValue.FromJson("{\"$int64\":\"-7\"}"));
        Assert.Equal(RDocValue.MinKey, RDocValue.FromJson("{\"$minKey\":1}"));
        Assert.Equal(1001, Code("{\"$int64\":\"1\",\"x\":1}"));
        Assert.Equal(1004, Code("{\"a\":1,\"$b\":1}"));
        Assert.Equal(RDocValue.FromBinary(BinarySubtype.Uuid, new byte[16]), RDocValue.FromJson("{\"$binary\":{\"subType\":\"04\",\"base64\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}}"));
        Assert.Equal(1001, Code("{\"$binary\":{\"base64\":\"AA==\",\"subType\":\"04\"}}"));
        Assert.Equal(1001, Code("{\"$binary\":{\"base64\":\"AA==\",\"subType\":\"05\"}}"));
        Assert.Equal(1001, Code("{\"$binary\":{\"base64\":\"Zh==\",\"subType\":\"00\"}}")); // non-zero unused bits
        Assert.Equal(1001, Code("{\"$binary\":{\"base64\":\"AQ ID\",\"subType\":\"00\"}}"));
        Assert.Equal(1004, Code("{\"$counter\":1}"));
        Assert.Equal(1040, Code("{\"$vector\":[1e39]}"));
        Assert.Equal(1004, Code("{\"$unknown\":1}"));
        Assert.Equal(1004, Code("{\"a\":1,\"a\":2}"));
        Assert.Equal(1004, Code("{\"a\":{\"b\":1,\"b\":2}}"));
        Assert.Equal(1001, Code("{\"a\":1} x"));
    }

    [Fact]
    public void tc_drv_net_004_wrapper_values()
    {
        Assert.Equal(RDocValue.FromDouble(double.NegativeInfinity), RDocValue.FromJson("{\"$float\":\"-Infinity\"}"));
        Assert.Equal(RDocValue.FromDouble(2.5), RDocValue.FromJson("{\"$float\":\"2.5\"}"));
        Assert.Equal(1001, Code("{\"$float\":\"2.5x\"}"));
        Assert.Equal("{\"$decimal\":\"-1.50E+10\"}", RDocValue.FromJson("{\"$decimal\":\"-1.50e10\"}").ToJson());
        Assert.Equal(1001, Code("{\"$decimal\":\"12345678901234567890123456789012345\"}"));
        Assert.Equal(RDocValue.FromTimestamp(new RDocTimestamp(18446744073709551615, 4294967295)), RDocValue.FromJson("{\"$ts\":\"18446744073709551615.4294967295\"}"));
        Assert.Equal(1001, Code("{\"$ts\":\"18446744073709551616.0\"}"));
        Assert.Equal(1001, Code("{\"$ts\":\"1.-1\"}"));
        Assert.Equal(1001, Code("{\"$oid\":\"65a1b2c3d4e5f60718293a4\"}"));
        Assert.Equal("{\"$oid\":\"65a1b2c3d4e5f60718293a4b\"}", RDocValue.FromJson("{\"$oid\":\"65A1B2C3D4E5F60718293A4B\"}").ToJson());
        Assert.Equal("{\"$uuid\":\"01234567-89ab-cdef-0123-456789abcdef\"}", RDocValue.FromJson("{\"$uuid\":\"01234567-89AB-CDEF-0123-456789ABCDEF\"}").ToJson());
        Assert.Equal(1001, Code("{\"$uuid\":\"0123456789abcdef0123456789abcdef\"}"));
        Assert.Equal(1001, Code("{\"$maxKey\":2}"));
        Assert.Equal("{\"$vector\":[]}", RDocValue.FromJson("{\"$vector\":[]}").ToJson());
    }

    [Fact]
    public void tc_drv_net_004_datetime_text_known_values_and_extremes()
    {
        Assert.Equal("1970-01-01T00:00:00.000Z", DateTimeText.Format(0));
        Assert.Equal("1969-12-31T23:59:59.999Z", DateTimeText.Format(-1));
        Assert.True(DateTimeText.TryParse("2026-01-01T00:00:00.000Z", out long a));
        Assert.Equal(1_767_225_600_000, a);
        Assert.True(DateTimeText.TryParse("2024-02-29T12:00:00Z", out long b));
        Assert.Equal(1_709_208_000_000, b);
        Assert.True(DateTimeText.TryParse("2024-02-29T12:00:00.5Z", out long c));
        Assert.Equal(1_709_208_000_500, c);
        foreach (long ms in new[] { long.MinValue, long.MaxValue, 0, -62_167_219_200_001, 253_402_300_800_000 })
        {
            Assert.True(DateTimeText.TryParse(DateTimeText.Format(ms), out long back), DateTimeText.Format(ms));
            Assert.Equal(ms, back);
        }

        Assert.StartsWith("-292275055", DateTimeText.Format(long.MinValue), StringComparison.Ordinal);
        foreach (string bad in new[]
        {
            "2023-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T00:00:00",
            "2026-01-01T00:00:00.0000Z", "+2026-01-01T00:00:00Z", "+999999999999-01-01T00:00:00Z",
        })
        {
            Assert.False(DateTimeText.TryParse(bad, out _), bad);
        }
    }

    [Fact]
    public void tc_drv_net_004_document_level_rules_and_json_element_interop()
    {
        Assert.Equal(1001, Assert.Throws<RDocException>(() => RDocument.FromJson("[1]")).Code);
        using JsonDocument jd = JsonDocument.Parse("{\"x\": 1, \"y\": [true, null], \"z\": {\"$date\": \"2026-01-01T00:00:00Z\"}}");
        RDocument d = RDocument.FromJson(jd.RootElement);
        Assert.Equal("{\"x\":1,\"y\":[true,null],\"z\":{\"$date\":\"2026-01-01T00:00:00.000Z\"}}", d.ToJson());
        Assert.Equal("{\"x\":{\"$int64\":\"1\"},\"y\":[true,null],\"z\":{\"$date\":\"2026-01-01T00:00:00.000Z\"}}", d.ToJson(RDocJsonMode.Extended));
        Assert.Equal(d.ToJson(), d.ToString());
        Assert.Equal(1003, Assert.Throws<RDocException>(() => RDocument.FromJson("{\"a\":" + new string('[', 100) + new string(']', 100) + "}")).Code);
    }
}
