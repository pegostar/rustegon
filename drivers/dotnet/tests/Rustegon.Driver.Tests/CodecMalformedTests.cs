// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers.Binary;
using System.IO;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// TC-DRV-NET-003 (FR-DOC-003/004): malformed, non-canonical and over-limit input is rejected with
/// the RGN code the server uses (1001 malformed, 1002 too large, 1003 too deep, 1004 names, 1040
/// vectors), and the decoder never throws anything but <see cref="RDocException"/>.
/// </summary>
public sealed class CodecMalformedTests
{
    private static byte[] AllTypes() => File.ReadAllBytes(Path.Combine(TestPaths.RdocFixtures, "all_types.rdoc"));

    /// <summary>A document with header fixed up for a hand-written object body.</summary>
    private static byte[] Doc(byte flags, params byte[] body)
    {
        byte[] b = new byte[7 + body.Length];
        b[0] = 0xD7;
        b[1] = 0x01;
        b[2] = flags;
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(3), (uint)b.Length);
        body.CopyTo(b, 7);
        return b;
    }

    private static int Code(Action a) => Assert.Throws<RDocException>(a).Code;

    [Fact]
    public void tc_drv_net_003_every_truncation_is_rejected()
    {
        byte[] full = AllTypes();
        for (int len = 0; len < full.Length; len++)
        {
            byte[] cut = full[..len];
            if (len >= 7)
            {
                // Keep total_len consistent so the body parser, not only the header check, is hit.
                BinaryPrimitives.WriteUInt32LittleEndian(cut.AsSpan(3), (uint)len);
            }

            Assert.Equal(1001, Code(() => RDocReader.ReadDocument(cut)));
        }
    }

    [Fact]
    public void tc_drv_net_003_every_single_bit_flip_fails_cleanly_or_decodes()
    {
        byte[] full = AllTypes();
        for (int i = 0; i < full.Length; i++)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                byte[] b = (byte[])full.Clone();
                b[i] ^= (byte)(1 << bit);
                try
                {
                    RDocReader.ReadDocument(b);
                }
                catch (RDocException)
                {
                }
            }
        }
    }

    [Fact]
    public void tc_drv_net_003_header_errors()
    {
        byte[] good = Doc(0x01, 0x0D, 0x00, 0x00);
        Assert.Equal(new RDocument(), RDocReader.ReadDocument(good));
        byte[] magic = (byte[])good.Clone();
        magic[0] = 0xD8;
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(magic)));
        byte[] version = (byte[])good.Clone();
        version[1] = 0x02;
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(version)));
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(Doc(0x02, 0x0D, 0x00, 0x00))));
        byte[] length = (byte[])good.Clone();
        length[3] = 11;
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(length)));
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument([.. good, 0x00])));
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(Doc(0x01, 0x0C, 0x00, 0x00))));
        byte[] huge = (byte[])good.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(huge.AsSpan(3), (16 * 1024 * 1024) + 1);
        Assert.Equal(1002, Code(() => RDocReader.ReadDocument(huge)));
    }

    /// <summary>{"a": &lt;value bytes&gt;} with a correct index.</summary>
    private static byte[] OneField(byte flags, params byte[] value)
    {
        ushort hash = (ushort)System.IO.Hashing.XxHash3.HashToUInt64("a"u8);
        byte bodyLength = (byte)(2 + value.Length);
        byte[] body = [0x0D, 0x01, bodyLength, (byte)hash, (byte)(hash >> 8), 0, 0, 0, 0, 0x01, (byte)'a', .. value];
        return Doc(flags, body);
    }

    [Fact]
    public void tc_drv_net_003_value_errors()
    {
        Assert.Equal(RDocValue.FromBoolean(true), RDocReader.ReadDocument(OneField(0x01, 0x02, 0x01))["a"]);
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, 0x02, 0x02)))); // bool byte
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, 0x12)))); // unknown tag
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, 0x06, 0x02, 0xC3, 0x28)))); // invalid UTF-8
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, 0x07, 0x05, 0x00)))); // reserved binary subtype
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, 0x07, 0x04, 0x01, 0x00)))); // uuid binary not 16 bytes
        Assert.Equal(1040, Code(() => RDocReader.ReadDocument(OneField(0x01, 0x0E, 0x01, 0x00, 0x00, 0xC0, 0x7F)))); // NaN element
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02)))); // varint overflow
    }

    [Fact]
    public void tc_drv_net_003_canonical_flag_rejects_non_canonical_encodings_and_clear_flag_normalizes()
    {
        byte[] nonMinimal = [0x03, 0x82, 0x00]; // int64 1 with a redundant varint group
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, nonMinimal))));
        Assert.Equal(RDocValue.FromInt64(1), RDocReader.ReadDocument(OneField(0x00, nonMinimal))["a"]);

        byte[] nanPayload = [0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x7F];
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, nanPayload))));
        RDocument normalized = RDocReader.ReadDocument(OneField(0x00, nanPayload));
        Assert.True(double.IsNaN(normalized["a"].AsDouble()));
        Assert.Equal(OneField(0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x7F), normalized.ToBytes());

        byte[] decimalNaNPayload = [0x05, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7C];
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(OneField(0x01, decimalNaNPayload))));
        Assert.True(RDocReader.ReadDocument(OneField(0x00, decimalNaNPayload))["a"].AsDecimal128().IsNaN);
    }

    [Fact]
    public void tc_drv_net_003_index_errors()
    {
        byte[] good = OneField(0x01, 0x01);
        byte[] wrongHash = (byte[])good.Clone();
        wrongHash[10] ^= 0x01;
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(wrongHash)));
        byte[] wrongOffset = (byte[])good.Clone();
        wrongOffset[12] = 1;
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(wrongOffset)));

        // Two fields named "a": the index entries are equal, which is a duplicate name (RGN-1004).
        ushort h = (ushort)System.IO.Hashing.XxHash3.HashToUInt64("a"u8);
        byte[] dup = Doc(0x01, 0x0D, 0x02, 0x06, (byte)h, (byte)(h >> 8), 0, 0, 0, 0, (byte)h, (byte)(h >> 8), 3, 0, 0, 0,
            0x01, (byte)'a', 0x01, 0x01, (byte)'a', 0x01);
        Assert.Equal(1004, Code(() => RDocReader.ReadDocument(dup)));

        // A forged field count is bounded by the body before anything is allocated.
        Assert.Equal(1001, Code(() => RDocReader.ReadDocument(Doc(0x01, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00))));
    }

    [Fact]
    public void tc_drv_net_003_field_name_rules_on_decode_and_encode()
    {
        foreach (string bad in new[] { string.Empty, "$x", "a\0b", new string('n', 1025) })
        {
            var d = new RDocument { { bad, 1 } };
            Assert.Equal(1004, Code(() => d.ToBytes()));
        }

        Assert.Equal(1004, Code(() => new RDocument { { "\uD800", 1 } }.ToBytes()));
        Assert.Equal(1001, Code(() => new RDocument { { "s", "\uDC00" } }.ToBytes()));
        new RDocument { { new string('n', 1024), 1 } }.ToBytes();
    }

    [Fact]
    public void tc_drv_net_003_depth_limit_is_100_levels()
    {
        RDocument Nest(int levels)
        {
            var root = new RDocument();
            RDocument cur = root;
            for (int i = 1; i < levels; i++)
            {
                var next = new RDocument();
                cur.Add("x", next);
                cur = next;
            }

            return root;
        }

        byte[] ok = Nest(100).ToBytes();
        Assert.Equal(100, Depth(RDocReader.ReadDocument(ok)));
        Assert.Equal(1003, Code(() => Nest(101).ToBytes()));
        Assert.Equal(1003, Code(() => RDocument.FromJson(Json(101))));
    }

    private static string Json(int levels) => string.Concat(System.Linq.Enumerable.Repeat("{\"x\":", levels - 1)) + "{}" + new string('}', levels - 1);

    private static int Depth(RDocument d) => d.TryGetValue("x", out RDocValue v) ? 1 + Depth(v.AsDocument()) : 1;

    [Fact]
    public void tc_drv_net_003_size_limit_is_16_mib_including_the_header()
    {
        // total = 7 (header) + 1 + 1 + varint(body) + 6 + body; body = 1 + 1 + (1 + varint(len) + len).
        const int limit = 16 * 1024 * 1024;
        int Total(int len) => new RDocument { { "s", new string('x', len) } }.Let(RDocWriter.GetEncodedLength);
        int len = limit - 30;
        while (Total(len) < limit)
        {
            len++;
        }

        Assert.Equal(limit, Total(len));
        Assert.Equal(limit, new RDocument { { "s", new string('x', len) } }.ToBytes().Length);
        Assert.Equal(1002, Code(() => new RDocument { { "s", new string('x', len + 1) } }.ToBytes()));
    }

    [Fact]
    public void tc_drv_net_003_missing_values_are_not_storable()
    {
        Assert.Throws<ArgumentException>(() => new RDocument { { "a", RDocValue.Missing } });
        Assert.Throws<ArgumentException>(() => new RDocArray { RDocValue.Missing });
        Assert.Equal(1001, Code(() => RDocWriter.ValueToBytes(RDocValue.Missing)));
        Assert.Throws<ArgumentException>(() => RDocValue.FromBinary(0x05, [1]));
        Assert.Throws<ArgumentException>(() => RDocValue.FromVector([float.NaN]));
        Assert.Throws<ArgumentException>(() => RDocValue.FromDateTime(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Local)));
    }
}

internal static class LetExtension
{
    internal static TResult Let<T, TResult>(this T value, Func<T, TResult> f) => f(value);
}
