// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// TC-DRV-NET-001 (FR-DRV-001, FR-DOC-001/003): the codec is byte-exact against the frozen Rust
/// RDoc v1 fixtures (<c>crates/rustegon-doc/tests/fixtures/formats/rdoc/1/</c>): every
/// <c>.rdoc</c> decodes to its canonical <c>.json</c>, and the JSON encodes back to the very same
/// bytes.
/// </summary>
public sealed class CodecFixtureTests
{
    public static TheoryData<string> Cases()
    {
        var data = new TheoryData<string>();
        foreach (string f in Directory.GetFiles(TestPaths.RdocFixtures, "*.rdoc").Order(StringComparer.Ordinal))
        {
            data.Add(Path.GetFileNameWithoutExtension(f));
        }

        return data;
    }

    private static (byte[] Rdoc, string Json) Load(string name) => (
        File.ReadAllBytes(Path.Combine(TestPaths.RdocFixtures, name + ".rdoc")),
        File.ReadAllText(Path.Combine(TestPaths.RdocFixtures, name + ".json"), Encoding.UTF8).TrimEnd('\n', '\r'));

    [Fact]
    public void tc_drv_net_001_fixture_set_is_complete()
    {
        // The seven v1 fixtures of M2 (DEC-018); a new one must be picked up, never silently missed.
        Assert.True(Cases().Count >= 7, "expected the RDoc v1 fixtures");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void tc_drv_net_001_rust_rdoc_decodes_to_its_canonical_json(string name)
    {
        (byte[] rdoc, string json) = Load(name);
        RDocument doc = RDocReader.ReadDocument(rdoc);
        Assert.Equal(json, doc.ToJson());
        Assert.True(RDocReader.IsCanonicalFlagSet(rdoc));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void tc_drv_net_001_reencoding_reproduces_the_rust_bytes(string name)
    {
        (byte[] rdoc, _) = Load(name);
        RDocument doc = RDocReader.ReadDocument(rdoc);
        Assert.Equal(rdoc, doc.ToBytes());
        Assert.Equal(rdoc.Length, RDocWriter.GetEncodedLength(doc));
        var buffer = new ArrayBufferWriter<byte>();
        Assert.Equal(rdoc.Length, RDocWriter.Write(doc, buffer));
        Assert.Equal(rdoc, buffer.WrittenSpan.ToArray());
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void tc_drv_net_001_json_encodes_to_the_rust_bytes(string name)
    {
        (byte[] rdoc, string json) = Load(name);
        if (name == "counter")
        {
            // Counters are a read-only projection: their JSON is output only (RGN-1004 as input).
            RDocException e = Assert.Throws<RDocException>(() => RDocument.FromJson(json));
            Assert.Equal(1004, e.Code);
            return;
        }

        RDocument doc = RDocument.FromJson(json);
        Assert.Equal(rdoc, doc.ToBytes());
        Assert.Equal(json, doc.ToJson());
    }

    [Fact]
    public void tc_drv_net_001_value_encoding_is_the_field_bytes()
    {
        // protocol.md §3 Value.rdoc_value: tag + payload exactly as inside a document (PD-053).
        RDocValue[] values =
        [
            RDocValue.Null, -5, "héllo", ObjectId.Parse("070707070707070707070707"),
            new RDocArray { true, 1.5 }, new RDocument { { "a", 1 } },
        ];
        foreach (RDocValue v in values)
        {
            byte[] bytes = RDocWriter.ValueToBytes(v);
            Assert.Equal(v, RDocReader.ReadValue(bytes));
            byte[] doc = new RDocument { { "v", v } }.ToBytes();
            Assert.True(doc.AsSpan().EndsWith(bytes), v.ToJson());
            Assert.Throws<RDocException>(() => RDocReader.ReadValue([.. bytes, 0x01]));
        }

        Assert.Throws<RDocException>(() => RDocReader.ReadValue([]));
        Assert.Throws<RDocException>(() => RDocReader.ReadValue([0xEE]));
    }

    [Fact]
    public void tc_drv_net_001_index_is_sorted_by_hash_then_name_bytes()
    {
        // Known hash: the Rust encoder of the same document yields the same index (many_fields).
        (byte[] rdoc, _) = Load("many_fields");
        int n = rdoc[8];
        var hashes = new List<ushort>();
        int indexAt = 7 + 1 + 1 + 2; // tag, varint(n = 40), varint(body_len, 2 bytes)
        for (int i = 0; i < n; i++)
        {
            hashes.Add(BitConverter.ToUInt16(rdoc, indexAt + (6 * i)));
        }

        Assert.Equal(hashes.Order().ToList(), hashes);
    }
}
