// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Rustegon.Driver.Mapping;
using Rustegon.Driver.MappedTypes;
using Rustegon.Driver.Tests.Conformance;
using Xunit;

namespace Rustegon.Driver.Tests.Mapping;

/// <summary>
/// TC-DRV-NET-025 (FR-DRV-001): the opt-in reflection codec writes the same bytes as the
/// generated codec and reads them back the same way; without the opt-in an unmapped type fails
/// when the handle is created. The tests that switch the process-wide fallback on run alone
/// (<see cref="ReflectionFallbackGroup"/>).
/// </summary>
public sealed class MappingReflectionTests
{
    private static void AssertSameBytes<T>(T value)
    {
        IRDocCodec<T> generated = RDocCodecRegistry.Get<T>();
        var reflected = new ReflectionCodec<T>();
        Assert.NotEqual(generated.GetType(), reflected.GetType());
        byte[] g = generated.Encode(value).ToBytes();
        Assert.Equal(g, reflected.Encode(value).ToBytes());
        Assert.Equal(g, generated.Encode(reflected.Decode(RDocument.FromBytes(g))).ToBytes());
        Assert.Equal(g, reflected.Encode(generated.Decode(RDocument.FromBytes(g))).ToBytes());
    }

    [FsCheck.Xunit.Property(MaxTest = 200)]
    public bool tc_drv_net_025_reflection_and_generated_codecs_write_identical_bytes(long l, int i, short s, double d, float f, decimal m, string? text, byte[]? bytes, long ms, Guid g, bool flag, int? maybe)
    {
        AssertSameBytes(MappingTypeTests.Make(l, i, s, d, f, m, text, bytes, ms, g, flag, maybe));
        return true;
    }

    [Fact]
    public void tc_drv_net_025_records_polymorphism_and_nesting_match_the_generated_codecs()
    {
        AssertSameBytes(new Order(5, OrderStatus.Shipped, 3.25m) { Customer = "c", Lines = [new Line { Sku = "a", Qty = 1 }], Embedding = [1, 2, 3], Location = [1, 2], Views = 3 });
        AssertSameBytes(new Address("s", "c") { Zip = "z" });
        AssertSameBytes(new Line { Sku = "x", Qty = 2 });
        AssertSameBytes<Shape>(new Square { Id = "q", Width = 2, Rounded = true });
        AssertSameBytes<Shape>(new Circle { Radius = 1 });
        AssertSameBytes(new Rect { Height = 1 });
        AssertSameBytes<Shape>(new Triangle { Id = "t", Side = 2 });
        AssertSameBytes(new Note { Body = "b", Id = "n" });
        AssertSameBytes(new Drawing { Shapes = [new Circle(), new Rect()], Main = new Square() });
        AssertSameBytes(new TreeNode { Label = "r", Children = [new TreeNode { Label = "c" }] });

        // Same read rules: unknown fields ignored, absent fields → default.
        var reflected = new ReflectionCodec<AllTypes>();
        AllTypes back = reflected.Decode(new RDocument { { "unknown", 1 }, { "long", 5 } });
        Assert.Equal((5L, default(DateTime)), (back.Long, back.When));
        Assert.Null(new ReflectionCodec<Order>().Decode(new RDocument { { "_id", 1 } }).Lines);
        Assert.Throws<RDocException>(() => new ReflectionCodec<Shape>().Decode(new RDocument { { "_type", "hexagon" } }));
        Assert.Throws<RDocException>(() => new ReflectionCodec<Shape>().Decode(new RDocument()));
        Assert.Throws<RDocException>(() => reflected.Decode(new RDocument { { "int", long.MaxValue } }));
    }

    [Fact]
    public void tc_drv_net_025_reflection_codec_refuses_unmappable_types()
    {
        Assert.Throws<NotSupportedException>(() => new ReflectionCodec<NoConstructor>());
        Assert.Throws<NotSupportedException>(() => new ReflectionCodec<UnsupportedMember>());
        Assert.Throws<NotSupportedException>(() => new ReflectionCodec<DuplicateField>());
    }

    [Fact]
    public async Task tc_drv_net_025_unmapped_types_fail_at_handle_creation_without_the_opt_in()
    {
        NotSupportedException e = Assert.Throws<NotSupportedException>(() => RDocCodecRegistry.Get<NeverMapped>());
        Assert.Contains("[RustegonDocument]", e.Message, StringComparison.Ordinal);
        Assert.Contains("EnableReflectionFallback", e.Message, StringComparison.Ordinal);

        var fake = new FakeGrpcServer(null);
        var s = new RustegonClientSettings { Tls = new TlsSettings { Enabled = false }, Credential = RustegonCredential.ApiKey("rgn_fake_key") };
        s.Endpoints.Add("fake.invalid:7700");
        await using var client = new RustegonClient(s, fake);
        Assert.Throws<NotSupportedException>(() => client.GetDatabase("db").GetCollection<NeverMapped>("c"));
        Assert.Throws<NotSupportedException>(() => client.GetDatabase("db").QueryAsync<NeverMapped>("FROM c"));
        Assert.Equal("c", client.GetDatabase("db").GetCollection<Order>("c").Name);
    }

    /// <summary>A POCO without [RustegonDocument], never given to the fallback.</summary>
    internal sealed class NeverMapped
    {
        /// <summary>A value.</summary>
        public int A { get; set; }
    }

    /// <summary>No constructor binds its parameters.</summary>
    internal sealed class NoConstructor
    {
        /// <summary>Creates it.</summary>
        /// <param name="other">Matches no property.</param>
        public NoConstructor(int other) => A = other;

        /// <summary>A value.</summary>
        public int A { get; set; }
    }

    /// <summary>A member type outside the mapping.</summary>
    internal sealed class UnsupportedMember
    {
        /// <summary>Not mapped.</summary>
        public IList<int>? Xs { get; set; }
    }

    /// <summary>Two members with one field name.</summary>
    internal sealed class DuplicateField
    {
        /// <summary>A.</summary>
        [RgnField("x")]
        public int A { get; set; }

        /// <summary>B.</summary>
        [RgnField("x")]
        public int B { get; set; }
    }
}

/// <summary>Tests that switch the process-wide reflection fallback on run alone.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ReflectionFallbackGroup
{
    /// <summary>The collection name.</summary>
    public const string Name = "reflection-fallback";
}

/// <summary>TC-DRV-NET-025: <see cref="RDocCodecRegistry.EnableReflectionFallback"/> maps plain POCOs.</summary>
[Collection(ReflectionFallbackGroup.Name)]
public sealed class MappingReflectionFallbackTests
{
    [Fact]
    public void tc_drv_net_025_opt_in_maps_plain_types()
    {
        Assert.False(RDocCodecRegistry.IsReflectionFallbackEnabled);
        RDocCodecRegistry.EnableReflectionFallback();
        try
        {
            Assert.True(RDocCodecRegistry.IsReflectionFallbackEnabled);
            IRDocCodec<PlainPoco> codec = RDocCodecRegistry.Get<PlainPoco>();
            Assert.IsType<ReflectionCodec<PlainPoco>>(codec);
            Assert.Same(codec, RDocCodecRegistry.Get<PlainPoco>());
            var value = new PlainPoco { Name = "n", Child = new PlainChild { Values = [1, 2] }, Status = OrderStatus.Paid };
            RDocument d = codec.Encode(value);
            Assert.Equal("""{"name":"n","child":{"values":[1,2]},"status":"Paid"}""", d.ToJson());
            PlainPoco back = codec.Decode(d);
            Assert.Equal([1L, 2L], back.Child!.Values);

            // Generated codecs keep priority over the fallback.
            Assert.IsNotType<ReflectionCodec<Order>>(RDocCodecRegistry.Get<Order>());
        }
        finally
        {
            RDocCodecRegistry.DisableReflectionFallback();
        }
    }

    /// <summary>A POCO without attributes.</summary>
    internal sealed class PlainPoco
    {
        /// <summary>Name.</summary>
        public string? Name { get; set; }

        /// <summary>Nested plain type (the fallback needs no attribute on it).</summary>
        public PlainChild? Child { get; set; }

        /// <summary>Enum.</summary>
        public OrderStatus Status { get; set; }
    }

    /// <summary>A nested POCO without attributes.</summary>
    internal sealed class PlainChild
    {
        /// <summary>Values.</summary>
        public List<long>? Values { get; set; }
    }
}
