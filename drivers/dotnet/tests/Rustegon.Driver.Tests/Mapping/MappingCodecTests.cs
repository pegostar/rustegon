// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using Google.Protobuf;
using Rustegon.Driver.Internal.Builders;
using Rustegon.Driver.Mapping;
using Rustegon.Driver.MappedTypes;
using Xunit;

namespace Rustegon.Driver.Tests.Mapping;

/// <summary>
/// TC-DRV-NET-022 (FR-DRV-001): the mapping attributes, the naming policy and member-expression
/// paths (<see cref="FieldPath"/>, <c>Filter.Eq&lt;T&gt;</c>) that produce the same AST as string paths.
/// </summary>
public sealed class MappingAttributeTests
{
    private static RDocument Encode<T>(T value) => RDocCodecRegistry.Get<T>().Encode(value);

    private static T Decode<T>(RDocument d) => RDocCodecRegistry.Get<T>().Decode(d);

    [Fact]
    public void tc_drv_net_022_field_names_follow_the_attributes_and_camel_case()
    {
        var all = new AllTypes { Text = "t", Renamed = "r", Ignored = "i", Rev = "should-not-be-written" };
        RDocument d = Encode(all);
        Assert.Equal(
            ["flag", "long", "int", "short", "double", "float", "money", "text", "bytes", "memory", "when", "at", "uuid", "oid", "dec", "vector",
             "vectorMemory", "status", "maybeInt", "maybeStatus", "custom_name", "tags", "numbers", "scores", "address", "lines", "extra", "any"],
            d.Names);

        // Id by convention, written first whatever the declaration order (PD-108).
        Assert.Equal("""{"_id":"n1","body":"b"}""", Encode(new Note { Body = "b", Id = "n1" }).ToJson());
        Assert.Equal("_id", FieldPath.Of<Note>(x => x.Id));

        // A null id is not written (the server generates one); a set id is "_id".
        all.Id = ObjectId.NewObjectId();
        Assert.Equal("_id", Encode(all).Names.First());
        Assert.Equal(all.Id, Decode<AllTypes>(Encode(all)).Id);
    }

    [Fact]
    public void tc_drv_net_022_rev_and_counters_are_read_but_never_written()
    {
        var order = new Order(7, OrderStatus.Paid, 12.5m) { Customer = "ann", Rev = "r1", Views = 99 };
        RDocument d = Encode(order);
        Assert.False(d.ContainsKey("_rev"));
        Assert.False(d.ContainsKey("views"));
        d.Add("_rev", "0123ABC");
        d.Add("views", RDocValue.FromCounter(41));
        Order back = Decode<Order>(d);
        Assert.Equal("0123ABC", back.Rev);
        Assert.Equal(41, back.Views);
        d["views"] = 5L;
        Assert.Equal(5, Decode<Order>(d).Views);
    }

    [Fact]
    public void tc_drv_net_022_vector_dimensions_and_geo_points()
    {
        var order = new Order(1, OrderStatus.New, 1m) { Customer = "c", Embedding = [1f, 2f, 3f], Location = [12.4964, 41.9028] };
        RDocument d = Encode(order);
        Assert.Equal(RDocType.VectorF32, d["embedding"].Type);
        Assert.Equal("""{"type":"Point","coordinates":[12.4964,41.9028]}""", d["location"].ToJson());
        Assert.Equal([12.4964, 41.9028], Decode<Order>(d).Location!);

        RDocException wrongDims = Assert.Throws<RDocException>(() => Encode(order with { Embedding = [1f, 2f] }));
        Assert.Contains("'embedding'", wrongDims.Message, StringComparison.Ordinal);
        d["embedding"] = RDocValue.FromVector([1f]);
        Assert.Throws<RDocException>(() => Decode<Order>(d));
        Assert.Throws<RDocException>(() => Encode(order with { Location = [1.0] }));
        Assert.Throws<RDocException>(() => Encode(order with { Location = [double.NaN, 1.0] }));
        Assert.Throws<RDocException>(() => Encode(order with { Location = [181.0, 0.0] }));
        Assert.Throws<RDocException>(() => Encode(order with { Location = [0.0, -90.5] }));
        d["embedding"] = RDocValue.Null;
        d["location"] = new RDocument { { "type", "LineString" }, { "coordinates", new RDocArray() } };
        Assert.Throws<RDocException>(() => Decode<Order>(d));
    }

    [Fact]
    public void tc_drv_net_022_member_expressions_give_the_mapped_paths()
    {
        Assert.Equal("_id", FieldPath.Of<Order>(x => x.Id));
        Assert.Equal("_rev", FieldPath.Of<Order>(x => x.Rev));
        Assert.Equal("status", FieldPath.Of<Order>(x => x.Status));
        Assert.Equal("lines.0.sku", FieldPath.Of<Order>(x => x.Lines[0].Sku));
        Assert.Equal("custom_name", FieldPath.Of<AllTypes>(x => x.Renamed));
        Assert.Equal("address.city", FieldPath.Of<AllTypes>(x => x.Address!.City));
        Assert.Equal("numbers.2", FieldPath.Of<AllTypes>(x => x.Numbers![2]));
        Assert.Equal("scores.math", FieldPath.Of<AllTypes>(x => x.Scores!["math"]));
        Assert.Equal("lines.1.qty", FieldPath.Of<AllTypes>(x => x.Lines![1].Qty));
    }

    [Fact]
    public void tc_drv_net_022_unsupported_expressions_throw_when_the_filter_is_built()
    {
        int i = 1;
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Ignored));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Text!.Length));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Tags!.Count));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Text!.ToUpperInvariant()));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Int + 1));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Lines![i].Sku));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Scores!["a.b"]));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x.Scores!["12"]));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => x));
        Assert.Throws<NotSupportedException>(() => FieldPath.Of<AllTypes>(x => DateTime.UtcNow));
        Assert.Throws<NotSupportedException>(() => Filter.Eq<AllTypes>(x => x.Ignored, "a"));
    }

    [Fact]
    public void tc_drv_net_022_expression_filters_build_the_same_ast_as_string_paths()
    {
        (Filter Typed, Filter Text)[] pairs =
        [
            (Filter.Eq<Order>(x => x.Status, "Paid"), Filter.Eq("status", "Paid")),
            (Filter.Ne<Order>(x => x.Lines[0].Sku, "a"), Filter.Ne("lines.0.sku", "a")),
            (Filter.Gt<Order>(x => x.Total, 10m), Filter.Gt("total", 10m)),
            (Filter.Gte<Order>(x => x.Id, 2), Filter.Gte("_id", 2)),
            (Filter.Lt<AllTypes>(x => x.Address!.City, "M"), Filter.Lt("address.city", "M")),
            (Filter.Lte<AllTypes>(x => x.Scores!["math"], 5.5), Filter.Lte("scores.math", 5.5)),
            (Filter.In<Order>(x => x.Status, ["New", "Paid"]), Filter.In("status", ["New", "Paid"])),
            (Filter.Nin<Order>(x => x.Status, ["New"]), Filter.Nin("status", ["New"])),
            (Filter.Exists<Order>(x => x.Embedding, false), Filter.Exists("embedding", false)),
            (Filter.Eq<Order>(x => x.Status, "Paid") & Filter.Gt<Order>(x => x.Total, 1), Filter.Eq("status", "Paid") & Filter.Gt("total", 1)),
        ];
        foreach ((Filter typed, Filter text) in pairs)
        {
            var s1 = new ParamSink();
            var s2 = new ParamSink();
            Assert.Equal(text.ToAst(s2), typed.ToAst(s1));
            Assert.Equal(s2.Params.ToDictionary(p => p.Key, p => p.Value.ToByteString()), s1.Params.ToDictionary(p => p.Key, p => p.Value.ToByteString()));
        }
    }
}

/// <summary>
/// TC-DRV-NET-023 (FR-DRV-001): the type mapping of dotnet-driver.md §7 as properties (FsCheck:
/// object → RDoc → bytes → object → RDoc is byte-identical and keeps the values) and its error cases.
/// </summary>
public sealed class MappingTypeTests
{
    private static readonly IRDocCodec<AllTypes> Codec = RDocCodecRegistry.Get<AllTypes>();

    internal static AllTypes Make(long l, int i, short s, double d, float f, decimal m, string? text, byte[]? bytes, long ms, Guid g, bool flag, int? maybe)
    {
        return new AllTypes
        {
            Flag = flag,
            Long = l,
            Int = i,
            Short = s,
            Double = d,
            Float = f,
            Money = m,
            Text = text is null || RDocArbitraries.IsValidUtf16(text) ? text : "x",
            Bytes = bytes,
            Memory = bytes ?? [],
            When = DateTime.UnixEpoch.AddMilliseconds(ms % 4_000_000_000_000L),
            At = DateTimeOffset.FromUnixTimeMilliseconds(ms % 4_000_000_000_000L),
            Uuid = g,
            Oid = new ObjectId(g.ToByteArray().AsSpan(0, 12)),
            Dec = Decimal128.FromDecimal(m),
            Vector = bytes?.Select(b => (float)b / 3).ToArray(),
            VectorMemory = new float[] { f is var x && float.IsFinite(x) ? x : 0f },
            Status = (OrderStatus)(Math.Abs(i % 3)),
            MaybeInt = maybe,
            MaybeStatus = maybe is null ? null : OrderStatus.Shipped,
            Renamed = text is null ? null : "r",
            Tags = text is null ? null : ["a", "b"],
            Numbers = [l, i, s],
            Scores = new Dictionary<string, double> { ["x"] = d },
            Address = new Address("main", "turin") { Zip = maybe?.ToString(System.Globalization.CultureInfo.InvariantCulture) },
            Lines = [new Line { Sku = "s", Qty = i }],
            Extra = new RDocument { { "k", l } },
            Any = flag ? RDocValue.FromInt64(l) : RDocValue.Null,
        };
    }

    [FsCheck.Xunit.Property(MaxTest = 300)]
    public bool tc_drv_net_023_mapped_objects_round_trip_byte_exact(long l, int i, short s, double d, float f, decimal m, string? text, byte[]? bytes, long ms, Guid g, bool flag, int? maybe)
    {
        AllTypes value = Make(l, i, s, d, f, m, text, bytes, ms, g, flag, maybe);
        byte[] first = Codec.Encode(value).ToBytes();
        AllTypes back = Codec.Decode(RDocument.FromBytes(first));
        byte[] second = Codec.Encode(back).ToBytes();
        return first.AsSpan().SequenceEqual(second)
            && back.Long == l && back.Int == i && back.Short == s && back.Money == m && back.Uuid == g && back.Flag == flag && back.MaybeInt == maybe
            && back.When == value.When && back.When.Kind == DateTimeKind.Utc && back.At == value.At
            && back.Text == value.Text && back.Status == value.Status && back.Address == value.Address;
    }

    [Fact]
    public void tc_drv_net_023_rdoc_types_of_each_member()
    {
        RDocument d = Codec.Encode(Make(1, 2, 3, 4.5, 5.5f, 6.25m, "t", [1, 2], 7, Guid.NewGuid(), true, 8));
        (string Field, RDocType Type)[] expected =
        [
            ("flag", RDocType.Bool), ("long", RDocType.Int64), ("int", RDocType.Int64), ("short", RDocType.Int64), ("double", RDocType.Float64),
            ("float", RDocType.Float64), ("money", RDocType.Decimal128), ("text", RDocType.String), ("bytes", RDocType.Binary), ("memory", RDocType.Binary),
            ("when", RDocType.DateTime), ("at", RDocType.DateTime), ("uuid", RDocType.Uuid), ("oid", RDocType.ObjectId), ("dec", RDocType.Decimal128),
            ("vector", RDocType.VectorF32), ("vectorMemory", RDocType.VectorF32), ("status", RDocType.String), ("maybeInt", RDocType.Int64),
            ("maybeStatus", RDocType.String), ("tags", RDocType.Array), ("numbers", RDocType.Array), ("scores", RDocType.Object),
            ("address", RDocType.Object), ("lines", RDocType.Array), ("extra", RDocType.Object), ("any", RDocType.Int64),
        ];
        foreach ((string field, RDocType type) in expected)
        {
            Assert.Equal(type, d[field].Type);
        }

        Assert.Equal("Shipped", d["maybeStatus"].AsString());
        Assert.Equal("""{"street":"main","city":"turin","zip":"8"}""", d["address"].ToJson());
        Assert.Equal("""[{"sku":"s","qty":2}]""", d["lines"].ToJson());
        Assert.Equal(RDocType.Null, Codec.Encode(new AllTypes())["text"].Type);
    }

    [Fact]
    public void tc_drv_net_023_unknown_fields_are_ignored_and_missing_fields_keep_defaults()
    {
        AllTypes back = Codec.Decode(new RDocument { { "unknown", 1 }, { "_createdAt", DateTimeOffset.UnixEpoch }, { "long", 5 }, { "_type", "x" } });
        Assert.Equal(5, back.Long);
        Assert.Equal(default, back.When); // absent → default, also over an initializer value (PD-108)
        Assert.True(back.Any.IsMissing);

        // Records: constructor parameters and init-only members take default when absent.
        Address a = RDocCodecRegistry.Get<Address>().Decode(new RDocument { { "city", "x" } });
        Assert.Equal(new Address(null!, "x"), a);
        Order o = RDocCodecRegistry.Get<Order>().Decode(new RDocument { { "_id", 3 } });
        Assert.Equal(3, o.Id);
        Assert.Null(o.Lines); // absent → default (PD-108)
    }

    [Fact]
    public void tc_drv_net_023_invalid_values_fail_with_the_field_name()
    {
        RDocException local = Assert.Throws<RDocException>(() => Codec.Encode(new AllTypes { When = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Local) }));
        Assert.Contains("'when'", local.Message, StringComparison.Ordinal);
        Assert.Equal(1001, local.Code);
        Assert.Throws<RDocException>(() => Codec.Encode(new AllTypes { Status = (OrderStatus)42 }));
        Assert.Throws<RDocException>(() => Codec.Encode(new AllTypes { Vector = [float.NaN] }));

        Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "int", long.MaxValue } }));
        Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "short", 40_000 } }));
        Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "long", RDocValue.Null } }));
        Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "long", "1" } }));
        Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "status", "Lost" } }));
        Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "status", "1" } }));
        Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "money", Decimal128.Parse("1E+40") } }));
        RDocException nested = Assert.Throws<RDocException>(() => Codec.Decode(new RDocument { { "lines", new RDocArray { new RDocument { { "qty", "x" } } } } }));
        Assert.Contains("'lines'", nested.Message, StringComparison.Ordinal);
        Assert.Contains("'qty'", nested.Message, StringComparison.Ordinal);

        // Numeric widening on reads: int64 into floating-point and decimal members.
        AllTypes widened = Codec.Decode(new RDocument { { "double", 3 }, { "float", 4 }, { "money", 5 } });
        Assert.Equal((3.0, 4f, 5m), (widened.Double, widened.Float, widened.Money));
    }

    [Fact]
    public void tc_drv_net_023_self_referencing_types_nest()
    {
        var tree = new TreeNode { Label = "root", Children = [new TreeNode { Label = "a", Children = [new TreeNode { Label = "a1" }] }, new TreeNode { Label = "b" }] };
        IRDocCodec<TreeNode> c = RDocCodecRegistry.Get<TreeNode>();
        RDocument d = c.Encode(tree);
        Assert.Equal(
            """{"label":"root","children":[{"label":"a","children":[{"label":"a1","children":null}]},{"label":"b","children":null}]}""",
            d.ToJson());
        Assert.Equal(d.ToBytes(), c.Encode(c.Decode(d)).ToBytes());
    }
}

/// <summary>TC-DRV-NET-024 (FR-DRV-001): polymorphism through <see cref="RgnDiscriminatorAttribute"/> (PD-110).</summary>
public sealed class MappingPolymorphismTests
{
    private static readonly IRDocCodec<Shape> Shapes = RDocCodecRegistry.Get<Shape>();

    [Fact]
    public void tc_drv_net_024_base_codec_writes_the_discriminator_first_and_reads_the_right_type()
    {
        RDocument circle = Shapes.Encode(new Circle { Id = "c1", Name = "dot", Radius = 2 });
        Assert.Equal("""{"_id":"c1","_type":"circle","name":"dot","radius":2.0}""", circle.ToJson());
        Assert.Equal(2, Assert.IsType<Circle>(Shapes.Decode(circle)).Radius);

        RDocument square = Shapes.Encode(new Square { Name = "sq", Width = 1, Height = 1, Rounded = true });
        Assert.Equal("""{"_type":"square","name":"sq","width":1.0,"height":1.0,"rounded":true}""", square.ToJson());
        Assert.True(Assert.IsType<Square>(Shapes.Decode(square)).Rounded);
        Assert.IsType<Square>(RDocCodecRegistry.Get<Rect>().Decode(square));
        Assert.Equal(square.ToBytes(), RDocCodecRegistry.Get<Rect>().Encode(new Square { Name = "sq", Width = 1, Height = 1, Rounded = true }).ToBytes());
        Assert.Equal(square.ToBytes(), RDocCodecRegistry.Get<Square>().Encode(new Square { Name = "sq", Width = 1, Height = 1, Rounded = true }).ToBytes());

        RDocument triangle = Shapes.Encode(new Triangle { Id = "t", Side = 1 });
        Assert.Equal("""{"_id":"t","_type":"Triangle","name":null,"side":1.0}""", triangle.ToJson());
        Assert.IsType<Triangle>(Shapes.Decode(triangle));

        RDocument rect = Shapes.Encode(new Rect { Width = 3 });
        Assert.Equal("rect", rect["_type"].AsString());
        Assert.IsType<Rect>(Shapes.Decode(rect));

        // The intermediate type reads its own documents without a discriminator too.
        Assert.IsType<Rect>(RDocCodecRegistry.Get<Rect>().Decode(new RDocument { { "width", 1.0 } }));
    }

    [Fact]
    public void tc_drv_net_024_unknown_or_missing_discriminators_fail()
    {
        Assert.Throws<RDocException>(() => Shapes.Decode(new RDocument { { "_type", "hexagon" } }));
        Assert.Throws<RDocException>(() => Shapes.Decode(new RDocument { { "name", "no type" } }));
        Assert.Throws<RDocException>(() => Shapes.Decode(new RDocument { { "_type", 3 } }));
        Assert.Throws<RDocException>(() => RDocCodecRegistry.Get<Rect>().Decode(new RDocument { { "_type", "circle" } }));
        Assert.Throws<RDocException>(() => RDocCodecRegistry.Get<Circle>().Decode(new RDocument { { "_type", "square" } }));
    }

    [Fact]
    public void tc_drv_net_024_polymorphic_members_and_lists_round_trip()
    {
        var drawing = new Drawing { Shapes = [new Circle { Radius = 1 }, new Square { Width = 2 }, new Rect { Height = 3 }], Main = new Circle { Radius = 9 } };
        IRDocCodec<Drawing> c = RDocCodecRegistry.Get<Drawing>();
        RDocument d = c.Encode(drawing);
        Drawing back = c.Decode(d);
        Assert.Equal([typeof(Circle), typeof(Square), typeof(Rect)], back.Shapes!.Select(s => s.GetType()));
        Assert.Equal(9, Assert.IsType<Circle>(back.Main).Radius);
        Assert.Equal(d.ToBytes(), c.Encode(back).ToBytes());
    }
}
