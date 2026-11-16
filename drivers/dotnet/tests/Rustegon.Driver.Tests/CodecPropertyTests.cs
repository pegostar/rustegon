// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Linq;
using System.Text;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>Generators of valid RDoc values (every type, nested up to depth 4).</summary>
public static class RDocArbitraries
{
    private static readonly Gen<string> Text =
        ArbMap.Default.GeneratorFor<string>().Where(s => s is not null && IsValidUtf16(s));

    private static readonly Gen<string> FieldName =
        Text.Where(s => s.Length > 0 && s[0] != '$' && !s.Contains('\0', StringComparison.Ordinal) && Encoding.UTF8.GetByteCount(s) <= 1024);

    internal static bool IsValidUtf16(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(s[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static Gen<RDocValue> Scalar()
    {
        Gen<long> int64 = ArbMap.Default.GeneratorFor<long>();
        Gen<byte[]> bytes = ArbMap.Default.GeneratorFor<byte[]>().Where(b => b is not null);
        Gen<UInt128> coefficient = Gen.Zip(ArbMap.Default.GeneratorFor<ulong>(), ArbMap.Default.GeneratorFor<ulong>(),
            (hi, lo) => (((UInt128)hi << 64) | lo) % (Decimal128.MaxCoefficient + 1));
        return Gen.OneOf(
            Gen.Constant(RDocValue.Null),
            Gen.Constant(RDocValue.MinKey),
            Gen.Constant(RDocValue.MaxKey),
            ArbMap.Default.GeneratorFor<bool>().Select(RDocValue.FromBoolean),
            int64.Select(RDocValue.FromInt64),
            ArbMap.Default.GeneratorFor<double>().Select(RDocValue.FromDouble),
            Gen.Zip(
                Gen.Zip(ArbMap.Default.GeneratorFor<bool>(), coefficient, (negative, c) => (Negative: negative, Coefficient: c)),
                Gen.Choose(Decimal128.MinExponent, Decimal128.MaxExponent),
                (nc, e) => RDocValue.FromDecimal128(Decimal128.FromParts(nc.Negative, nc.Coefficient, e))),
            Gen.Elements(Decimal128.NaN, Decimal128.PositiveInfinity, Decimal128.NegativeInfinity).Select(RDocValue.FromDecimal128),
            ArbMap.Default.GeneratorFor<decimal>().Select(d => RDocValue.FromDecimal128(d)),
            Text.Select(s => RDocValue.FromString(s)),
            bytes.Select(b => RDocValue.FromBinary(b)),
            bytes.Select(b => RDocValue.FromBinary(0x80, b)),
            ArbMap.Default.GeneratorFor<Guid>().Select(g => RDocValue.FromBinary(BinarySubtype.Uuid, g.ToByteArray())),
            int64.Select(RDocValue.FromUnixTimeMilliseconds),
            Gen.Zip(ArbMap.Default.GeneratorFor<ulong>(), ArbMap.Default.GeneratorFor<uint>(), (w, l) => RDocValue.FromTimestamp(new RDocTimestamp(w, l))),
            Gen.ArrayOf(ArbMap.Default.GeneratorFor<byte>(), 12).Select(b => RDocValue.FromObjectId(new ObjectId(b))),
            ArbMap.Default.GeneratorFor<Guid>().Select(RDocValue.FromGuid),
            ArbMap.Default.GeneratorFor<float[]>().Where(a => a is not null)
                .Select(a => RDocValue.FromVector(a.Where(float.IsFinite).ToArray())));
    }

    private static Gen<RDocValue> ValueOf(int depth) => depth <= 0
        ? Scalar()
        : Gen.Frequency(
            (6, Scalar()),
            (1, Gen.ListOf(ValueOf(depth - 1)).Select(items => RDocValue.FromArray(new RDocArray(items)))),
            (1, DocumentOf(depth - 1).Select(RDocValue.FromDocument)));

    private static Gen<RDocument> DocumentOf(int depth) =>
        Gen.ListOf(Gen.Zip(FieldName, ValueOf(depth), (n, v) => (Name: n, Value: v))).Select(fields =>
        {
            var d = new RDocument();
            foreach ((string name, RDocValue value) in fields)
            {
                d.TryAdd(name, value);
            }

            return d;
        });

    public static Arbitrary<RDocValue> Value() => Arb.From(ValueOf(3));

    public static Arbitrary<RDocument> Document() => Arb.From(DocumentOf(3));
}

/// <summary>TC-DRV-NET-002 (FR-DRV-001, FR-DOC-001): value → bytes → value and value → JSON → value round trips.</summary>
[Properties(Arbitrary = [typeof(RDocArbitraries)], MaxTest = 300)]
public sealed class CodecPropertyTests
{
    [Property]
    public bool tc_drv_net_002_value_encoding_round_trips(RDocValue v) =>
        RDocReader.ReadValue(RDocWriter.ValueToBytes(v)).Equals(v);

    [Property]
    public bool tc_drv_net_002_document_round_trips_byte_exact(RDocument d)
    {
        byte[] bytes = d.ToBytes();
        RDocument back = RDocReader.ReadDocument(bytes);
        return back.Equals(d) && back.ToBytes().AsSpan().SequenceEqual(bytes) && RDocWriter.GetEncodedLength(d) == bytes.Length;
    }

    [Property]
    public bool tc_drv_net_002_canonical_json_round_trips(RDocument d) =>
        RDocument.FromJson(d.ToJson()).Equals(d);

    [Property]
    public bool tc_drv_net_002_extended_json_round_trips(RDocument d) =>
        RDocument.FromJson(d.ToJson(RDocJsonMode.Extended)).Equals(d);

    [Property]
    public bool tc_drv_net_002_canonical_json_is_deterministic(RDocument d) =>
        RDocument.FromJson(d.ToJson()).ToJson() == d.ToJson();

    [Property]
    public bool tc_drv_net_002_corrupted_bytes_never_escape_as_other_exceptions(RDocument d, int position, byte value)
    {
        // Any single-byte change either still decodes or fails with RDocException; never anything
        // else (the decoder never crashes on untrusted input, data-model.md §4).
        byte[] bytes = d.ToBytes();
        bytes[(int)((uint)position % (uint)bytes.Length)] = value;
        try
        {
            RDocReader.ReadDocument(bytes);
        }
        catch (RDocException)
        {
        }

        return true;
    }
}
