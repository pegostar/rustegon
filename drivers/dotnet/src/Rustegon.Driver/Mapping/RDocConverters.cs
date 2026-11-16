// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Rustegon.Driver.Mapping;

/// <summary>
/// The converters of the type mapping (dotnet-driver.md §7). Generated codecs reference these
/// members; the reflection fallback picks the same ones, so both produce the same bytes.
/// Reads are strict about the RDoc type except numeric widening (an int64 into a floating-point
/// or decimal member); narrowing (int64 into <see cref="int"/> or <see cref="short"/>) is checked.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class RDocConverters
{
    /// <summary><see cref="bool"/> ↔ bool.</summary>
    public static RDocConverter<bool> Boolean { get; } = new FuncConverter<bool>(RDocValue.FromBoolean, v => v.AsBoolean());

    /// <summary><see cref="long"/> ↔ int64.</summary>
    public static RDocConverter<long> Int64 { get; } = new FuncConverter<long>(RDocValue.FromInt64, v => v.AsInt64());

    /// <summary><see cref="int"/> ↔ int64 (reads checked).</summary>
    public static RDocConverter<int> Int32 { get; } = new FuncConverter<int>(x => RDocValue.FromInt64(x), v => checked((int)v.AsInt64()));

    /// <summary><see cref="short"/> ↔ int64 (reads checked).</summary>
    public static RDocConverter<short> Int16 { get; } = new FuncConverter<short>(x => RDocValue.FromInt64(x), v => checked((short)v.AsInt64()));

    /// <summary><see cref="double"/> ↔ float64 (reads also take int64).</summary>
    public static RDocConverter<double> Double { get; } = new FuncConverter<double>(RDocValue.FromDouble, ReadDouble);

    /// <summary><see cref="float"/> ↔ float64 (reads also take int64).</summary>
    public static RDocConverter<float> Single { get; } = new FuncConverter<float>(x => RDocValue.FromDouble(x), v => (float)ReadDouble(v));

    /// <summary><see cref="decimal"/> ↔ decimal128 (reads also take int64; a decimal128 outside <see cref="decimal"/> fails).</summary>
    public static RDocConverter<decimal> Decimal { get; } = new FuncConverter<decimal>(
        x => RDocValue.FromDecimal128(Rustegon.Driver.Decimal128.FromDecimal(x)),
        v => v.Type == RDocType.Int64 ? v.AsInt64() : v.AsDecimal128().ToDecimal());

    /// <summary><see cref="Driver.Decimal128"/> ↔ decimal128.</summary>
    public static RDocConverter<Decimal128> Decimal128 { get; } = new FuncConverter<Decimal128>(RDocValue.FromDecimal128, v => v.AsDecimal128());

    /// <summary><see cref="string"/> ↔ string.</summary>
    public static RDocConverter<string> String { get; } = new FuncConverter<string>(RDocValue.FromString, v => v.AsString());

    /// <summary><c>byte[]</c> ↔ binary (generic subtype).</summary>
    public static RDocConverter<byte[]> Binary { get; } = new FuncConverter<byte[]>(x => RDocValue.FromBinary(x), v => v.AsBinary().ToArray());

    /// <summary><c>ReadOnlyMemory&lt;byte&gt;</c> ↔ binary (generic subtype).</summary>
    public static RDocConverter<ReadOnlyMemory<byte>> BinaryMemory { get; } = new FuncConverter<ReadOnlyMemory<byte>>(x => RDocValue.FromBinary(x.Span), v => v.AsBinary());

    /// <summary><see cref="System.DateTime"/> ↔ datetime; writes require <see cref="DateTimeKind.Utc"/>, reads give UTC (millisecond precision).</summary>
    public static RDocConverter<DateTime> DateTime { get; } = new FuncConverter<DateTime>(RDocValue.FromDateTime, v => v.AsDateTimeOffset().UtcDateTime);

    /// <summary><see cref="System.DateTimeOffset"/> ↔ datetime (the instant; reads give offset zero, millisecond precision).</summary>
    public static RDocConverter<DateTimeOffset> DateTimeOffset { get; } = new FuncConverter<DateTimeOffset>(RDocValue.FromDateTimeOffset, v => v.AsDateTimeOffset());

    /// <summary><see cref="System.Guid"/> ↔ uuid.</summary>
    public static RDocConverter<Guid> Guid { get; } = new FuncConverter<Guid>(RDocValue.FromGuid, v => v.AsGuid());

    /// <summary><see cref="Driver.ObjectId"/> ↔ objectId.</summary>
    public static RDocConverter<ObjectId> ObjectId { get; } = new FuncConverter<ObjectId>(RDocValue.FromObjectId, v => v.AsObjectId());

    /// <summary><see cref="RDocValue"/> as is (any type; a missing value is written as null).</summary>
    public static RDocConverter<RDocValue> Value { get; } = new FuncConverter<RDocValue>(v => v.IsMissing ? RDocValue.Null : v, v => v);

    /// <summary><see cref="RDocument"/> ↔ object (schemaless sub-document).</summary>
    public static RDocConverter<RDocument> RawDocument { get; } = new FuncConverter<RDocument>(RDocValue.FromDocument, v => v.AsDocument());

    /// <summary><see cref="RDocArray"/> ↔ array (schemaless).</summary>
    public static RDocConverter<RDocArray> RawArray { get; } = new FuncConverter<RDocArray>(RDocValue.FromArray, v => v.AsArray());

    /// <summary><c>float[]</c> ↔ vector_f32 (elements must be finite).</summary>
    public static RDocConverter<float[]> Vector { get; } = FixedVector(0);

    /// <summary><c>ReadOnlyMemory&lt;float&gt;</c> ↔ vector_f32.</summary>
    public static RDocConverter<ReadOnlyMemory<float>> VectorMemory { get; } = FixedVectorMemory(0);

    /// <summary>
    /// <c>double[]</c> <c>[longitude, latitude]</c> ↔ GeoJSON point <c>{"type": "Point", "coordinates": [lng, lat]}</c>
    /// (<see cref="RgnGeoPointAttribute"/>, PD-109).
    /// </summary>
    public static RDocConverter<double[]> GeoPoint { get; } = new FuncConverter<double[]>(WriteGeoPoint, ReadGeoPoint);

    /// <summary>A counter projection (<see cref="RgnCounterAttribute"/>): reads counter or int64 values; never written by the codecs.</summary>
    public static RDocConverter<long> Counter { get; } = new FuncConverter<long>(
        RDocValue.FromInt64, v => v.Type == RDocType.Counter ? v.AsCounter() : v.AsInt64());

    /// <summary><c>float[]</c> ↔ vector_f32 of exactly <paramref name="dimensions"/> elements (<see cref="RgnVectorAttribute"/>; 0 = any).</summary>
    /// <param name="dimensions">The number of dimensions, or 0.</param>
    /// <returns>The converter.</returns>
    public static RDocConverter<float[]> FixedVector(int dimensions) => new FuncConverter<float[]>(
        x => RDocValue.FromVector(CheckDimensions(x, dimensions)),
        v => CheckDimensions(v.AsVector(), dimensions).ToArray());

    /// <summary><c>ReadOnlyMemory&lt;float&gt;</c> ↔ vector_f32 of exactly <paramref name="dimensions"/> elements (0 = any).</summary>
    /// <param name="dimensions">The number of dimensions, or 0.</param>
    /// <returns>The converter.</returns>
    public static RDocConverter<ReadOnlyMemory<float>> FixedVectorMemory(int dimensions) => new FuncConverter<ReadOnlyMemory<float>>(
        x => RDocValue.FromVector(CheckDimensions(x, dimensions).Span),
        v => CheckDimensions(v.AsVector(), dimensions));

    /// <summary><c>S?</c> over the converter of <typeparamref name="TS"/>.</summary>
    /// <typeparam name="TS">The underlying value type.</typeparam>
    /// <param name="inner">Its converter.</param>
    /// <returns>The converter.</returns>
    public static RDocConverter<TS?> Nullable<TS>(RDocConverter<TS> inner)
        where TS : struct => new NullableConverter<TS>(inner ?? throw new ArgumentNullException(nameof(inner)));

    /// <summary><c>List&lt;E&gt;</c> ↔ array.</summary>
    /// <typeparam name="TE">Element type.</typeparam>
    /// <param name="element">Element converter.</param>
    /// <returns>The converter.</returns>
    public static RDocConverter<List<TE>> List<TE>(RDocConverter<TE> element)
    {
        ArgumentNullException.ThrowIfNull(element);
        return new FuncConverter<List<TE>>(
            x => WriteArray(x, element),
            v =>
            {
                RDocArray a = v.AsArray();
                var r = new List<TE>(a.Count);
                foreach (RDocValue e in a)
                {
                    r.Add(element.Read(e));
                }

                return r;
            });
    }

    /// <summary><c>E[]</c> ↔ array (<c>byte[]</c> and <c>float[]</c> use <see cref="Binary"/> and <see cref="Vector"/>).</summary>
    /// <typeparam name="TE">Element type.</typeparam>
    /// <param name="element">Element converter.</param>
    /// <returns>The converter.</returns>
    public static RDocConverter<TE[]> Array<TE>(RDocConverter<TE> element)
    {
        ArgumentNullException.ThrowIfNull(element);
        return new FuncConverter<TE[]>(
            x => WriteArray(x, element),
            v =>
            {
                RDocArray a = v.AsArray();
                var r = new TE[a.Count];
                for (int i = 0; i < r.Length; i++)
                {
                    r[i] = element.Read(a[i]);
                }

                return r;
            });
    }

    /// <summary><c>Dictionary&lt;string, E&gt;</c> ↔ object.</summary>
    /// <typeparam name="TE">Value type.</typeparam>
    /// <param name="element">Value converter.</param>
    /// <returns>The converter.</returns>
    public static RDocConverter<Dictionary<string, TE>> Dictionary<TE>(RDocConverter<TE> element) =>
        new DictionaryConverter<TE>(element ?? throw new ArgumentNullException(nameof(element)));

    /// <summary>An enum ↔ the string of its member name (dotnet-driver.md §7: enums as strings; undefined values fail).</summary>
    /// <typeparam name="TE">The enum.</typeparam>
    /// <returns>The converter.</returns>
    public static RDocConverter<TE> Enum<TE>()
        where TE : struct, Enum => new FuncConverter<TE>(
            x => RDocValue.FromString(System.Enum.GetName(x) ?? throw new ArgumentException($"{x} is not a named value of {typeof(TE).Name}.", nameof(x))),
            v => System.Enum.TryParse(v.AsString(), out TE r) && System.Enum.IsDefined(r) && !char.IsAsciiDigit(v.AsString()[0]) && v.AsString()[0] != '-'
                ? r
                : throw new InvalidCastException($"'{v.AsString()}' is not a value of {typeof(TE).Name}."));

    /// <summary>A nested <see cref="RustegonDocumentAttribute"/> type ↔ object (codec from <see cref="RDocCodecRegistry"/>).</summary>
    /// <typeparam name="TD">The mapped type.</typeparam>
    /// <returns>The converter.</returns>
    public static RDocConverter<TD> Document<TD>() => new DocumentConverter<TD>();

    private static double ReadDouble(RDocValue v) => v.Type == RDocType.Int64 ? v.AsInt64() : v.AsDouble();

    private static RDocValue WriteArray<TE>(IEnumerable<TE> items, RDocConverter<TE> element)
    {
        var a = new RDocArray();
        foreach (TE e in items)
        {
            a.Add(element.Write(e));
        }

        return RDocValue.FromArray(a);
    }

    private static T CheckDimensions<T>(T vector, int dimensions)
        where T : notnull
    {
        int length = vector switch
        {
            float[] f => f.Length,
            ReadOnlyMemory<float> m => m.Length,
            _ => -1,
        };
        return dimensions == 0 || length == dimensions
            ? vector
            : throw new ArgumentException($"The vector has {length} dimensions, not {dimensions}.", nameof(vector));
    }

    private static RDocValue WriteGeoPoint(double[] lngLat)
    {
        if (lngLat.Length != 2 || lngLat[0] is not (>= -180 and <= 180) || lngLat[1] is not (>= -90 and <= 90))
        {
            throw new ArgumentException("A geo point is [longitude, latitude] with longitude in [-180, 180] and latitude in [-90, 90].", nameof(lngLat));
        }

        return RDocValue.FromDocument(new RDocument
        {
            { "type", "Point" },
            { "coordinates", new RDocArray { lngLat[0], lngLat[1] } },
        });
    }

    private static double[] ReadGeoPoint(RDocValue v)
    {
        RDocument d = v.AsDocument();
        if (!d.TryGetValue("type", out RDocValue type) || type.Type != RDocType.String || type.AsString() != "Point"
            || !d.TryGetValue("coordinates", out RDocValue c) || c.Type != RDocType.Array || c.AsArray().Count != 2)
        {
            throw new InvalidCastException("The value is not a GeoJSON point {\"type\": \"Point\", \"coordinates\": [lng, lat]}.");
        }

        return [ReadDouble(c.AsArray()[0]), ReadDouble(c.AsArray()[1])];
    }
}
