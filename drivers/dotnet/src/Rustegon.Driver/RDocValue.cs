// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers.Binary;
using Rustegon.Driver.Internal.Json;

namespace Rustegon.Driver;

/// <summary>
/// One value of the Rustegon type system (data-model.md §2): an immutable tagged union. Scalars are
/// stored inline; strings, binaries and vectors are immutable copies; documents and arrays are
/// referenced (they are mutable containers, so share them knowingly).
/// </summary>
/// <remarks>
/// Equality is representation equality, the identity the RDoc canonical form defines: the same
/// type and the same canonical encoding, recursively. So <c>1</c> (int64) differs from <c>1.0</c>
/// (float64), decimal cohort members differ, <c>-0.0</c> differs from <c>0.0</c>, and all NaNs
/// are equal. This is not the query-language comparison of §2.1.
/// </remarks>
public readonly struct RDocValue : IEquatable<RDocValue>
{
    /// <summary>The canonical float64 NaN (quiet, positive, no payload).</summary>
    internal const ulong CanonicalNaNBits = 0x7FF8_0000_0000_0000;

    // Payload layout by type (see the factories): object reference for strings, binaries, vectors,
    // documents and arrays; `_lo`/`_hi` for everything inline (int64 bits, float64 bits, decimal128
    // BID halves, timestamp wall/logical, objectId and UUID big-endian halves, binary subtype).
    private readonly object? _ref;
    private readonly ulong _lo;
    private readonly ulong _hi;

    private RDocValue(RDocType type, object? reference, ulong lo, ulong hi)
    {
        Type = type;
        _ref = reference;
        _lo = lo;
        _hi = hi;
    }

    /// <summary>The value's type; <see cref="RDocType.Missing"/> for <c>default</c>.</summary>
    public RDocType Type { get; }

    /// <summary>The absent value (<c>default</c>); never encodable.</summary>
    public static RDocValue Missing => default;

    /// <summary><c>null</c>.</summary>
    public static RDocValue Null => new(RDocType.Null, null, 0, 0);

    /// <summary>The smallest value of the total order.</summary>
    public static RDocValue MinKey => new(RDocType.MinKey, null, 0, 0);

    /// <summary>The largest value of the total order.</summary>
    public static RDocValue MaxKey => new(RDocType.MaxKey, null, 0, 0);

    /// <summary>Whether this is <see cref="RDocType.Missing"/>.</summary>
    public bool IsMissing => Type == RDocType.Missing;

    /// <summary>Whether this is <c>null</c>.</summary>
    public bool IsNull => Type == RDocType.Null;

    /// <summary>A boolean.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromBoolean(bool value) => new(RDocType.Bool, null, value ? 1UL : 0UL, 0);

    /// <summary>An int64.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromInt64(long value) => new(RDocType.Int64, null, unchecked((ulong)value), 0);

    /// <summary>A float64 (any NaN becomes the canonical NaN).</summary>
    /// <param name="value">The value.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromDouble(double value) =>
        new(RDocType.Float64, null, double.IsNaN(value) ? CanonicalNaNBits : BitConverter.DoubleToUInt64Bits(value), 0);

    /// <summary>A decimal128.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromDecimal128(Decimal128 value)
    {
        UInt128 bits = value.ToIeeeBits();
        return new(RDocType.Decimal128, null, (ulong)bits, (ulong)(bits >> 64));
    }

    /// <summary>A string (<see langword="null"/> gives <see cref="Null"/>).</summary>
    /// <param name="value">The value.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromString(string? value) => value is null ? Null : new(RDocType.String, value, 0, 0);

    /// <summary>A binary value with subtype 0 (generic); the bytes are copied.</summary>
    /// <param name="data">The bytes.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromBinary(ReadOnlySpan<byte> data) => FromBinary(BinarySubtype.Generic, data);

    /// <summary>A binary value; the bytes are copied.</summary>
    /// <param name="subtype">0 (generic), 4 (UUID, exactly 16 bytes) or 0x80–0xFF (user defined).</param>
    /// <param name="data">The bytes.</param>
    /// <returns>The RDoc value.</returns>
    /// <exception cref="ArgumentException">A reserved subtype, or subtype 4 not 16 bytes long.</exception>
    public static RDocValue FromBinary(byte subtype, ReadOnlySpan<byte> data)
    {
        string? error = BinarySubtype.Check(subtype, data.Length);
        if (error is not null)
        {
            throw new ArgumentException(error, nameof(subtype));
        }

        return new(RDocType.Binary, data.ToArray(), subtype, 0);
    }

    /// <summary>A datetime from milliseconds since the Unix epoch (UTC).</summary>
    /// <param name="unixMilliseconds">The instant.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromUnixTimeMilliseconds(long unixMilliseconds) =>
        new(RDocType.DateTime, null, unchecked((ulong)unixMilliseconds), 0);

    /// <summary>A datetime (sub-millisecond precision is truncated).</summary>
    /// <param name="value">The instant.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromDateTimeOffset(DateTimeOffset value) => FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());

    /// <summary>A datetime from a UTC <see cref="DateTime"/> (dotnet-driver.md §7: UTC enforced).</summary>
    /// <param name="value">A value of <see cref="DateTimeKind.Utc"/>.</param>
    /// <returns>The RDoc value.</returns>
    /// <exception cref="ArgumentException"><paramref name="value"/> is not UTC.</exception>
    public static RDocValue FromDateTime(DateTime value)
    {
        if (value.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException("Only DateTimeKind.Utc values are stored; convert with ToUniversalTime() first.", nameof(value));
        }

        return FromDateTimeOffset(new DateTimeOffset(value));
    }

    /// <summary>A hybrid logical clock timestamp.</summary>
    /// <param name="value">The timestamp.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromTimestamp(RDocTimestamp value) => new(RDocType.Timestamp, null, value.Wall, value.Logical);

    /// <summary>An object id.</summary>
    /// <param name="value">The id.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromObjectId(ObjectId value)
    {
        Span<byte> b = stackalloc byte[16];
        value.WriteTo(b);
        return new(RDocType.ObjectId, null, BinaryPrimitives.ReadUInt64BigEndian(b), BinaryPrimitives.ReadUInt64BigEndian(b[8..]));
    }

    /// <summary>A UUID; the 16 bytes are the RFC 9562 (big-endian) order of the text form.</summary>
    /// <param name="value">The UUID.</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromGuid(Guid value)
    {
        Span<byte> b = stackalloc byte[16];
        value.TryWriteBytes(b, bigEndian: true, out _);
        return FromUuidBytes(b);
    }

    /// <summary>A UUID from its 16 bytes.</summary>
    internal static RDocValue FromUuidBytes(ReadOnlySpan<byte> b) =>
        new(RDocType.Uuid, null, BinaryPrimitives.ReadUInt64BigEndian(b), BinaryPrimitives.ReadUInt64BigEndian(b[8..]));

    /// <summary>A vector of finite floats; the elements are copied.</summary>
    /// <param name="elements">The elements.</param>
    /// <returns>The RDoc value.</returns>
    /// <exception cref="ArgumentException">An element is not finite (RGN-1040).</exception>
    public static RDocValue FromVector(ReadOnlySpan<float> elements)
    {
        foreach (float x in elements)
        {
            if (!float.IsFinite(x))
            {
                throw new ArgumentException("Vector elements must be finite.", nameof(elements));
            }
        }

        return new(RDocType.VectorF32, elements.ToArray(), 0, 0);
    }

    /// <summary>A document value (<see langword="null"/> gives <see cref="Null"/>).</summary>
    /// <param name="value">The document (referenced, not copied).</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromDocument(RDocument? value) => value is null ? Null : new(RDocType.Object, value, 0, 0);

    /// <summary>An array value (<see langword="null"/> gives <see cref="Null"/>).</summary>
    /// <param name="value">The array (referenced, not copied).</param>
    /// <returns>The RDoc value.</returns>
    public static RDocValue FromArray(RDocArray? value) => value is null ? Null : new(RDocType.Array, value, 0, 0);

    /// <summary>A counter projection. Only the server produces these; they are never accepted as input.</summary>
    internal static RDocValue FromCounter(long value) => new(RDocType.Counter, null, unchecked((ulong)value), 0);

    /// <summary>Wraps an already copied binary payload (decoder use; the array must not be shared).</summary>
    internal static RDocValue FromOwnedBinary(byte subtype, byte[] data) => new(RDocType.Binary, data, subtype, 0);

    /// <summary>Wraps an already copied vector (decoder use; the array must not be shared).</summary>
    internal static RDocValue FromOwnedVector(float[] data) => new(RDocType.VectorF32, data, 0, 0);

    /// <summary>The boolean.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not a bool.</exception>
    public bool AsBoolean() => Expect(RDocType.Bool)._lo != 0;

    /// <summary>The int64.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not an int64.</exception>
    public long AsInt64() => unchecked((long)Expect(RDocType.Int64)._lo);

    /// <summary>The float64.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not a float64.</exception>
    public double AsDouble() => BitConverter.UInt64BitsToDouble(Expect(RDocType.Float64)._lo);

    /// <summary>The decimal128.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not a decimal128.</exception>
    public Decimal128 AsDecimal128()
    {
        RDocValue v = Expect(RDocType.Decimal128);
        return Decimal128.FromIeeeBits(((UInt128)v._hi << 64) | v._lo);
    }

    /// <summary>The string.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not a string.</exception>
    public string AsString() => (string)Expect(RDocType.String)._ref!;

    /// <summary>The bytes of a binary value.</summary>
    /// <returns>A read-only view of the (immutable) bytes.</returns>
    /// <exception cref="InvalidCastException">Not a binary.</exception>
    public ReadOnlyMemory<byte> AsBinary() => (byte[])Expect(RDocType.Binary)._ref!;

    /// <summary>The subtype of a binary value.</summary>
    /// <exception cref="InvalidCastException">Not a binary.</exception>
    public byte BinarySubtypeValue => (byte)Expect(RDocType.Binary)._lo;

    /// <summary>A datetime as milliseconds since the Unix epoch.</summary>
    /// <returns>The instant.</returns>
    /// <exception cref="InvalidCastException">Not a datetime.</exception>
    public long AsUnixTimeMilliseconds() => unchecked((long)Expect(RDocType.DateTime)._lo);

    /// <summary>A datetime as <see cref="DateTimeOffset"/> (UTC).</summary>
    /// <returns>The instant.</returns>
    /// <exception cref="InvalidCastException">Not a datetime.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Outside the years 0001–9999 that <see cref="DateTimeOffset"/> covers.</exception>
    public DateTimeOffset AsDateTimeOffset() => DateTimeOffset.FromUnixTimeMilliseconds(AsUnixTimeMilliseconds());

    /// <summary>The timestamp.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not a timestamp.</exception>
    public RDocTimestamp AsTimestamp()
    {
        RDocValue v = Expect(RDocType.Timestamp);
        return new RDocTimestamp(v._lo, (uint)v._hi);
    }

    /// <summary>The object id.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not an objectId.</exception>
    public ObjectId AsObjectId()
    {
        RDocValue v = Expect(RDocType.ObjectId);
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(b, v._lo);
        BinaryPrimitives.WriteUInt64BigEndian(b[8..], v._hi);
        return new ObjectId(b[..ObjectId.Length]);
    }

    /// <summary>The UUID.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidCastException">Not a uuid.</exception>
    public Guid AsGuid()
    {
        Span<byte> b = stackalloc byte[16];
        Expect(RDocType.Uuid).WriteUuidBytes(b);
        return new Guid(b, bigEndian: true);
    }

    /// <summary>The vector elements.</summary>
    /// <returns>A read-only view of the (immutable) elements.</returns>
    /// <exception cref="InvalidCastException">Not a vector_f32.</exception>
    public ReadOnlyMemory<float> AsVector() => (float[])Expect(RDocType.VectorF32)._ref!;

    /// <summary>The document.</summary>
    /// <returns>The (shared, mutable) document.</returns>
    /// <exception cref="InvalidCastException">Not an object.</exception>
    public RDocument AsDocument() => (RDocument)Expect(RDocType.Object)._ref!;

    /// <summary>The array.</summary>
    /// <returns>The (shared, mutable) array.</returns>
    /// <exception cref="InvalidCastException">Not an array.</exception>
    public RDocArray AsArray() => (RDocArray)Expect(RDocType.Array)._ref!;

    /// <summary>The value of a counter projection.</summary>
    /// <returns>The counter value.</returns>
    /// <exception cref="InvalidCastException">Not a counter.</exception>
    public long AsCounter() => unchecked((long)Expect(RDocType.Counter)._lo);

    /// <summary>Raw inline payload (codec use).</summary>
    internal ulong Low => _lo;

    /// <summary>Raw inline payload (codec use).</summary>
    internal ulong High => _hi;

    /// <summary>Raw reference payload (codec use).</summary>
    internal object? Reference => _ref;

    /// <summary>Writes the 16 bytes of a UUID value.</summary>
    internal void WriteUuidBytes(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination, _lo);
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], _hi);
    }

    /// <summary>Writes the 12 bytes of an objectId value.</summary>
    internal void WriteObjectIdBytes(Span<byte> destination)
    {
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(b, _lo);
        BinaryPrimitives.WriteUInt64BigEndian(b[8..], _hi);
        b[..ObjectId.Length].CopyTo(destination);
    }

    private RDocValue Expect(RDocType type) =>
        Type == type ? this : throw new InvalidCastException($"The value is {Type}, not {type}.");

    /// <summary>Parses one extended-JSON value (data-model.md §2).</summary>
    /// <param name="json">The JSON text.</param>
    /// <returns>The value.</returns>
    /// <exception cref="RDocException">Invalid JSON or an invalid value (RGN-1001/1003/1004/1040).</exception>
    public static RDocValue FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return RDocJsonReader.ParseValue(json);
    }

    /// <summary>Serializes the value as JSON.</summary>
    /// <param name="mode">Canonical (default) or extended output.</param>
    /// <returns>The JSON text.</returns>
    public string ToJson(RDocJsonMode mode = RDocJsonMode.Canonical) => RDocJsonWriter.WriteValue(this, mode);

    /// <summary>The canonical JSON form (<c>""</c> for <see cref="Missing"/>).</summary>
    /// <returns>The text.</returns>
    public override string ToString() => IsMissing ? string.Empty : ToJson();

    /// <inheritdoc/>
    public bool Equals(RDocValue other)
    {
        if (Type != other.Type || _lo != other._lo || _hi != other._hi)
        {
            return false;
        }

        return Type switch
        {
            RDocType.String => string.Equals((string)_ref!, (string)other._ref!, StringComparison.Ordinal),
            RDocType.Binary => ((byte[])_ref!).AsSpan().SequenceEqual((byte[])other._ref!),
            RDocType.VectorF32 => VectorBitsEqual((float[])_ref!, (float[])other._ref!),
            RDocType.Object => ((RDocument)_ref!).Equals((RDocument)other._ref!),
            RDocType.Array => ((RDocArray)_ref!).Equals((RDocArray)other._ref!),
            _ => true,
        };
    }

    private static bool VectorBitsEqual(float[] a, float[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (int i = 0; i < a.Length; i++)
        {
            if (BitConverter.SingleToUInt32Bits(a[i]) != BitConverter.SingleToUInt32Bits(b[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is RDocValue other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        int inner = Type switch
        {
            RDocType.String => StringComparer.Ordinal.GetHashCode((string)_ref!),
            RDocType.Binary => ((byte[])_ref!).Length,
            RDocType.VectorF32 => ((float[])_ref!).Length,
            RDocType.Object => ((RDocument)_ref!).Count,
            RDocType.Array => ((RDocArray)_ref!).Count,
            _ => 0,
        };
        return HashCode.Combine(Type, _lo, _hi, inner);
    }

    /// <summary>Representation equality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether both values are equal.</returns>
    public static bool operator ==(RDocValue left, RDocValue right) => left.Equals(right);

    /// <summary>Representation inequality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether the values differ.</returns>
    public static bool operator !=(RDocValue left, RDocValue right) => !left.Equals(right);

    /// <summary>A boolean.</summary>
    /// <param name="value">The value.</param>
    public static implicit operator RDocValue(bool value) => FromBoolean(value);

    /// <summary>An int64.</summary>
    /// <param name="value">The value.</param>
    public static implicit operator RDocValue(int value) => FromInt64(value);

    /// <summary>An int64.</summary>
    /// <param name="value">The value.</param>
    public static implicit operator RDocValue(long value) => FromInt64(value);

    /// <summary>A float64.</summary>
    /// <param name="value">The value.</param>
    public static implicit operator RDocValue(double value) => FromDouble(value);

    /// <summary>A decimal128 (exact).</summary>
    /// <param name="value">The value.</param>
    public static implicit operator RDocValue(decimal value) => FromDecimal128(Decimal128.FromDecimal(value));

    /// <summary>A decimal128.</summary>
    /// <param name="value">The value.</param>
    public static implicit operator RDocValue(Decimal128 value) => FromDecimal128(value);

    /// <summary>A string (<see langword="null"/> gives <see cref="Null"/>).</summary>
    /// <param name="value">The value.</param>
    public static implicit operator RDocValue(string? value) => FromString(value);

    /// <summary>A generic binary (<see langword="null"/> gives <see cref="Null"/>); the bytes are copied.</summary>
    /// <param name="value">The bytes.</param>
    public static implicit operator RDocValue(byte[]? value) => value is null ? Null : FromBinary(value);

    /// <summary>A datetime.</summary>
    /// <param name="value">The instant.</param>
    public static implicit operator RDocValue(DateTimeOffset value) => FromDateTimeOffset(value);

    /// <summary>A timestamp.</summary>
    /// <param name="value">The timestamp.</param>
    public static implicit operator RDocValue(RDocTimestamp value) => FromTimestamp(value);

    /// <summary>An object id.</summary>
    /// <param name="value">The id.</param>
    public static implicit operator RDocValue(ObjectId value) => FromObjectId(value);

    /// <summary>A UUID.</summary>
    /// <param name="value">The UUID.</param>
    public static implicit operator RDocValue(Guid value) => FromGuid(value);

    /// <summary>A document (<see langword="null"/> gives <see cref="Null"/>).</summary>
    /// <param name="value">The document.</param>
    public static implicit operator RDocValue(RDocument? value) => FromDocument(value);

    /// <summary>An array (<see langword="null"/> gives <see cref="Null"/>).</summary>
    /// <param name="value">The array.</param>
    public static implicit operator RDocValue(RDocArray? value) => FromArray(value);
}
