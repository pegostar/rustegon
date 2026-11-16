// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;

namespace Rustegon.Driver;

/// <summary>
/// A 12-byte object identifier (data-model.md §2, type 0x0A): 4 bytes Unix seconds (big endian, so
/// ids sort by creation second), 5 bytes random per process, 3 bytes counter (big endian) starting
/// at a random value.
/// </summary>
public readonly struct ObjectId : IEquatable<ObjectId>, IComparable<ObjectId>, IComparable
{
    /// <summary>Length of an object id in bytes.</summary>
    public const int Length = 12;

    private const int HexLength = 24;
    private const uint CounterMask = 0x00FF_FFFF;

    // The per-process part and the counter start are drawn once from the OS CSPRNG, as
    // data-model.md §2 requires ("5 B random per process").
    private static readonly byte[] ProcessRandom = RandomNumberGenerator.GetBytes(5);

    // Incremented with Interlocked: uniqueness only needs every increment to return a distinct
    // value; no other memory is published through it.
    private static uint s_counter = BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(4));

    // Big-endian bytes 0..7 and 8..11; two fields keep the struct small and comparisons cheap.
    private readonly ulong _high;
    private readonly uint _low;

    /// <summary>Creates an object id from its 12 bytes.</summary>
    /// <param name="bytes">Exactly <see cref="Length"/> bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is not 12 bytes long.</exception>
    public ObjectId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            throw new ArgumentException("An ObjectId has exactly 12 bytes.", nameof(bytes));
        }

        _high = BinaryPrimitives.ReadUInt64BigEndian(bytes);
        _low = BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]);
    }

    /// <summary>The all-zero object id.</summary>
    public static ObjectId Empty => default;

    /// <summary>Creation time encoded in the first four bytes.</summary>
    public DateTimeOffset CreationTime => DateTimeOffset.FromUnixTimeSeconds(Seconds);

    /// <summary>Creation time in Unix seconds (first four bytes).</summary>
    public uint Seconds => (uint)(_high >> 32);

    /// <summary>Generates a new, process-unique object id for the current time.</summary>
    /// <returns>The new id.</returns>
    public static ObjectId NewObjectId() => NewObjectId(DateTimeOffset.UtcNow);

    /// <summary>Generates a new object id for the given creation time.</summary>
    /// <param name="time">Creation time; seconds are truncated to 32 bits as the format defines.</param>
    /// <returns>The new id.</returns>
    public static ObjectId NewObjectId(DateTimeOffset time)
    {
        Span<byte> b = stackalloc byte[Length];
        BinaryPrimitives.WriteUInt32BigEndian(b, unchecked((uint)time.ToUnixTimeSeconds()));
        ProcessRandom.CopyTo(b[4..]);
        uint counter = Interlocked.Increment(ref s_counter) & CounterMask;
        b[9] = (byte)(counter >> 16);
        b[10] = (byte)(counter >> 8);
        b[11] = (byte)counter;
        return new ObjectId(b);
    }

    /// <summary>Parses 24 hexadecimal digits (either case).</summary>
    /// <param name="s">The text.</param>
    /// <returns>The id.</returns>
    /// <exception cref="FormatException"><paramref name="s"/> is not 24 hex digits.</exception>
    public static ObjectId Parse(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        return TryParse(s, out ObjectId id) ? id : throw new FormatException("An ObjectId is 24 hexadecimal digits.");
    }

    /// <summary>Tries to parse 24 hexadecimal digits (either case).</summary>
    /// <param name="s">The text.</param>
    /// <param name="result">The id, or <see cref="Empty"/> on failure.</param>
    /// <returns>Whether <paramref name="s"/> was valid.</returns>
    public static bool TryParse([NotNullWhen(true)] string? s, out ObjectId result)
    {
        result = default;
        if (s is null || s.Length != HexLength)
        {
            return false;
        }

        Span<byte> b = stackalloc byte[Length];
        if (Convert.FromHexString(s, b, out _, out int written) != System.Buffers.OperationStatus.Done || written != Length)
        {
            return false;
        }

        result = new ObjectId(b);
        return true;
    }

    /// <summary>Writes the 12 bytes into <paramref name="destination"/>.</summary>
    /// <param name="destination">At least 12 bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is too short.</exception>
    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < Length)
        {
            throw new ArgumentException("The destination needs 12 bytes.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt64BigEndian(destination, _high);
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], _low);
    }

    /// <summary>The 12 bytes as a new array.</summary>
    /// <returns>The bytes.</returns>
    public byte[] ToByteArray()
    {
        byte[] b = new byte[Length];
        WriteTo(b);
        return b;
    }

    /// <summary>24 lowercase hexadecimal digits.</summary>
    /// <returns>The text form.</returns>
    public override string ToString()
    {
        Span<byte> b = stackalloc byte[Length];
        WriteTo(b);
        return Convert.ToHexStringLower(b);
    }

    /// <inheritdoc/>
    public bool Equals(ObjectId other) => _high == other._high && _low == other._low;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is ObjectId other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(_high, _low);

    /// <summary>Byte-wise order (creation second first).</summary>
    /// <param name="other">The other id.</param>
    /// <returns>Negative, zero or positive.</returns>
    public int CompareTo(ObjectId other)
    {
        int c = _high.CompareTo(other._high);
        return c != 0 ? c : _low.CompareTo(other._low);
    }

    /// <inheritdoc/>
    public int CompareTo(object? obj) => obj switch
    {
        null => 1,
        ObjectId other => CompareTo(other),
        _ => throw new ArgumentException("Not an ObjectId.", nameof(obj)),
    };

    /// <summary>Equality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether both ids are equal.</returns>
    public static bool operator ==(ObjectId left, ObjectId right) => left.Equals(right);

    /// <summary>Inequality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether the ids differ.</returns>
    public static bool operator !=(ObjectId left, ObjectId right) => !left.Equals(right);

    /// <summary>Byte-wise order.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether <paramref name="left"/> sorts first.</returns>
    public static bool operator <(ObjectId left, ObjectId right) => left.CompareTo(right) < 0;

    /// <summary>Byte-wise order.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether <paramref name="left"/> sorts first or equal.</returns>
    public static bool operator <=(ObjectId left, ObjectId right) => left.CompareTo(right) <= 0;

    /// <summary>Byte-wise order.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether <paramref name="left"/> sorts last.</returns>
    public static bool operator >(ObjectId left, ObjectId right) => left.CompareTo(right) > 0;

    /// <summary>Byte-wise order.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>Whether <paramref name="left"/> sorts last or equal.</returns>
    public static bool operator >=(ObjectId left, ObjectId right) => left.CompareTo(right) >= 0;
}
