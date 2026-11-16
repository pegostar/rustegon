// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Rustegon.Driver.Internal.Codec;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver;

/// <summary>
/// RDoc v1 encoder (data-model.md §4). Always writes the canonical form (flag bit 0 set), byte for
/// byte what the server's <c>rustegon_doc::rdoc::encode</c> writes.
/// </summary>
/// <remarks>
/// Two passes, as the Rust encoder: <c>Measure</c> computes every container's body length (kept in
/// pre-order in a pooled table) and enforces the depth and size limits before anything is
/// written, so an oversized document fails without a 16 MiB buffer; the write pass then fills a
/// span of exactly the measured length, back-patching each object index whose slots it reserved
/// before the fields. Writing into <see cref="IBufferWriter{T}"/> therefore needs no extra copy.
/// </remarks>
public static class RDocWriter
{
    /// <summary>Exact encoded size of a document (header included), without encoding it.</summary>
    /// <param name="document">The document.</param>
    /// <returns>Number of bytes.</returns>
    /// <exception cref="RDocException">As <see cref="ToBytes"/>.</exception>
    public static int GetEncodedLength(RDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var sizes = new SizeTable();
        try
        {
            return TotalLength(MeasureObject(document, 1, ref sizes));
        }
        finally
        {
            sizes.Dispose();
        }
    }

    /// <summary>Encodes a document as canonical RDoc v1.</summary>
    /// <param name="document">The document.</param>
    /// <returns>The bytes.</returns>
    /// <exception cref="RDocException">
    /// RGN-1002 above 16 MiB, RGN-1003 beyond 100 levels, RGN-1004 for an invalid field name,
    /// RGN-1001 for a missing value or a string that is not valid UTF-16.
    /// </exception>
    public static byte[] ToBytes(RDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var sizes = new SizeTable();
        try
        {
            int total = TotalLength(MeasureObject(document, 1, ref sizes));
            byte[] output = new byte[total];
            WriteDocument(document, output, ref sizes);
            return output;
        }
        finally
        {
            sizes.Dispose();
        }
    }

    /// <summary>Encodes a document as canonical RDoc v1 into a buffer writer.</summary>
    /// <param name="document">The document.</param>
    /// <param name="output">Destination; exactly the returned number of bytes is advanced.</param>
    /// <returns>Number of bytes written.</returns>
    /// <exception cref="RDocException">As <see cref="ToBytes"/>.</exception>
    public static int Write(RDocument document, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);
        var sizes = new SizeTable();
        try
        {
            int total = TotalLength(MeasureObject(document, 1, ref sizes));
            Span<byte> span = output.GetSpan(total)[..total];
            WriteDocument(document, span, ref sizes);
            output.Advance(total);
            return total;
        }
        finally
        {
            sizes.Dispose();
        }
    }

    /// <summary>
    /// Encodes one value in the RDoc value encoding: tag and payload exactly as inside a document,
    /// no header (<c>Value.rdoc_value</c> of protocol.md §3: ids, parameters, option values).
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The bytes.</returns>
    /// <exception cref="RDocException">As <see cref="ToBytes"/>.</exception>
    public static byte[] ValueToBytes(RDocValue value)
    {
        var sizes = new SizeTable();
        try
        {
            long size = MeasureValue(value, 0, ref sizes);
            byte[] output = new byte[size];
            var w = new SpanWriter(output, sizes.Items);
            w.Value(value);
            return output;
        }
        finally
        {
            sizes.Dispose();
        }
    }

    /// <summary>Encodes one value (see <see cref="ValueToBytes"/>) into a buffer writer.</summary>
    /// <param name="value">The value.</param>
    /// <param name="output">Destination.</param>
    /// <returns>Number of bytes written.</returns>
    /// <exception cref="RDocException">As <see cref="ToBytes"/>.</exception>
    public static int WriteValue(RDocValue value, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var sizes = new SizeTable();
        try
        {
            int size = (int)MeasureValue(value, 0, ref sizes);
            Span<byte> span = output.GetSpan(size)[..size];
            var w = new SpanWriter(span, sizes.Items);
            w.Value(value);
            output.Advance(size);
            return size;
        }
        finally
        {
            sizes.Dispose();
        }
    }

    private static void WriteDocument(RDocument document, Span<byte> output, ref SizeTable sizes)
    {
        output[0] = RDocFormat.Magic;
        output[1] = RDocFormat.Version;
        output[2] = RDocFormat.FlagCanonical;
        BinaryPrimitives.WriteUInt32LittleEndian(output[3..], (uint)output.Length);
        var w = new SpanWriter(output, sizes.Items) { Position = RDocFormat.HeaderLength };
        w.Object(document);
        if (w.Position != output.Length)
        {
            throw new InvalidOperationException("RDoc measure and write disagree (driver bug).");
        }
    }

    private static int TotalLength(long root)
    {
        long total = RDocFormat.HeaderLength + root;
        return total > RDocFormat.MaxDocumentSize ? throw TooLarge(total) : (int)total;
    }

    private static RDocException TooLarge(long size) =>
        new(ErrorCodes.DocumentTooLarge, $"document of {size} bytes exceeds the {RDocFormat.MaxDocumentSize}-byte limit");

    internal static int Utf8Length(string s, bool fieldName)
    {
        try
        {
            return RDocFormat.StrictUtf8.GetByteCount(s);
        }
        catch (EncoderFallbackException)
        {
            throw new RDocException(
                fieldName ? ErrorCodes.InvalidFieldName : RDocFormat.Malformed,
                "string is not valid UTF-16 (lone surrogate)");
        }
    }

    private static long LengthPrefixed(long n) => RDocFormat.VarintLength((ulong)n) + n;

    private static void CheckDepth(int depth)
    {
        if (depth > RDocFormat.MaxDepth)
        {
            throw new RDocException(ErrorCodes.NestingTooDeep, $"nesting deeper than {RDocFormat.MaxDepth} levels");
        }
    }

    /// <summary>Encoded size of one value; pushes container body lengths in pre-order.</summary>
    private static long MeasureValue(RDocValue v, int depth, ref SizeTable sizes)
    {
        long size = v.Type switch
        {
            RDocType.Null or RDocType.MinKey or RDocType.MaxKey => 1,
            RDocType.Bool => 2,
            RDocType.Int64 or RDocType.DateTime or RDocType.Counter => 1 + RDocFormat.VarintLength(RDocFormat.ZigZag((long)v.Low)),
            RDocType.Float64 => 9,
            RDocType.Decimal128 or RDocType.Uuid => 17,
            RDocType.Timestamp or RDocType.ObjectId => 13,
            RDocType.String => 1 + LengthPrefixed(Utf8Length((string)v.Reference!, fieldName: false)),
            RDocType.Binary => 2 + LengthPrefixed(((byte[])v.Reference!).Length),
            RDocType.VectorF32 => 1 + RDocFormat.VarintLength((ulong)((float[])v.Reference!).Length) + (4L * ((float[])v.Reference!).Length),
            RDocType.Array => MeasureArray((RDocArray)v.Reference!, depth + 1, ref sizes),
            RDocType.Object => MeasureObject((RDocument)v.Reference!, depth + 1, ref sizes),
            _ => throw new RDocException(RDocFormat.Malformed, "a missing value cannot be encoded"),
        };
        return size > RDocFormat.MaxDocumentSize ? throw TooLarge(size) : size;
    }

    private static long ContainerSize(int n, int entryLength, long body) =>
        1 + RDocFormat.VarintLength((ulong)n) + RDocFormat.VarintLength((ulong)body) + ((long)entryLength * n) + body;

    private static long MeasureObject(RDocument d, int depth, ref SizeTable sizes)
    {
        CheckDepth(depth);
        int slot = sizes.Push();
        long body = 0;
        foreach (KeyValuePair<string, RDocValue> f in d)
        {
            int nameLength = Utf8Length(f.Key, fieldName: true);
            string? error = RDocFormat.FieldNameError(f.Key, nameLength);
            if (error is not null)
            {
                throw new RDocException(ErrorCodes.InvalidFieldName, error);
            }

            body += LengthPrefixed(nameLength) + MeasureValue(f.Value, depth, ref sizes);
            if (body > RDocFormat.MaxDocumentSize)
            {
                throw TooLarge(body);
            }
        }

        sizes.Set(slot, body);
        return ContainerSize(d.Count, RDocFormat.IndexEntryLength, body);
    }

    private static long MeasureArray(RDocArray items, int depth, ref SizeTable sizes)
    {
        CheckDepth(depth);
        int slot = sizes.Push();
        long body = 0;
        foreach (RDocValue item in items)
        {
            body += MeasureValue(item, depth, ref sizes);
            if (body > RDocFormat.MaxDocumentSize)
            {
                throw TooLarge(body);
            }
        }

        sizes.Set(slot, body);
        return ContainerSize(items.Count, RDocFormat.ArrayOffsetLength, body);
    }

    /// <summary>Container body lengths in pre-order, in a pooled array.</summary>
    private struct SizeTable : IDisposable
    {
        private const int InitialCapacity = 16;
        private int _count;

        public long[]? Items { get; private set; }

        public int Push()
        {
            Items ??= ArrayPool<long>.Shared.Rent(InitialCapacity);
            if (_count == Items.Length)
            {
                long[] bigger = ArrayPool<long>.Shared.Rent(Items.Length * 2);
                Items.AsSpan(0, _count).CopyTo(bigger);
                ArrayPool<long>.Shared.Return(Items);
                Items = bigger;
            }

            Items[_count] = 0;
            return _count++;
        }

        public readonly void Set(int slot, long value) => Items![slot] = value;

        public void Dispose()
        {
            if (Items is not null)
            {
                ArrayPool<long>.Shared.Return(Items);
                Items = null;
            }
        }
    }

    /// <summary>One object index entry before sorting.</summary>
    private readonly record struct IndexEntry(ushort Hash, string Name, uint Offset);

    /// <summary>
    /// Orders index entries by (hash, name bytes). UTF-8 byte order equals code point order, which
    /// differs from UTF-16 code unit order only between surrogates and U+E000..U+FFFF; the
    /// fix-up below maps code units to code point order without encoding the names again.
    /// </summary>
    private sealed class IndexEntryComparer : IComparer<IndexEntry>
    {
        internal static readonly IndexEntryComparer Instance = new();

        public int Compare(IndexEntry x, IndexEntry y)
        {
            int c = x.Hash.CompareTo(y.Hash);
            return c != 0 ? c : CompareCodePoints(x.Name, y.Name);
        }

        internal static int CompareCodePoints(string a, string b)
        {
            int n = Math.Min(a.Length, b.Length);
            for (int i = 0; i < n; i++)
            {
                if (a[i] != b[i])
                {
                    return Fix(a[i]).CompareTo(Fix(b[i]));
                }
            }

            return a.Length.CompareTo(b.Length);
        }

        private static int Fix(char c) => c switch
        {
            >= '\uD800' and <= '\uDFFF' => c + 0x2000,
            >= '' => c - 0x800,
            _ => c,
        };
    }

    /// <summary>Sequential writer over the exact-size output span.</summary>
    private ref struct SpanWriter
    {
        private readonly Span<byte> _out;
        private readonly long[]? _sizes;
        private int _next;

        public SpanWriter(Span<byte> output, long[]? sizes)
        {
            _out = output;
            _sizes = sizes;
        }

        public int Position { get; set; }

        private long NextSize() => _sizes![_next++];

        private void Varint(ulong v)
        {
            while (v >= 0x80)
            {
                _out[Position++] = (byte)(v | 0x80);
                v >>= 7;
            }

            _out[Position++] = (byte)v;
        }

        private void Utf8(string s, int byteLength)
        {
            RDocFormat.StrictUtf8.GetBytes(s, _out.Slice(Position, byteLength));
            Position += byteLength;
        }

        public void Value(RDocValue v)
        {
            switch (v.Type)
            {
                case RDocType.Array:
                    Array((RDocArray)v.Reference!);
                    return;
                case RDocType.Object:
                    Object((RDocument)v.Reference!);
                    return;
            }

            _out[Position++] = (byte)v.Type;
            switch (v.Type)
            {
                case RDocType.Null or RDocType.MinKey or RDocType.MaxKey:
                    break;
                case RDocType.Bool:
                    _out[Position++] = (byte)v.Low;
                    break;
                case RDocType.Int64 or RDocType.DateTime or RDocType.Counter:
                    Varint(RDocFormat.ZigZag((long)v.Low));
                    break;
                case RDocType.Float64:
                    // FromDouble already canonicalized NaN to 0x7FF8000000000000.
                    BinaryPrimitives.WriteUInt64LittleEndian(_out[Position..], v.Low);
                    Position += 8;
                    break;
                case RDocType.Decimal128:
                    BinaryPrimitives.WriteUInt64LittleEndian(_out[Position..], v.Low);
                    BinaryPrimitives.WriteUInt64LittleEndian(_out[(Position + 8)..], v.High);
                    Position += 16;
                    break;
                case RDocType.String:
                    string s = (string)v.Reference!;
                    int len = RDocFormat.StrictUtf8.GetByteCount(s);
                    Varint((ulong)len);
                    Utf8(s, len);
                    break;
                case RDocType.Binary:
                    byte[] data = (byte[])v.Reference!;
                    _out[Position++] = (byte)v.Low;
                    Varint((ulong)data.Length);
                    data.CopyTo(_out[Position..]);
                    Position += data.Length;
                    break;
                case RDocType.Timestamp:
                    BinaryPrimitives.WriteUInt64LittleEndian(_out[Position..], v.Low);
                    BinaryPrimitives.WriteUInt32LittleEndian(_out[(Position + 8)..], (uint)v.High);
                    Position += 12;
                    break;
                case RDocType.ObjectId:
                    v.WriteObjectIdBytes(_out[Position..]);
                    Position += ObjectId.Length;
                    break;
                case RDocType.Uuid:
                    v.WriteUuidBytes(_out[Position..]);
                    Position += 16;
                    break;
                case RDocType.VectorF32:
                    float[] xs = (float[])v.Reference!;
                    Varint((ulong)xs.Length);
                    foreach (float x in xs)
                    {
                        BinaryPrimitives.WriteSingleLittleEndian(_out[Position..], x);
                        Position += 4;
                    }

                    break;
            }
        }

        public void Object(RDocument d)
        {
            _out[Position++] = (byte)RDocType.Object;
            int n = d.Count;
            Varint((ulong)n);
            long body = NextSize();
            Varint((ulong)body);
            int indexAt = Position;
            Position += RDocFormat.IndexEntryLength * n;
            int fieldsAt = Position;
            IndexEntry[] entries = ArrayPool<IndexEntry>.Shared.Rent(n);
            try
            {
                int i = 0;
                foreach (KeyValuePair<string, RDocValue> f in d)
                {
                    uint offset = (uint)(Position - fieldsAt);
                    int nameLength = RDocFormat.StrictUtf8.GetByteCount(f.Key);
                    Varint((ulong)nameLength);
                    int nameAt = Position;
                    Utf8(f.Key, nameLength);
                    entries[i++] = new IndexEntry(RDocFormat.NameHash16(_out.Slice(nameAt, nameLength)), f.Key, offset);
                    Value(f.Value);
                }

                // Index order (hash, name bytes) makes lookups a binary search and the bytes canonical.
                System.Array.Sort(entries, 0, n, IndexEntryComparer.Instance);
                for (int j = 0; j < n; j++)
                {
                    Span<byte> slot = _out.Slice(indexAt + (j * RDocFormat.IndexEntryLength), RDocFormat.IndexEntryLength);
                    BinaryPrimitives.WriteUInt16LittleEndian(slot, entries[j].Hash);
                    BinaryPrimitives.WriteUInt32LittleEndian(slot[2..], entries[j].Offset);
                }
            }
            finally
            {
                ArrayPool<IndexEntry>.Shared.Return(entries, clearArray: true);
            }

            if (Position - fieldsAt != body)
            {
                throw new InvalidOperationException("RDoc object body length mismatch (driver bug).");
            }
        }

        public void Array(RDocArray items)
        {
            _out[Position++] = (byte)RDocType.Array;
            Varint((ulong)items.Count);
            long body = NextSize();
            Varint((ulong)body);
            int tableAt = Position;
            Position += RDocFormat.ArrayOffsetLength * items.Count;
            int elementsAt = Position;
            for (int i = 0; i < items.Count; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(_out[(tableAt + (i * RDocFormat.ArrayOffsetLength))..], (uint)(Position - elementsAt));
                Value(items[i]);
            }

            if (Position - elementsAt != body)
            {
                throw new InvalidOperationException("RDoc array body length mismatch (driver bug).");
            }
        }
    }
}
