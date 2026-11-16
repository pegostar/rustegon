// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Rustegon.Driver.Internal.Codec;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver;

/// <summary>
/// RDoc v1 decoder with full validation (data-model.md §4), mirroring
/// <c>crates/rustegon-doc/src/rdoc/decode.rs</c>.
/// </summary>
/// <remarks>
/// Every input is untrusted: reads are bounds-checked against the enclosing value, counts are
/// bounded by the bytes that could hold them before anything is allocated, recursion is bounded by
/// the depth limit, and every inconsistency (truncation, unknown tags, invalid UTF-8, index or
/// offset mismatches, trailing bytes) is an <see cref="RDocException"/>; nothing else escapes.
/// With the canonical flag set, non-canonical encodings (non-minimal varints, NaN payloads,
/// non-canonical decimal128) are rejected; without it they are accepted and normalized.
/// </remarks>
public static class RDocReader
{
    /// <summary>Decodes and validates an RDoc v1 document.</summary>
    /// <param name="rdoc">The whole document (its length must equal <c>total_len</c>).</param>
    /// <returns>The document.</returns>
    /// <exception cref="RDocException">RGN-1001 malformed, RGN-1002 too large, RGN-1003 too deep, RGN-1004 invalid or duplicate names, RGN-1040 non-finite vector.</exception>
    public static RDocument ReadDocument(ReadOnlySpan<byte> rdoc)
    {
        bool strict = CheckHeader(rdoc);
        var d = new Decoder(rdoc, strict);
        if (rdoc[RDocFormat.HeaderLength] != (byte)RDocType.Object)
        {
            throw Malformed(RDocFormat.HeaderLength, "root is not an object");
        }

        RDocument doc = d.Object(RDocFormat.HeaderLength + 1, rdoc.Length, 1, out int next);
        return next == rdoc.Length ? doc : throw Malformed(next, "trailing bytes after the root object");
    }

    /// <summary>
    /// Decodes one value in the RDoc value encoding (tag + payload, no header; protocol.md §3
    /// <c>Value.rdoc_value</c>). Non-canonical variants are accepted and normalized.
    /// </summary>
    /// <param name="rdocValue">Exactly one encoded value.</param>
    /// <returns>The value.</returns>
    /// <exception cref="RDocException">As <see cref="ReadDocument"/>; also trailing bytes.</exception>
    public static RDocValue ReadValue(ReadOnlySpan<byte> rdocValue)
    {
        var d = new Decoder(rdocValue, strict: false);
        RDocValue v = d.Value(0, rdocValue.Length, 0, out int next);
        return next == rdocValue.Length ? v : throw Malformed(next, "trailing bytes after value");
    }

    /// <summary>Whether the bytes carry the canonical flag (after header validation).</summary>
    /// <param name="rdoc">A whole document.</param>
    /// <returns>The flag.</returns>
    /// <exception cref="RDocException">An invalid header.</exception>
    public static bool IsCanonicalFlagSet(ReadOnlySpan<byte> rdoc) => CheckHeader(rdoc);

    private static bool CheckHeader(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < RDocFormat.HeaderLength + 1)
        {
            throw Malformed(bytes.Length, "truncated header");
        }

        if (bytes[0] != RDocFormat.Magic)
        {
            throw Malformed(0, "bad magic");
        }

        if (bytes[1] != RDocFormat.Version)
        {
            throw Malformed(1, "unsupported RDoc version");
        }

        byte flags = bytes[2];
        if ((flags & ~RDocFormat.FlagCanonical) != 0)
        {
            throw Malformed(2, "unknown flag bits");
        }

        uint total = BinaryPrimitives.ReadUInt32LittleEndian(bytes[3..]);
        if (total > RDocFormat.MaxDocumentSize)
        {
            throw new RDocException(ErrorCodes.DocumentTooLarge, $"document of {total} bytes exceeds the {RDocFormat.MaxDocumentSize}-byte limit");
        }

        if (total != bytes.Length)
        {
            throw Malformed(3, "total_len does not match the input length");
        }

        return (flags & RDocFormat.FlagCanonical) != 0;
    }

    private static RDocException Malformed(long position, string reason) => new(RDocFormat.Malformed, reason, position);

    /// <summary>Positions of a container's parts (after its tag).</summary>
    private readonly record struct ContainerHeader(int Count, int TableAt, int BodyAt, int BodyEnd);

    /// <summary>A decoded field before the index check.</summary>
    private readonly record struct Field(string Name, RDocValue Value, int Start, int NameAt, int NameLength);

    private readonly ref struct Decoder
    {
        private readonly ReadOnlySpan<byte> _buf;
        private readonly bool _strict;

        public Decoder(ReadOnlySpan<byte> buf, bool strict)
        {
            _buf = buf;
            _strict = strict;
        }

        private static int CheckedEnd(int pos, long length, int end)
        {
            long stop = pos + length;
            return length < 0 || stop > end ? throw Malformed(pos, "length exceeds the enclosing value") : (int)stop;
        }

        /// <summary>Unsigned LEB128 at <paramref name="pos"/> bounded by <paramref name="end"/>.</summary>
        private ulong Varint(int pos, int end, out int next)
        {
            ulong v = 0;
            for (int i = 0; i < RDocFormat.MaxVarintLength; i++)
            {
                int p = pos + i;
                if (p >= end)
                {
                    throw Malformed(p, "truncated varint");
                }

                byte b = _buf[p];
                if (i == RDocFormat.MaxVarintLength - 1 && b > 1)
                {
                    throw Malformed(p, "varint overflows u64");
                }

                v |= (ulong)(b & 0x7F) << (7 * i);
                if ((b & 0x80) == 0)
                {
                    if (_strict && i > 0 && b == 0)
                    {
                        throw Malformed(p, "non-minimal varint");
                    }

                    next = p + 1;
                    return v;
                }
            }

            throw Malformed(pos, "varint too long");
        }

        private int Length(int pos, int end, out int next)
        {
            ulong v = Varint(pos, end, out next);
            // Any length beyond the input cannot be satisfied; reporting it here keeps the
            // arithmetic below in int range.
            return v > (ulong)_buf.Length ? throw Malformed(pos, "length exceeds the enclosing value") : (int)v;
        }

        private ContainerHeader Header(int pos, int end, int entryLength)
        {
            int n = Length(pos, end, out int p);
            int bodyLength = Length(p, end, out int tableAt);
            int bodyAt = CheckedEnd(tableAt, (long)n * entryLength, end);
            int bodyEnd = CheckedEnd(bodyAt, bodyLength, end);
            return new ContainerHeader(n, tableAt, bodyAt, bodyEnd);
        }

        private string Utf8(int pos, int end, out int next, out int nameAt, out int length)
        {
            length = Length(pos, end, out nameAt);
            next = CheckedEnd(nameAt, length, end);
            try
            {
                return RDocFormat.StrictUtf8.GetString(_buf.Slice(nameAt, length));
            }
            catch (DecoderFallbackException)
            {
                throw Malformed(nameAt, "invalid UTF-8");
            }
        }

        private static void CheckDepth(int depth)
        {
            if (depth > RDocFormat.MaxDepth)
            {
                throw new RDocException(ErrorCodes.NestingTooDeep, $"nesting deeper than {RDocFormat.MaxDepth} levels");
            }
        }

        /// <summary>Decodes the value whose tag is at <paramref name="pos"/>; containers get <paramref name="depth"/> + 1.</summary>
        public RDocValue Value(int pos, int end, int depth, out int next)
        {
            if (pos >= end)
            {
                throw Malformed(pos, "missing value");
            }

            byte tag = _buf[pos];
            int at = pos + 1;
            switch ((RDocType)tag)
            {
                case RDocType.Null:
                    next = at;
                    return RDocValue.Null;
                case RDocType.MinKey:
                    next = at;
                    return RDocValue.MinKey;
                case RDocType.MaxKey:
                    next = at;
                    return RDocValue.MaxKey;
                case RDocType.Bool:
                    next = CheckedEnd(at, 1, end);
                    return _buf[at] switch
                    {
                        0 => RDocValue.FromBoolean(false),
                        1 => RDocValue.FromBoolean(true),
                        _ => throw Malformed(at, "bool byte not 0 or 1"),
                    };
                case RDocType.Int64:
                    return RDocValue.FromInt64(RDocFormat.UnZigZag(Varint(at, end, out next)));
                case RDocType.DateTime:
                    return RDocValue.FromUnixTimeMilliseconds(RDocFormat.UnZigZag(Varint(at, end, out next)));
                case RDocType.Counter:
                    return RDocValue.FromCounter(RDocFormat.UnZigZag(Varint(at, end, out next)));
                case RDocType.Float64:
                {
                    next = CheckedEnd(at, 8, end);
                    ulong bits = BinaryPrimitives.ReadUInt64LittleEndian(_buf[at..]);
                    double f = BitConverter.UInt64BitsToDouble(bits);
                    if (_strict && double.IsNaN(f) && bits != RDocValue.CanonicalNaNBits)
                    {
                        throw Malformed(at, "non-canonical NaN");
                    }

                    return RDocValue.FromDouble(f);
                }

                case RDocType.Decimal128:
                {
                    next = CheckedEnd(at, 16, end);
                    UInt128 bits = BinaryPrimitives.ReadUInt128LittleEndian(_buf[at..]);
                    Decimal128 d = Decimal128.FromIeeeBits(bits, out bool canonical);
                    if (_strict && !canonical)
                    {
                        throw Malformed(at, "non-canonical decimal128");
                    }

                    return RDocValue.FromDecimal128(d);
                }

                case RDocType.String:
                    return RDocValue.FromString(Utf8(at, end, out next, out _, out _));
                case RDocType.Binary:
                {
                    CheckedEnd(at, 1, end);
                    byte subtype = _buf[at];
                    int length = Length(at + 1, end, out int dataAt);
                    next = CheckedEnd(dataAt, length, end);
                    if (BinarySubtype.Check(subtype, length) is not null)
                    {
                        throw Malformed(at, "bad binary");
                    }

                    return RDocValue.FromOwnedBinary(subtype, _buf.Slice(dataAt, length).ToArray());
                }

                case RDocType.Timestamp:
                    next = CheckedEnd(at, 12, end);
                    return RDocValue.FromTimestamp(new RDocTimestamp(
                        BinaryPrimitives.ReadUInt64LittleEndian(_buf[at..]),
                        BinaryPrimitives.ReadUInt32LittleEndian(_buf[(at + 8)..])));
                case RDocType.ObjectId:
                    next = CheckedEnd(at, ObjectId.Length, end);
                    return RDocValue.FromObjectId(new ObjectId(_buf.Slice(at, ObjectId.Length)));
                case RDocType.Uuid:
                    next = CheckedEnd(at, 16, end);
                    return RDocValue.FromUuidBytes(_buf.Slice(at, 16));
                case RDocType.VectorF32:
                    return Vector(at, end, out next);
                case RDocType.Array:
                    return RDocValue.FromArray(Array(at, end, depth + 1, out next));
                case RDocType.Object:
                    return RDocValue.FromDocument(Object(at, end, depth + 1, out next));
                default:
                    throw Malformed(pos, "unknown type tag");
            }
        }

        private RDocValue Vector(int pos, int end, out int next)
        {
            int dims = Length(pos, end, out int q);
            next = CheckedEnd(q, 4L * dims, end);
            float[] v = new float[dims];
            for (int i = 0; i < dims; i++)
            {
                float x = BinaryPrimitives.ReadSingleLittleEndian(_buf[(q + (4 * i))..]);
                if (!float.IsFinite(x))
                {
                    throw new RDocException(ErrorCodes.InvalidVector, "non-finite vector element", q + (4 * i));
                }

                v[i] = x;
            }

            return RDocValue.FromOwnedVector(v);
        }

        /// <summary>
        /// Decodes an object (after its tag) and checks the index against the fields: every entry
        /// points at a field start and carries that field's name hash, and entries are strictly
        /// increasing by (hash, name bytes) — which also proves the names unique and the index a
        /// permutation of the fields.
        /// </summary>
        public RDocument Object(int pos, int end, int depth, out int next)
        {
            CheckDepth(depth);
            ContainerHeader h = Header(pos, end, RDocFormat.IndexEntryLength);
            // Each field takes at least 3 bytes (name length, one name byte, tag): bound the count
            // before allocating so a forged count cannot reserve gigabytes.
            if (h.Count > (h.BodyEnd - h.BodyAt) / 3)
            {
                throw Malformed(pos, "field count exceeds the body");
            }

            var fields = new List<Field>(h.Count);
            int q = h.BodyAt;
            for (int i = 0; i < h.Count; i++)
            {
                int start = q - h.BodyAt;
                string name = Utf8(q, h.BodyEnd, out int afterName, out int nameAt, out int nameLength);
                string? error = RDocFormat.FieldNameError(name, nameLength);
                if (error is not null)
                {
                    throw new RDocException(ErrorCodes.InvalidFieldName, error, q);
                }

                RDocValue v = Value(afterName, h.BodyEnd, depth, out q);
                fields.Add(new Field(name, v, start, nameAt, nameLength));
            }

            if (q != h.BodyEnd)
            {
                throw Malformed(q, "object body length mismatch");
            }

            CheckIndex(h, fields);
            var doc = new RDocument(h.Count);
            foreach (Field f in fields)
            {
                doc.AddUnchecked(f.Name, f.Value);
            }

            next = h.BodyEnd;
            return doc;
        }

        private void CheckIndex(ContainerHeader h, List<Field> fields)
        {
            int prevField = -1;
            ushort prevHash = 0;
            for (int i = 0; i < h.Count; i++)
            {
                int at = h.TableAt + (i * RDocFormat.IndexEntryLength);
                ushort hash = BinaryPrimitives.ReadUInt16LittleEndian(_buf[at..]);
                uint offset = BinaryPrimitives.ReadUInt32LittleEndian(_buf[(at + 2)..]);
                int j = FindStart(fields, offset);
                if (j < 0)
                {
                    throw Malformed(at, "index offset is not a field start");
                }

                Field f = fields[j];
                ReadOnlySpan<byte> name = _buf.Slice(f.NameAt, f.NameLength);
                if (RDocFormat.NameHash16(name) != hash)
                {
                    throw Malformed(at, "index hash mismatch");
                }

                if (prevField >= 0)
                {
                    Field p = fields[prevField];
                    int c = prevHash != hash ? prevHash.CompareTo(hash) : _buf.Slice(p.NameAt, p.NameLength).SequenceCompareTo(name);
                    if (c == 0)
                    {
                        throw new RDocException(ErrorCodes.InvalidFieldName, "duplicate field name", at);
                    }

                    if (c > 0)
                    {
                        throw Malformed(at, "index not sorted");
                    }
                }

                prevField = j;
                prevHash = hash;
            }
        }

        /// <summary>Binary search of a field start (starts are ascending: fields are in order).</summary>
        private static int FindStart(List<Field> fields, uint offset)
        {
            int lo = 0;
            int hi = fields.Count - 1;
            while (lo <= hi)
            {
                int mid = lo + ((hi - lo) / 2);
                long s = fields[mid].Start;
                if (s == offset)
                {
                    return mid;
                }

                if (s < offset)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid - 1;
                }
            }

            return -1;
        }

        public RDocArray Array(int pos, int end, int depth, out int next)
        {
            CheckDepth(depth);
            ContainerHeader h = Header(pos, end, RDocFormat.ArrayOffsetLength);
            if (h.Count > h.BodyEnd - h.BodyAt)
            {
                throw Malformed(pos, "element count exceeds the body");
            }

            var items = new RDocArray(h.Count);
            int q = h.BodyAt;
            for (int i = 0; i < h.Count; i++)
            {
                int at = h.TableAt + (i * RDocFormat.ArrayOffsetLength);
                if (BinaryPrimitives.ReadUInt32LittleEndian(_buf[at..]) != (uint)(q - h.BodyAt))
                {
                    throw Malformed(at, "array offset mismatch");
                }

                items.AddUnchecked(Value(q, h.BodyEnd, depth, out q));
            }

            if (q != h.BodyEnd)
            {
                throw Malformed(q, "array body length mismatch");
            }

            next = h.BodyEnd;
            return items;
        }
    }
}
