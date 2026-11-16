// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static io.rustegon.driver.rdoc.Codec.ARRAY;
import static io.rustegon.driver.rdoc.Codec.ARRAY_OFFSET_LEN;
import static io.rustegon.driver.rdoc.Codec.BINARY;
import static io.rustegon.driver.rdoc.Codec.BOOL;
import static io.rustegon.driver.rdoc.Codec.COUNTER;
import static io.rustegon.driver.rdoc.Codec.DATETIME;
import static io.rustegon.driver.rdoc.Codec.DECIMAL;
import static io.rustegon.driver.rdoc.Codec.FLAG_CANONICAL;
import static io.rustegon.driver.rdoc.Codec.FLOAT64;
import static io.rustegon.driver.rdoc.Codec.HEADER_LEN;
import static io.rustegon.driver.rdoc.Codec.INDEX_ENTRY_LEN;
import static io.rustegon.driver.rdoc.Codec.INT64;
import static io.rustegon.driver.rdoc.Codec.MAGIC;
import static io.rustegon.driver.rdoc.Codec.MAX_DEPTH;
import static io.rustegon.driver.rdoc.Codec.MAX_DOCUMENT_SIZE;
import static io.rustegon.driver.rdoc.Codec.MAX_KEY;
import static io.rustegon.driver.rdoc.Codec.MIN_KEY;
import static io.rustegon.driver.rdoc.Codec.NULL;
import static io.rustegon.driver.rdoc.Codec.OBJECT;
import static io.rustegon.driver.rdoc.Codec.OBJECT_ID;
import static io.rustegon.driver.rdoc.Codec.STRING;
import static io.rustegon.driver.rdoc.Codec.TIMESTAMP;
import static io.rustegon.driver.rdoc.Codec.UUID_TAG;
import static io.rustegon.driver.rdoc.Codec.VECTOR;
import static io.rustegon.driver.rdoc.Codec.VERSION;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * RDoc v1 decoder with full validation (data-model.md §4), equivalent to the server's
 * {@code rustegon-doc} decoder.
 *
 * <p>Every input is untrusted: all reads are bounds-checked against the enclosing value, counts
 * are bounded by the body length before anything is allocated, recursion is bounded by the depth
 * limit, and every inconsistency (truncation, lengths past the enclosing value, unknown tags,
 * invalid UTF-8, inconsistent index or offsets, trailing bytes) is an {@link RDocException},
 * never another runtime exception. With the canonical flag set the bytes must also be canonical
 * (minimal varints, canonical NaN and decimal128); without it those variants are accepted and
 * normalized.
 *
 * <p>Stateless and thread-safe; the input buffer is only read (absolute reads, its position is
 * not changed).
 */
public final class RDocReader {
    private RDocReader() {}

    /**
     * Decodes and validates an RDoc.
     *
     * @param rdoc the bytes, exactly one document
     * @return the document
     * @throws RDocException on malformed input (codes as in {@link RDocWriter#encode})
     */
    public static RDocument decode(byte[] rdoc) {
        return decode(ByteBuffer.wrap(rdoc));
    }

    /**
     * Decodes the document held by the remaining bytes of {@code rdoc}.
     *
     * @param rdoc the bytes between position and limit, exactly one document
     * @return the document
     * @throws RDocException on malformed input
     */
    public static RDocument decode(ByteBuffer rdoc) {
        ByteBuffer buf = rdoc.slice().order(ByteOrder.LITTLE_ENDIAN);
        boolean strict = checkHeader(buf);
        Decoder d = new Decoder(buf, strict);
        int end = buf.limit();
        if ((buf.get(HEADER_LEN) & 0xFF) != OBJECT) {
            throw RDocException.malformed(HEADER_LEN, "root is not an object");
        }
        RDocument doc = d.object(HEADER_LEN + 1, end, 1);
        if (d.next != end) {
            throw RDocException.malformed(d.next, "trailing bytes after the root object");
        }
        return doc;
    }

    /**
     * Decodes one value in the RDoc value encoding ({@link RDocWriter#encodeValue}): the whole
     * input must be exactly one value. Non-canonical variants are accepted and normalized.
     *
     * @param bytes the value bytes
     * @return the value ({@code null} for the null value)
     * @throws RDocException on malformed input or trailing bytes
     */
    public static Object decodeValue(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        Decoder d = new Decoder(buf, false);
        Object v = d.value(0, bytes.length, 0);
        if (d.next != bytes.length) {
            throw RDocException.malformed(d.next, "trailing bytes after value");
        }
        return v;
    }

    private static boolean checkHeader(ByteBuffer b) {
        int len = b.limit();
        if (len < HEADER_LEN + 1) {
            throw RDocException.malformed(len, "truncated header");
        }
        if ((b.get(0) & 0xFF) != MAGIC) {
            throw RDocException.malformed(0, "bad magic");
        }
        if ((b.get(1) & 0xFF) != VERSION) {
            throw RDocException.malformed(1, "unsupported RDoc version");
        }
        int flags = b.get(2) & 0xFF;
        if ((flags & ~FLAG_CANONICAL) != 0) {
            throw RDocException.malformed(2, "unknown flag bits");
        }
        long total = b.getInt(3) & 0xFFFF_FFFFL;
        if (total > MAX_DOCUMENT_SIZE) {
            throw new RDocException(RDocException.DOCUMENT_TOO_LARGE,
                    "total_len " + total + " exceeds the 16 MiB limit");
        }
        if (total != len) {
            throw RDocException.malformed(3, "total_len does not match the input length");
        }
        return (flags & FLAG_CANONICAL) != 0;
    }

    /**
     * One decoding pass. Positions are absolute ints into {@code buf}; every reader returns
     * its value and leaves the position after it in {@link #next}.
     */
    private static final class Decoder {
        /** Each field takes at least 3 bytes: name length, one name byte, tag. */
        private static final int MIN_FIELD_LEN = 3;
        private final ByteBuffer buf;
        private final boolean strict;
        private int next;

        Decoder(ByteBuffer buf, boolean strict) {
            this.buf = buf;
            this.strict = strict;
        }

        private int u8(int at, int end) {
            if (at >= end) {
                throw RDocException.malformed(at, "truncated value");
            }
            return buf.get(at) & 0xFF;
        }

        /** {@code pos + len} if it does not pass {@code end}. */
        private static int checkedEnd(int pos, long len, int end) {
            if (len < 0 || pos + len > end) {
                throw RDocException.malformed(pos, "length exceeds the enclosing value");
            }
            return (int) (pos + len);
        }

        /** Unsigned LEB128 at {@code pos}; sets {@link #next}. */
        private long varint(int pos, int end) {
            // A u64 needs at most 10 groups of 7 bits; the 10th may only carry the top bit.
            long v = 0;
            for (int i = 0; i < 10; i++) {
                int p = pos + i;
                if (p >= end) {
                    throw RDocException.malformed(p, "truncated varint");
                }
                int b = buf.get(p) & 0xFF;
                if (i == 9 && b > 1) {
                    throw RDocException.malformed(p, "varint overflows u64");
                }
                v |= (long) (b & 0x7F) << (7 * i);
                if ((b & 0x80) == 0) {
                    if (strict && i > 0 && b == 0) {
                        throw RDocException.malformed(p, "non-minimal varint");
                    }
                    next = p + 1;
                    return v;
                }
            }
            throw RDocException.malformed(pos, "varint too long");
        }

        /** A varint used as a length or count (bounded by the 16 MiB input anyway). */
        private int length(int pos, int end) {
            long v = varint(pos, end);
            if (v < 0 || v > Integer.MAX_VALUE) {
                throw RDocException.malformed(pos, "length overflow");
            }
            return (int) v;
        }

        private static void checkDepth(int depth) {
            if (depth > MAX_DEPTH) {
                throw new RDocException(RDocException.NESTING_TOO_DEEP,
                        "nesting deeper than " + MAX_DEPTH + " levels");
            }
        }

        /** Decodes the value whose tag is at {@code pos}; containers get {@code depth + 1}. */
        Object value(int pos, int end, int depth) {
            if (pos >= end) {
                throw RDocException.malformed(pos, "missing value");
            }
            int tag = buf.get(pos) & 0xFF;
            int at = pos + 1;
            switch (tag) {
                case NULL -> {
                    next = at;
                    return null;
                }
                case MIN_KEY -> {
                    next = at;
                    return MinKey.INSTANCE;
                }
                case MAX_KEY -> {
                    next = at;
                    return MaxKey.INSTANCE;
                }
                case BOOL -> {
                    int b = u8(at, end);
                    if (b > 1) {
                        throw RDocException.malformed(at, "bool byte not 0 or 1");
                    }
                    next = at + 1;
                    return b == 1;
                }
                case INT64 -> {
                    return Codec.unzigzag(varint(at, end));
                }
                case DATETIME -> {
                    return Instant.ofEpochMilli(Codec.unzigzag(varint(at, end)));
                }
                case COUNTER -> {
                    return new RCounter(Codec.unzigzag(varint(at, end)));
                }
                case FLOAT64 -> {
                    checkedEnd(at, 8, end);
                    long bits = buf.getLong(at);
                    double f = Double.longBitsToDouble(bits);
                    if (strict && Double.isNaN(f) && bits != 0x7FF8_0000_0000_0000L) {
                        throw RDocException.malformed(at, "non-canonical NaN");
                    }
                    next = at + 8;
                    return Double.isNaN(f) ? Double.NaN : f;
                }
                case DECIMAL -> {
                    checkedEnd(at, 16, end);
                    long low = buf.getLong(at);
                    long high = buf.getLong(at + 8);
                    if (strict && !Decimal128.isCanonical(high, low)) {
                        throw RDocException.malformed(at, "non-canonical decimal128");
                    }
                    next = at + 16;
                    return Decimal128.fromBits(high, low);
                }
                case STRING -> {
                    return string(at, end);
                }
                case BINARY -> {
                    int subtype = u8(at, end);
                    int len = length(at + 1, end);
                    int start = next;
                    int stop = checkedEnd(start, len, end);
                    try {
                        RBinary.check(subtype, len);
                    } catch (RDocException e) {
                        throw RDocException.malformed(at, "bad binary");
                    }
                    byte[] data = new byte[len];
                    buf.get(start, data);
                    next = stop;
                    return new RBinary(subtype, data);
                }
                case TIMESTAMP -> {
                    checkedEnd(at, 12, end);
                    next = at + 12;
                    return new RTimestamp(buf.getLong(at), buf.getInt(at + 8));
                }
                case OBJECT_ID -> {
                    checkedEnd(at, 12, end);
                    byte[] id = new byte[ObjectId.LENGTH];
                    buf.get(at, id);
                    next = at + 12;
                    return ObjectId.of(id);
                }
                case UUID_TAG -> {
                    checkedEnd(at, 16, end);
                    ByteBuffer be = buf.duplicate().order(ByteOrder.BIG_ENDIAN);
                    next = at + 16;
                    return new UUID(be.getLong(at), be.getLong(at + 8));
                }
                case VECTOR -> {
                    return vector(at, end);
                }
                case ARRAY -> {
                    return array(at, end, depth + 1);
                }
                case OBJECT -> {
                    return object(at, end, depth + 1);
                }
                default -> throw RDocException.malformed(pos, "unknown type tag");
            }
        }

        private String string(int p, int end) {
            int len = length(p, end);
            int start = next;
            int stop = checkedEnd(start, len, end);
            String s = Codec.utf8(buf, start, len);
            next = stop;
            return s;
        }

        private RVector vector(int p, int end) {
            int dims = length(p, end);
            int start = next;
            int stop = checkedEnd(start, 4L * dims, end);
            float[] v = new float[dims];
            for (int i = 0; i < dims; i++) {
                float x = buf.getFloat(start + 4 * i);
                if (!Float.isFinite(x)) {
                    throw new RDocException(RDocException.INVALID_VECTOR, "non-finite element");
                }
                v[i] = x;
            }
            next = stop;
            return new RVector(v);
        }

        /** {@code n}, table start, body start and end of a container (after its tag). */
        private int[] header(int pos, int end, int entryLen) {
            int n = length(pos, end);
            int bodyLen = length(next, end);
            int tableAt = next;
            int bodyAt = checkedEnd(tableAt, (long) n * entryLen, end);
            int bodyEnd = checkedEnd(bodyAt, bodyLen, end);
            return new int[] {n, tableAt, bodyAt, bodyEnd};
        }

        /**
         * Decodes an object (after its tag) and checks the index against the fields: every
         * entry must point at a field start and carry that field's name hash, and entries must
         * be strictly increasing by (hash, name bytes) — which also proves the names unique and
         * the index a permutation of the fields.
         */
        RDocument object(int p, int end, int depth) {
            checkDepth(depth);
            int[] h = header(p, end, INDEX_ENTRY_LEN);
            int n = h[0];
            int tableAt = h[1];
            int bodyAt = h[2];
            int bodyEnd = h[3];
            // Bound n before allocating so that a forged count cannot reserve gigabytes.
            if (n > (bodyEnd - bodyAt) / MIN_FIELD_LEN) {
                throw RDocException.malformed(p, "field count exceeds the body");
            }
            String[] names = new String[n];
            byte[][] nameBytes = new byte[n][];
            Object[] values = new Object[n];
            int[] starts = new int[n];
            int q = bodyAt;
            for (int i = 0; i < n; i++) {
                starts[i] = q - bodyAt;
                int len = length(q, bodyEnd);
                int nameAt = next;
                int afterName = checkedEnd(nameAt, len, bodyEnd);
                String name = Codec.utf8(buf, nameAt, len);
                byte[] raw = new byte[len];
                buf.get(nameAt, raw);
                Codec.validateFieldName(name, raw);
                names[i] = name;
                nameBytes[i] = raw;
                values[i] = value(afterName, bodyEnd, depth);
                q = next;
            }
            if (q != bodyEnd) {
                throw RDocException.malformed(q, "object body length mismatch");
            }
            int prevHash = -1;
            byte[] prevName = null;
            for (int i = 0; i < n; i++) {
                int at = tableAt + i * INDEX_ENTRY_LEN;
                int hash = buf.getShort(at) & 0xFFFF;
                long offset = buf.getInt(at + 2) & 0xFFFF_FFFFL;
                int j = offset > Integer.MAX_VALUE ? -1 : Arrays.binarySearch(starts, (int) offset);
                if (j < 0) {
                    throw RDocException.malformed(at, "index offset is not a field start");
                }
                if (Xxh3.nameHash16(nameBytes[j]) != hash) {
                    throw RDocException.malformed(at, "index hash mismatch");
                }
                if (prevName != null) {
                    int c = hash != prevHash ? Integer.compare(prevHash, hash)
                            : Arrays.compareUnsigned(prevName, nameBytes[j]);
                    if (c == 0) {
                        throw RDocException.fieldName("duplicate field name");
                    }
                    if (c > 0) {
                        throw RDocException.malformed(at, "index not sorted");
                    }
                }
                prevHash = hash;
                prevName = nameBytes[j];
            }
            RDocument doc = new RDocument();
            for (int i = 0; i < n; i++) {
                doc.put(names[i], values[i]);
            }
            next = bodyEnd;
            return doc;
        }

        List<Object> array(int p, int end, int depth) {
            checkDepth(depth);
            int[] h = header(p, end, ARRAY_OFFSET_LEN);
            int n = h[0];
            int tableAt = h[1];
            int bodyAt = h[2];
            int bodyEnd = h[3];
            if (n > bodyEnd - bodyAt) {
                throw RDocException.malformed(p, "element count exceeds the body");
            }
            List<Object> items = new ArrayList<>(n);
            int q = bodyAt;
            for (int i = 0; i < n; i++) {
                int at = tableAt + i * ARRAY_OFFSET_LEN;
                if ((buf.getInt(at) & 0xFFFF_FFFFL) != q - bodyAt) {
                    throw RDocException.malformed(at, "array offset mismatch");
                }
                items.add(value(q, bodyEnd, depth));
                q = next;
            }
            if (q != bodyEnd) {
                throw RDocException.malformed(q, "array body length mismatch");
            }
            next = bodyEnd;
            return items;
        }
    }
}
