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
import static io.rustegon.driver.rdoc.Codec.OBJECT;
import static io.rustegon.driver.rdoc.Codec.OBJECT_ID;
import static io.rustegon.driver.rdoc.Codec.STRING;
import static io.rustegon.driver.rdoc.Codec.TIMESTAMP;
import static io.rustegon.driver.rdoc.Codec.UUID_TAG;
import static io.rustegon.driver.rdoc.Codec.VECTOR;
import static io.rustegon.driver.rdoc.Codec.VERSION;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * RDoc v1 encoder (data-model.md §4, FR-DOC-001/003/004). Always writes the canonical form
 * (flag bit 0 set), byte for byte what the server's {@code rustegon-doc} encoder writes.
 *
 * <p>Two passes, like the server: {@code measure} computes every container's body length (kept
 * in pre-order) and enforces the depth and size limits before anything is written, so an
 * oversized document is rejected without building a 16 MiB buffer; {@code write} then emits the
 * bytes into an exactly sized buffer in one pass, back-patching each object's index (sorted by
 * name hash, then name bytes) whose slots are reserved before the fields. UTF-8 forms of names
 * and strings computed by {@code measure} are reused by {@code write} (same traversal order).
 *
 * <p>Stateless and thread-safe.
 */
public final class RDocWriter {
    private RDocWriter() {}

    /**
     * Encodes a document as canonical RDoc v1.
     *
     * @param document the fields, in iteration order (keys must be strings)
     * @return the bytes
     * @throws RDocException {@link RDocException#DOCUMENT_TOO_LARGE} above 16 MiB,
     *     {@link RDocException#NESTING_TOO_DEEP} beyond 100 levels,
     *     {@link RDocException#INVALID_FIELD_NAME} for names breaking data-model.md §2.2,
     *     {@link RDocException#INVALID_VECTOR} for non-finite vector elements,
     *     {@link RDocException#INVALID_ARGUMENT} for unsupported values
     */
    public static byte[] encode(Map<?, ?> document) {
        Encoder e = new Encoder();
        long root = e.measureObject(document, 1);
        long total = HEADER_LEN + root;
        if (total > MAX_DOCUMENT_SIZE) {
            throw tooLarge(total);
        }
        e.out = new byte[(int) total];
        e.out[0] = (byte) MAGIC;
        e.out[1] = (byte) VERSION;
        e.out[2] = (byte) FLAG_CANONICAL;
        e.putU32((int) total, 3);
        e.pos = HEADER_LEN;
        e.writeObject(document);
        assert e.pos == total : "measure and write disagree";
        return e.out;
    }

    /**
     * Encodes a document into {@code target} at its position (advanced past the document).
     *
     * @param document the fields
     * @param target the destination; needs {@link #encodedLength(Map)} bytes remaining
     * @throws RDocException as {@link #encode(Map)}
     * @throws java.nio.BufferOverflowException if {@code target} is too small
     */
    public static void encode(Map<?, ?> document, ByteBuffer target) {
        target.put(encode(document));
    }

    /**
     * Exact encoded size of a document, header included.
     *
     * @param document the fields
     * @return the size in bytes
     * @throws RDocException as {@link #encode(Map)}
     */
    public static int encodedLength(Map<?, ?> document) {
        long total = HEADER_LEN + new Encoder().measureObject(document, 1);
        if (total > MAX_DOCUMENT_SIZE) {
            throw tooLarge(total);
        }
        return (int) total;
    }

    /**
     * Encodes one value in the RDoc value encoding: type tag and payload exactly as the value
     * is stored inside a document, without a header. This is {@code Value.rdoc_value} of the
     * protocol (protocol.md §3): document ids, query parameters, option values.
     *
     * @param value the value (any type accepted in documents)
     * @return the bytes
     * @throws RDocException as {@link #encode(Map)}
     */
    public static byte[] encodeValue(Object value) {
        Encoder e = new Encoder();
        long size = e.measureValue(value, 0);
        e.out = new byte[(int) size];
        e.writeValue(value);
        return e.out;
    }

    private static RDocException tooLarge(long size) {
        return new RDocException(RDocException.DOCUMENT_TOO_LARGE,
                "encoded size " + size + " exceeds the 16 MiB limit");
    }

    /** One encoding: the measure results, then the output. */
    private static final class Encoder {
        /** Container body lengths in pre-order. */
        private long[] sizes = new long[8];
        private int sizeCount;
        private int nextSize;
        /** UTF-8 of names and strings in traversal order. */
        private final List<byte[]> texts = new ArrayList<>();
        private int nextText;
        private byte[] out;
        private int pos;

        private int pushSizeSlot() {
            if (sizeCount == sizes.length) {
                sizes = Arrays.copyOf(sizes, sizes.length * 2);
            }
            return sizeCount++;
        }

        private static void checkDepth(int depth) {
            if (depth > MAX_DEPTH) {
                throw new RDocException(RDocException.NESTING_TOO_DEEP,
                        "nesting deeper than " + MAX_DEPTH + " levels");
            }
        }

        private static long checkSize(long size) {
            if (size > MAX_DOCUMENT_SIZE) {
                throw tooLarge(size);
            }
            return size;
        }

        private static long lenPrefixed(long n) {
            return Codec.varintLen(n) + n;
        }

        private static long container(int n, int entryLen, long body) {
            return 1 + Codec.varintLen(n) + Codec.varintLen(body) + (long) entryLen * n + body;
        }

        long measureValue(Object v, int depth) {
            int tag = Codec.tagOf(v);
            long size = switch (tag) {
                case BOOL -> 2;
                case INT64 -> 1 + Codec.varintLen(Codec.zigzag(Codec.int64(v)));
                case DATETIME -> 1 + Codec.varintLen(Codec.zigzag(Codec.millis(v)));
                case COUNTER -> 1 + Codec.varintLen(Codec.zigzag(((RCounter) v).value()));
                case FLOAT64 -> 9;
                case DECIMAL -> {
                    Codec.decimal(v);
                    yield 17;
                }
                case UUID_TAG -> 17;
                case TIMESTAMP, OBJECT_ID -> 13;
                case STRING -> {
                    byte[] s = Codec.utf8((String) v);
                    texts.add(s);
                    yield 1 + lenPrefixed(s.length);
                }
                case BINARY -> 2 + lenPrefixed(Codec.binary(v).raw().length);
                case VECTOR -> {
                    int dims = Codec.vector(v).raw().length;
                    yield 1 + Codec.varintLen(dims) + 4L * dims;
                }
                case ARRAY -> measureArray(Codec.elements(v), depth + 1);
                case OBJECT -> measureObject((Map<?, ?>) v, depth + 1);
                default -> 1; // null, minKey, maxKey
            };
            return checkSize(size);
        }

        long measureObject(Map<?, ?> d, int depth) {
            checkDepth(depth);
            int slot = pushSizeSlot();
            long body = 0;
            for (Map.Entry<?, ?> f : d.entrySet()) {
                if (!(f.getKey() instanceof String name)) {
                    throw RDocException.invalid("document field names must be strings");
                }
                byte[] utf8 = Codec.utf8(name);
                Codec.validateFieldName(name, utf8);
                texts.add(utf8);
                body += lenPrefixed(utf8.length) + measureValue(f.getValue(), depth);
                checkSize(body);
            }
            sizes[slot] = body;
            return container(d.size(), INDEX_ENTRY_LEN, body);
        }

        long measureArray(Collection<?> items, int depth) {
            checkDepth(depth);
            int slot = pushSizeSlot();
            long body = 0;
            for (Object item : items) {
                body += measureValue(item, depth);
                checkSize(body);
            }
            sizes[slot] = body;
            return container(items.size(), ARRAY_OFFSET_LEN, body);
        }

        private void put(int b) {
            out[pos++] = (byte) b;
        }

        private void putBytes(byte[] b) {
            System.arraycopy(b, 0, out, pos, b.length);
            pos += b.length;
        }

        private void putVarint(long v) {
            while (Long.compareUnsigned(v, 0x80) >= 0) {
                put((int) (v & 0x7F) | 0x80);
                v >>>= 7;
            }
            put((int) v);
        }

        private void putLong(long v) {
            for (int i = 0; i < 8; i++) {
                put((int) (v >>> (8 * i)));
            }
        }

        private void putU32(int v, int at) {
            out[at] = (byte) v;
            out[at + 1] = (byte) (v >>> 8);
            out[at + 2] = (byte) (v >>> 16);
            out[at + 3] = (byte) (v >>> 24);
        }

        void writeValue(Object v) {
            int tag = Codec.tagOf(v);
            if (tag == ARRAY) {
                writeArray(Codec.elements(v));
                return;
            }
            if (tag == OBJECT) {
                writeObject((Map<?, ?>) v);
                return;
            }
            put(tag);
            switch (tag) {
                case BOOL -> put((Boolean) v ? 1 : 0);
                case INT64 -> putVarint(Codec.zigzag(Codec.int64(v)));
                case DATETIME -> putVarint(Codec.zigzag(Codec.millis(v)));
                case COUNTER -> putVarint(Codec.zigzag(((RCounter) v).value()));
                // doubleToLongBits maps every NaN to the canonical 0x7FF8000000000000.
                case FLOAT64 -> putLong(Double.doubleToLongBits(Codec.float64(v)));
                case DECIMAL -> {
                    Decimal128 d = Codec.decimal(v);
                    putLong(d.lowBits());
                    putLong(d.highBits());
                }
                case STRING -> {
                    byte[] s = texts.get(nextText++);
                    putVarint(s.length);
                    putBytes(s);
                }
                case BINARY -> {
                    RBinary b = Codec.binary(v);
                    put(b.subtype());
                    putVarint(b.raw().length);
                    putBytes(b.raw());
                }
                case TIMESTAMP -> {
                    RTimestamp t = (RTimestamp) v;
                    putLong(t.wall());
                    putU32(t.logical(), pos);
                    pos += 4;
                }
                case OBJECT_ID -> putBytes(((ObjectId) v).raw());
                case UUID_TAG -> {
                    UUID u = (UUID) v;
                    putLong(Long.reverseBytes(u.getMostSignificantBits()));
                    putLong(Long.reverseBytes(u.getLeastSignificantBits()));
                }
                case VECTOR -> {
                    float[] xs = Codec.vector(v).raw();
                    putVarint(xs.length);
                    for (float x : xs) {
                        putU32(Float.floatToRawIntBits(x), pos);
                        pos += 4;
                    }
                }
                default -> { } // null, minKey, maxKey: tag only
            }
        }

        void writeObject(Map<?, ?> d) {
            put(OBJECT);
            int n = d.size();
            putVarint(n);
            long body = sizes[nextSize++];
            putVarint(body);
            int indexAt = pos;
            pos += INDEX_ENTRY_LEN * n;
            int fieldsAt = pos;
            int[] hashes = new int[n];
            byte[][] names = new byte[n][];
            int[] offsets = new int[n];
            int i = 0;
            for (Map.Entry<?, ?> f : d.entrySet()) {
                byte[] name = texts.get(nextText++);
                offsets[i] = pos - fieldsAt;
                names[i] = name;
                hashes[i] = Xxh3.nameHash16(name);
                putVarint(name.length);
                putBytes(name);
                writeValue(f.getValue());
                i++;
            }
            // Index order (hash, name bytes) makes lookups a binary search and the bytes
            // canonical; names are unique (a Map), so the order is strict.
            Integer[] order = new Integer[n];
            for (int k = 0; k < n; k++) {
                order[k] = k;
            }
            Arrays.sort(order, (a, b) -> {
                int c = Integer.compare(hashes[a], hashes[b]);
                return c != 0 ? c : Arrays.compareUnsigned(names[a], names[b]);
            });
            for (int k = 0; k < n; k++) {
                int at = indexAt + k * INDEX_ENTRY_LEN;
                int e = order[k];
                out[at] = (byte) hashes[e];
                out[at + 1] = (byte) (hashes[e] >>> 8);
                putU32(offsets[e], at + 2);
            }
            assert pos - fieldsAt == body : "object body length";
        }

        void writeArray(Collection<?> items) {
            put(ARRAY);
            putVarint(items.size());
            long body = sizes[nextSize++];
            putVarint(body);
            int tableAt = pos;
            pos += ARRAY_OFFSET_LEN * items.size();
            int elemsAt = pos;
            int i = 0;
            for (Object item : items) {
                putU32(pos - elemsAt, tableAt + i * ARRAY_OFFSET_LEN);
                writeValue(item);
                i++;
            }
            assert pos - elemsAt == body : "array body length";
        }
    }
}
