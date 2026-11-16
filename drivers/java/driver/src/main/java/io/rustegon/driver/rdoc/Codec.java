// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Map;
import java.util.UUID;

/**
 * Constants and helpers shared by the RDoc encoder, decoder and the JSON codec
 * (data-model.md §2, §2.2, §4).
 */
final class Codec {
    private Codec() {}

    /** First byte of every RDoc. */
    static final int MAGIC = 0xD7;
    /** Format version written and read. */
    static final int VERSION = 1;
    /** {@code flags} bit 0: canonical form. */
    static final int FLAG_CANONICAL = 0x01;
    /** Header: magic, version, flags, {@code total_len} (u32 LE). */
    static final int HEADER_LEN = 7;
    /** Object index entry: {@code name_hash16} u16 + offset u32. */
    static final int INDEX_ENTRY_LEN = 6;
    /** Array offset-table entry: u32. */
    static final int ARRAY_OFFSET_LEN = 4;
    /** FR-DOC-004: 16 MiB including the header. */
    static final int MAX_DOCUMENT_SIZE = 16 * 1024 * 1024;
    /** Root object = depth 1; each nested container adds 1. */
    static final int MAX_DEPTH = 100;
    /** Field names: 1–1024 bytes of UTF-8 (§2.2). */
    static final int MAX_FIELD_NAME_LEN = 1024;
    /** Largest integer magnitude a JSON number carries without loss in IEEE-double parsers. */
    static final long MAX_SAFE_INTEGER = 1L << 53;

    // Type tags (data-model.md §2).
    static final int NULL = 0x01;
    static final int BOOL = 0x02;
    static final int INT64 = 0x03;
    static final int FLOAT64 = 0x04;
    static final int DECIMAL = 0x05;
    static final int STRING = 0x06;
    static final int BINARY = 0x07;
    static final int DATETIME = 0x08;
    static final int TIMESTAMP = 0x09;
    static final int OBJECT_ID = 0x0A;
    static final int UUID_TAG = 0x0B;
    static final int ARRAY = 0x0C;
    static final int OBJECT = 0x0D;
    static final int VECTOR = 0x0E;
    static final int COUNTER = 0x0F;
    static final int MIN_KEY = 0x10;
    static final int MAX_KEY = 0x11;

    /**
     * The type tag of a Java value accepted by the codecs (see {@link RDocument}).
     *
     * @throws RDocException for an unsupported type
     */
    static int tagOf(Object v) {
        return switch (v) {
            case null -> NULL;
            case Boolean b -> BOOL;
            case Long l -> INT64;
            case Integer i -> INT64;
            case Short s -> INT64;
            case Byte b -> INT64;
            case Double d -> FLOAT64;
            case Float f -> FLOAT64;
            case Decimal128 d -> DECIMAL;
            case BigDecimal d -> DECIMAL;
            case String s -> STRING;
            case RBinary b -> BINARY;
            case byte[] b -> BINARY;
            case Instant t -> DATETIME;
            case OffsetDateTime t -> DATETIME;
            case ZonedDateTime t -> DATETIME;
            case RTimestamp t -> TIMESTAMP;
            case ObjectId o -> OBJECT_ID;
            case UUID u -> UUID_TAG;
            case Collection<?> c -> ARRAY;
            case Object[] a -> ARRAY;
            case Map<?, ?> m -> OBJECT;
            case RVector r -> VECTOR;
            case float[] f -> VECTOR;
            case RCounter c -> COUNTER;
            case MinKey k -> MIN_KEY;
            case MaxKey k -> MAX_KEY;
            default -> throw RDocException.invalid(
                    "unsupported value type " + v.getClass().getName());
        };
    }

    /** int64 value of an integral Java number. */
    static long int64(Object v) {
        return ((Number) v).longValue();
    }

    /** float64 value of a Java float or double ({@code Float} widened exactly). */
    static double float64(Object v) {
        return ((Number) v).doubleValue();
    }

    static Decimal128 decimal(Object v) {
        return v instanceof BigDecimal b ? Decimal128.of(b) : (Decimal128) v;
    }

    static RBinary binary(Object v) {
        return v instanceof byte[] b ? RBinary.of(b) : (RBinary) v;
    }

    static RVector vector(Object v) {
        return v instanceof float[] f ? new RVector(f) : (RVector) v;
    }

    /** Milliseconds since the epoch; sub-millisecond digits are truncated (floor). */
    static long millis(Object v) {
        Instant t = switch (v) {
            case OffsetDateTime o -> o.toInstant();
            case ZonedDateTime z -> z.toInstant();
            default -> (Instant) v;
        };
        try {
            return t.toEpochMilli();
        } catch (ArithmeticException e) {
            throw RDocException.invalid("datetime outside the int64 millisecond range");
        }
    }

    /** Elements of an array value. */
    static Collection<?> elements(Object v) {
        return v instanceof Object[] a ? java.util.Arrays.asList(a) : (Collection<?>) v;
    }

    /** Field-name rules every stored name obeys at any level (§2.2, RGN-1004). */
    static void validateFieldName(String name, byte[] utf8) {
        String reason;
        if (utf8.length == 0) {
            reason = "empty field name";
        } else if (utf8.length > MAX_FIELD_NAME_LEN) {
            reason = "field name longer than 1024 bytes";
        } else if (name.indexOf('\0') >= 0) {
            reason = "field name contains NUL";
        } else if (name.charAt(0) == '$') {
            reason = "field name starts with '$'";
        } else {
            return;
        }
        throw RDocException.fieldName(reason);
    }

    /** Strict UTF-8 encoding: a lone surrogate is an error, not a silent {@code ?}. */
    static byte[] utf8(String s) {
        // Fast path: pure ASCII needs no coding checks.
        boolean ascii = true;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) >= 0x80) {
                ascii = false;
                break;
            }
        }
        if (ascii) {
            return s.getBytes(StandardCharsets.US_ASCII);
        }
        try {
            ByteBuffer b = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(s));
            byte[] out = new byte[b.remaining()];
            b.get(out);
            return out;
        } catch (CharacterCodingException e) {
            throw RDocException.invalid("string is not valid Unicode (lone surrogate)");
        }
    }

    /** Strict UTF-8 decoding of {@code len} bytes at {@code at} (absolute). */
    static String utf8(ByteBuffer buf, int at, int len) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(buf.slice(at, len))
                    .toString();
        } catch (CharacterCodingException e) {
            throw RDocException.malformed(at, "invalid UTF-8");
        }
    }

    /** Zigzag mapping of a signed integer onto an unsigned one. */
    static long zigzag(long v) {
        return (v << 1) ^ (v >> 63);
    }

    static long unzigzag(long z) {
        return (z >>> 1) ^ -(z & 1);
    }

    /** Encoded length of an unsigned LEB128 varint. */
    static int varintLen(long v) {
        int n = 1;
        while (Long.compareUnsigned(v, 0x80) >= 0) {
            v >>>= 7;
            n++;
        }
        return n;
    }
}
