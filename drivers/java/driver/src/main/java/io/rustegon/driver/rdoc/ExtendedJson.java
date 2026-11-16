// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Canonical and extended JSON of documents and values (data-model.md §2, FR-DOC-003), a port
 * of the server's {@code rustegon-doc} JSON codec: same output bytes, same accepted input.
 *
 * <p><b>Output</b> ({@link JsonMode}): compact, fields in stored order, only {@code "}, {@code \}
 * and C0 controls escaped ({@code \b \f \n \r \t}, others {@code \}{@code u00xx}), non-ASCII
 * verbatim; float64 as its shortest round-trip text in the server's notation (plain between
 * 1e-4 and 1e16, else {@code 1e300}-style exponent; always a {@code .} or an exponent).
 *
 * <p><b>Input</b>: RFC 8259 syntax. Integers within int64 become {@link Long}; integers beyond it
 * become {@link Double} (nearest); a fraction or exponent gives a {@link Double}; magnitudes
 * beyond the float64 range are rejected. A {@code $}-prefixed name is valid only as the single
 * key of a wrapper ({@code $int64 $float $decimal $date $oid $uuid $ts $binary $vector $minKey
 * $maxKey}); anywhere else, duplicate names and {@code {"$counter":…}} are
 * {@link RDocException#INVALID_FIELD_NAME}; nesting beyond 100 levels is
 * {@link RDocException#NESTING_TOO_DEEP}.
 */
public final class ExtendedJson {
    private ExtendedJson() {}

    /**
     * Parses a JSON object into a document.
     *
     * @param json the text
     * @return the document
     * @throws RDocException on syntax errors, a non-object top level, invalid names or values
     */
    public static RDocument parseDocument(String json) {
        if (parseValue(json) instanceof RDocument d) {
            return d;
        }
        throw RDocException.invalid("a document must be a JSON object");
    }

    /**
     * Parses any JSON value (extended-JSON wrappers included).
     *
     * @param json the text
     * @return the value ({@code null} for JSON {@code null})
     * @throws RDocException as {@link #parseDocument}
     */
    public static Object parseValue(String json) {
        Parser p = new Parser(json);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.pos != json.length()) {
            throw p.err("trailing characters");
        }
        return v;
    }

    /**
     * Serializes a document.
     *
     * @param document the fields (keys must be strings)
     * @param mode canonical or extended
     * @return the JSON text
     * @throws RDocException for unsupported values
     */
    public static String toJson(Map<?, ?> document, JsonMode mode) {
        StringBuilder out = new StringBuilder();
        writeObject(out, document, mode);
        return out.toString();
    }

    /**
     * Serializes one value.
     *
     * @param value the value
     * @param mode canonical or extended
     * @return the JSON text
     * @throws RDocException for unsupported values
     */
    public static String valueToJson(Object value, JsonMode mode) {
        StringBuilder out = new StringBuilder();
        writeValue(out, value, mode);
        return out.toString();
    }

    // --- Output ---------------------------------------------------------------------------

    private static void writeObject(StringBuilder out, Map<?, ?> d, JsonMode mode) {
        out.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : d.entrySet()) {
            if (!(e.getKey() instanceof String name)) {
                throw RDocException.invalid("document field names must be strings");
            }
            if (!first) {
                out.append(',');
            }
            first = false;
            writeString(out, name);
            out.append(':');
            writeValue(out, e.getValue(), mode);
        }
        out.append('}');
    }

    private static void wrap(StringBuilder out, String key, String text) {
        out.append("{\"").append(key).append("\":\"").append(text).append("\"}");
    }

    private static void writeValue(StringBuilder out, Object v, JsonMode mode) {
        switch (Codec.tagOf(v)) {
            case Codec.NULL -> out.append("null");
            case Codec.BOOL -> out.append((Boolean) v ? "true" : "false");
            case Codec.INT64 -> {
                long i = Codec.int64(v);
                boolean plain = mode == JsonMode.CANONICAL && i != Long.MIN_VALUE
                        && Math.abs(i) <= Codec.MAX_SAFE_INTEGER;
                if (plain) {
                    out.append(i);
                } else {
                    wrap(out, "$int64", Long.toString(i));
                }
            }
            case Codec.FLOAT64 -> {
                double f = Codec.float64(v);
                if (Double.isNaN(f)) {
                    wrap(out, "$float", "NaN");
                } else if (Double.isInfinite(f)) {
                    wrap(out, "$float", f > 0 ? "Infinity" : "-Infinity");
                } else if (mode == JsonMode.CANONICAL) {
                    out.append(floatText(f));
                } else {
                    wrap(out, "$float", floatText(f));
                }
            }
            case Codec.DECIMAL -> wrap(out, "$decimal", Codec.decimal(v).toString());
            case Codec.STRING -> writeString(out, (String) v);
            case Codec.BINARY -> {
                RBinary b = Codec.binary(v);
                out.append("{\"$binary\":{\"base64\":\"")
                        .append(Base64.getEncoder().encodeToString(b.raw()))
                        .append("\",\"subType\":\"")
                        .append(HexFormat.of().toHexDigits((byte) b.subtype()))
                        .append("\"}}");
            }
            case Codec.DATETIME -> wrap(out, "$date", IsoDate.format(Codec.millis(v)));
            case Codec.TIMESTAMP -> wrap(out, "$ts", v.toString());
            case Codec.OBJECT_ID -> wrap(out, "$oid", v.toString());
            case Codec.UUID_TAG -> wrap(out, "$uuid", v.toString());
            case Codec.ARRAY -> {
                out.append('[');
                boolean first = true;
                for (Object item : Codec.elements(v)) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    writeValue(out, item, mode);
                }
                out.append(']');
            }
            case Codec.OBJECT -> writeObject(out, (Map<?, ?>) v, mode);
            case Codec.VECTOR -> {
                out.append("{\"$vector\":[");
                float[] xs = Codec.vector(v).raw();
                for (int i = 0; i < xs.length; i++) {
                    if (i > 0) {
                        out.append(',');
                    }
                    float a = Math.abs(xs[i]);
                    BigDecimal digits = oneDigitIfPossible(new BigDecimal(Float.toString(a)),
                            new BigDecimal((double) a), c -> Float.parseFloat(c.toString()) == a);
                    out.append(shortest(digits,
                            xs[i] < 0 || (xs[i] == 0 && 1 / xs[i] < 0), Math.abs(xs[i]), 1e-4f, 1e16f));
                }
                out.append("]}");
            }
            case Codec.COUNTER -> out.append("{\"$counter\":").append(((RCounter) v).value())
                    .append('}');
            case Codec.MIN_KEY -> out.append("{\"$minKey\":1}");
            case Codec.MAX_KEY -> out.append("{\"$maxKey\":1}");
            default -> throw new IllegalStateException("unreachable tag");
        }
    }

    /** Shortest round-trip text of a finite double in the server's (Rust {@code {:?}}) notation. */
    static String floatText(double f) {
        double abs = Math.abs(f);
        boolean negative = f < 0 || (f == 0 && 1 / f < 0);
        BigDecimal digits = oneDigitIfPossible(new BigDecimal(Double.toString(abs)),
                new BigDecimal(abs), c -> Double.parseDouble(c.toString()) == abs);
        return shortest(digits, negative, abs, 1e-4, 1e16);
    }

    /**
     * The JDK (19+) prints two digits when a one-digit decimal also round-trips but a two-digit
     * one is closer ({@code 4.9E-324}); the server (Rust, shortest first) prints the one-digit
     * form ({@code 5e-324}). Returns the closest one-digit decimal that round-trips, if any.
     */
    private static BigDecimal oneDigitIfPossible(BigDecimal javaDigits, BigDecimal exact,
            java.util.function.Predicate<BigDecimal> roundTrips) {
        BigDecimal s = javaDigits.stripTrailingZeros();
        if (s.signum() == 0 || s.precision() != 2) {
            return s;
        }
        BigDecimal best = null;
        for (java.math.RoundingMode mode : new java.math.RoundingMode[] {
            java.math.RoundingMode.FLOOR, java.math.RoundingMode.CEILING}) {
            BigDecimal c = s.round(new java.math.MathContext(1, mode));
            if (roundTrips.test(c) && (best == null || c.subtract(exact).abs()
                    .compareTo(best.subtract(exact).abs()) < 0)) {
                best = c;
            }
        }
        return best == null ? s : best.stripTrailingZeros();
    }

    /**
     * Formats {@code digits} (the shortest decimal of the magnitude, from the JDK's shortest
     * {@code toString}, JDK 19+) as Rust's {@code Debug} does: plain notation with at least one
     * fraction digit when {@code small <= |x| < big} (1e-4 and 1e16 in the value's own precision) or {@code x == 0}, else
     * {@code d[.ddd]e[-]x}.
     */
    private static String shortest(BigDecimal digits, boolean negative, double abs,
            double small, double big) {
        StringBuilder s = new StringBuilder();
        if (negative) {
            s.append('-');
        }
        if (abs == 0) {
            return s.append("0.0").toString();
        }
        BigDecimal d = digits.stripTrailingZeros();
        String unscaled = d.unscaledValue().toString();
        int n = unscaled.length();
        // value = unscaled × 10^(-scale)
        int exp10 = -d.scale();
        if (abs >= small && abs < big) {
            if (exp10 >= 0) {
                s.append(unscaled).append("0".repeat(exp10)).append(".0");
            } else if (n + exp10 > 0) {
                int point = n + exp10;
                s.append(unscaled, 0, point).append('.').append(unscaled, point, n);
            } else {
                s.append("0.").append("0".repeat(-(n + exp10))).append(unscaled);
            }
        } else {
            s.append(unscaled.charAt(0));
            if (n > 1) {
                s.append('.').append(unscaled, 1, n);
            }
            s.append('e').append(exp10 + n - 1);
        }
        return s.toString();
    }

    /**
     * Minimal escaping: {@code "}, {@code \} and C0 controls; everything else verbatim.
     */
    private static void writeString(StringBuilder out, String s) {
        // Validates as the RDoc encoder does: a lone surrogate is not text.
        Codec.utf8(s);
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append("\\u00").append(HexFormat.of().toHexDigits((byte) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    // --- Input ----------------------------------------------------------------------------

    /** Recursive-descent parser; depth is bounded before recursing (bounded stack). */
    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        RDocException err(String reason) {
            return RDocException.invalid("invalid JSON at character " + pos + ": " + reason);
        }

        private int peek() {
            return pos < s.length() ? s.charAt(pos) : -1;
        }

        void ws() {
            while (true) {
                int c = peek();
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    return;
                }
                pos++;
            }
        }

        private void eat(char c) {
            ws();
            if (peek() != c) {
                throw err("expected '" + c + "'");
            }
            pos++;
        }

        private Object literal(String word, Object v) {
            if (!s.startsWith(word, pos)) {
                throw err("invalid literal");
            }
            pos += word.length();
            return v;
        }

        /** A value; {@code depth} is the depth of the enclosing container (0 at top level). */
        Object value(int depth) {
            ws();
            int c = peek();
            return switch (c) {
                case '{' -> object(depth + 1);
                case '[' -> array(depth + 1);
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        yield numberValue(number());
                    }
                    throw err("expected a value");
                }
            };
        }

        private static void checkDepth(int depth) {
            if (depth > Codec.MAX_DEPTH) {
                throw new RDocException(RDocException.NESTING_TOO_DEEP,
                        "nesting deeper than " + Codec.MAX_DEPTH + " levels");
            }
        }

        private List<Object> array(int depth) {
            checkDepth(depth);
            pos++;
            List<Object> items = new ArrayList<>();
            ws();
            if (peek() == ']') {
                pos++;
                return items;
            }
            while (true) {
                items.add(value(depth));
                ws();
                int c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return items;
                } else {
                    throw err("expected ',' or ']'");
                }
            }
        }

        private Object object(int depth) {
            checkDepth(depth);
            pos++;
            RDocument doc = new RDocument();
            ws();
            if (peek() == '}') {
                pos++;
                return doc;
            }
            while (true) {
                ws();
                if (peek() != '"') {
                    throw err("expected a field name");
                }
                String name = string();
                eat(':');
                if (doc.isEmpty() && name.startsWith("$")) {
                    // A `$` name is legal only as the single key of an extended-JSON wrapper.
                    Object v = wrapper(name);
                    eat('}');
                    return v;
                }
                Codec.validateFieldName(name, Codec.utf8(name));
                Object v = value(depth);
                if (doc.containsKey(name)) {
                    throw RDocException.fieldName("duplicate field name");
                }
                doc.put(name, v);
                ws();
                int c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return doc;
                } else {
                    throw err("expected ',' or '}'");
                }
            }
        }

        private String string() {
            pos++; // opening quote
            StringBuilder out = new StringBuilder();
            while (true) {
                int c = peek();
                if (c == -1) {
                    throw err("unterminated string");
                }
                if (c == '"') {
                    pos++;
                    return out.toString();
                }
                if (c == '\\') {
                    pos++;
                    escape(out);
                } else if (c < 0x20) {
                    throw err("control character in string");
                } else {
                    out.append((char) c);
                    pos++;
                }
            }
        }

        private void escape(StringBuilder out) {
            int c = peek();
            if (c == -1) {
                throw err("unterminated escape");
            }
            pos++;
            switch (c) {
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                case '/' -> out.append('/');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    int hi = hex4();
                    if (hi >= 0xD800 && hi < 0xDC00) {
                        if (!s.startsWith("\\u", pos)) {
                            throw err("lone surrogate");
                        }
                        pos += 2;
                        int lo = hex4();
                        if (lo < 0xDC00 || lo >= 0xE000) {
                            throw err("lone surrogate");
                        }
                        out.append((char) hi).append((char) lo);
                    } else if (hi >= 0xDC00 && hi < 0xE000) {
                        throw err("lone surrogate");
                    } else {
                        out.append((char) hi);
                    }
                }
                default -> throw err("invalid escape");
            }
        }

        private int hex4() {
            if (pos + 4 > s.length()) {
                throw err("truncated \\u escape");
            }
            String digits = s.substring(pos, pos + 4);
            if (!ObjectId.isHex(digits)) {
                throw err("bad \\u escape");
            }
            pos += 4;
            return Integer.parseInt(digits, 16);
        }

        /** Scans {@code -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?}. */
        private JsonNumber number() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            int intStart = pos;
            int n = digits();
            if (n == 0 || (n > 1 && s.charAt(intStart) == '0')) {
                throw err("invalid number");
            }
            boolean integral = true;
            if (peek() == '.') {
                pos++;
                integral = false;
                if (digits() == 0) {
                    throw err("invalid number fraction");
                }
            }
            if (peek() == 'e' || peek() == 'E') {
                pos++;
                integral = false;
                if (peek() == '+' || peek() == '-') {
                    pos++;
                }
                if (digits() == 0) {
                    throw err("invalid number exponent");
                }
            }
            return new JsonNumber(s.substring(start, pos), integral);
        }

        private int digits() {
            int from = pos;
            while (peek() >= '0' && peek() <= '9') {
                pos++;
            }
            return pos - from;
        }

        private Object numberValue(JsonNumber n) {
            if (n.integral) {
                try {
                    return Long.parseLong(n.text);
                } catch (NumberFormatException e) {
                    // Beyond int64: nearest float64 below.
                }
            }
            // Double.parseDouble is correctly rounded; out-of-range magnitudes become infinite,
            // which plain JSON cannot mean, so they are rejected.
            double f = Double.parseDouble(n.text);
            if (Double.isInfinite(f)) {
                throw err("number outside the float64 range");
            }
            return f;
        }

        private String wrapperString() {
            ws();
            if (peek() != '"') {
                throw err("expected a string");
            }
            return string();
        }

        private Object wrapper(String key) {
            int at = pos;
            return switch (key) {
                case "$int64" -> {
                    String t = wrapperString();
                    try {
                        yield Long.parseLong(t);
                    } catch (NumberFormatException e) {
                        throw bad(at, key, "not an int64");
                    }
                }
                case "$float" -> parseFloat(at, wrapperString());
                case "$decimal" -> Decimal128.parse(wrapperString());
                case "$date" -> java.time.Instant.ofEpochMilli(IsoDate.parse(wrapperString()));
                case "$oid" -> ObjectId.parse(wrapperString());
                case "$uuid" -> parseUuid(at, wrapperString());
                case "$ts" -> parseTimestamp(at, wrapperString());
                case "$binary" -> binary();
                case "$vector" -> vector();
                case "$minKey", "$maxKey" -> {
                    ws();
                    JsonNumber n = number();
                    if (!n.text.equals("1")) {
                        throw bad(at, key, "expected 1");
                    }
                    yield key.equals("$minKey") ? MinKey.INSTANCE : MaxKey.INSTANCE;
                }
                case "$counter" -> throw RDocException.fieldName(
                        "$counter is a read-only projection, not accepted as input");
                default -> throw RDocException.fieldName("field name starts with '$'");
            };
        }

        private RDocException bad(int at, String key, String reason) {
            return RDocException.invalid("invalid JSON at character " + at + ": " + key + ": "
                    + reason);
        }

        private Double parseFloat(int at, String t) {
            switch (t) {
                case "NaN" -> {
                    return Double.NaN;
                }
                case "Infinity" -> {
                    return Double.POSITIVE_INFINITY;
                }
                case "-Infinity" -> {
                    return Double.NEGATIVE_INFINITY;
                }
                default -> {
                    Parser p = new Parser(t);
                    JsonNumber n;
                    try {
                        n = p.number();
                    } catch (RDocException e) {
                        throw bad(at, "$float", "not a number");
                    }
                    if (p.pos != t.length()) {
                        throw bad(at, "$float", "not a number");
                    }
                    // As in the server, the text parses to the nearest double (inf allowed).
                    return Double.parseDouble(n.text);
                }
            }
        }

        private UUID parseUuid(int at, String t) {
            boolean shape = t.length() == 36 && t.charAt(8) == '-' && t.charAt(13) == '-'
                    && t.charAt(18) == '-' && t.charAt(23) == '-';
            String compact = t.replace("-", "");
            if (!shape || compact.length() != 32 || !ObjectId.isHex(compact)) {
                throw bad(at, "$uuid", "expected 8-4-4-4-12 hex");
            }
            ByteBuffer b = ByteBuffer.wrap(HexFormat.of().parseHex(compact))
                    .order(ByteOrder.BIG_ENDIAN);
            return new UUID(b.getLong(), b.getLong());
        }

        private RTimestamp parseTimestamp(int at, String t) {
            int dot = t.indexOf('.');
            if (dot < 0) {
                throw bad(at, "$ts", "expected wall.logical");
            }
            String w = t.substring(0, dot);
            String l = t.substring(dot + 1);
            if (!allDigits(w) || !allDigits(l)) {
                throw bad(at, "$ts", "expected wall.logical");
            }
            try {
                return new RTimestamp(Long.parseUnsignedLong(w), Integer.parseUnsignedInt(l));
            } catch (NumberFormatException e) {
                throw bad(at, "$ts", "out of range");
            }
        }

        private static boolean allDigits(String t) {
            if (t.isEmpty()) {
                return false;
            }
            for (int i = 0; i < t.length(); i++) {
                if (t.charAt(i) < '0' || t.charAt(i) > '9') {
                    return false;
                }
            }
            return true;
        }

        /** {@code {"base64":"…","subType":"hh"}} in either key order. */
        private RBinary binary() {
            int at = pos;
            eat('{');
            byte[] data = null;
            int subtype = -1;
            for (int i = 0; i < 2; i++) {
                if (i > 0) {
                    eat(',');
                }
                ws();
                if (peek() != '"') {
                    throw bad(at, "$binary", "expected base64 and subType");
                }
                String k = string();
                eat(':');
                String v = wrapperString();
                if (k.equals("base64") && data == null) {
                    data = strictBase64(v);
                    if (data == null) {
                        throw bad(at, "$binary", "invalid base64");
                    }
                } else if (k.equals("subType") && subtype < 0) {
                    if (v.length() != 2 || !ObjectId.isHex(v)) {
                        throw bad(at, "$binary", "subType is 2 hex digits");
                    }
                    subtype = Integer.parseInt(v, 16);
                } else {
                    throw bad(at, "$binary", "expected base64 and subType");
                }
            }
            eat('}');
            return new RBinary(subtype, data);
        }

        /** RFC 4648 base64 with padding and zero unused bits; {@code null} otherwise. */
        private static byte[] strictBase64(String v) {
            if (v.length() % 4 != 0) {
                return null;
            }
            byte[] data;
            try {
                data = Base64.getDecoder().decode(v);
            } catch (IllegalArgumentException e) {
                return null;
            }
            // Re-encoding detects non-zero unused bits and misplaced padding.
            return Base64.getEncoder().encodeToString(data).equals(v) ? data : null;
        }

        /** {@code [n, …]} of numbers, each converted to the nearest finite f32. */
        private RVector vector() {
            eat('[');
            List<Float> xs = new ArrayList<>();
            ws();
            if (peek() == ']') {
                pos++;
                return new RVector(new float[0]);
            }
            while (true) {
                ws();
                JsonNumber n = number();
                float x = Float.parseFloat(n.text);
                if (!Float.isFinite(x)) {
                    throw new RDocException(RDocException.INVALID_VECTOR,
                            "element outside the f32 range");
                }
                xs.add(x);
                ws();
                int c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    float[] out = new float[xs.size()];
                    for (int i = 0; i < out.length; i++) {
                        out[i] = xs.get(i);
                    }
                    return new RVector(out);
                } else {
                    throw err("expected ',' or ']'");
                }
            }
        }
    }

    /** A JSON number with its text (needed for exact int64/float/f32 conversion). */
    private record JsonNumber(String text, boolean integral) {}
}
