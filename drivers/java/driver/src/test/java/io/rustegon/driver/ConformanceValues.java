// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.rdoc.Decimal128;
import io.rustegon.driver.rdoc.ExtendedJson;
import io.rustegon.driver.rdoc.JsonMode;
import io.rustegon.driver.rdoc.ObjectId;
import io.rustegon.driver.rdoc.RBinary;
import io.rustegon.driver.rdoc.RDocException;
import io.rustegon.driver.rdoc.RDocument;
import io.rustegon.driver.rdoc.RTimestamp;
import io.rustegon.driver.rdoc.RVector;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

/**
 * Values and matching of the conformance suite (drivers/conformance/README.md §5): YAML (or
 * JSON) nodes become driver values (a YAML integer is int64, a float is float64, {@code $}
 * wrappers are canonical extended JSON), placeholders ({@code $$any}, {@code $$type},
 * {@code $$ref}) are resolved, and results are compared {@code exact} or {@code subset} with
 * the normalisation of §5.
 */
final class ConformanceValues {
    /** {@code "$$any"}: matches any value. */
    static final Object ANY = new Object() {
        @Override
        public String toString() {
            return "$$any";
        }
    };

    /** {@code {"$$type": name}}. */
    record TypeOf(String type) {}

    /** Server-maintained fields dropped before comparing unless the expectation names them. */
    private static final Set<String> SYSTEM_FIELDS = Set.of("_rev", "_createdAt", "_updatedAt");

    private ConformanceValues() {}

    @SuppressWarnings("unchecked")
    static <T> T load(Path file) throws IOException {
        return (T) new Load(LoadSettings.builder().build()).loadFromString(Files.readString(file));
    }

    /**
     * A YAML node as a driver value. {@code refs} resolves {@code $$ref:name[.path]};
     * {@code substitute} replaces {@code ${…}} in strings.
     */
    @SuppressWarnings("unchecked")
    static Object value(Object y, Function<String, Object> refs, Function<String, String> substitute) {
        if (y == null || y instanceof Boolean) {
            return y;
        }
        if (y instanceof Integer || y instanceof Long || y instanceof Short) {
            return ((Number) y).longValue();
        }
        if (y instanceof BigInteger b) {
            throw new IllegalArgumentException("integer beyond int64 in the suite: " + b);
        }
        if (y instanceof Double || y instanceof Float) {
            return ((Number) y).doubleValue();
        }
        if (y instanceof String s) {
            if (s.equals("$$any")) {
                return ANY;
            }
            if (s.startsWith("$$ref:")) {
                return refs.apply(s.substring("$$ref:".length()));
            }
            return substitute.apply(s);
        }
        if (y instanceof List<?> l) {
            List<Object> out = new ArrayList<>(l.size());
            for (Object e : l) {
                out.add(value(e, refs, substitute));
            }
            return out;
        }
        Map<String, Object> m = (Map<String, Object>) y;
        if (m.size() == 1) {
            String k = m.keySet().iterator().next();
            if (k.equals("$$type")) {
                return new TypeOf((String) m.get(k));
            }
            if (k.startsWith("$")) {
                try {
                    return ExtendedJson.parseValue(json(m));
                } catch (RDocException e) {
                    // Not a wrapper ({"$set": 1}): a document with that field name, which the
                    // codec or the server must reject (TC-DRV-CONF-CRUD-008).
                }
            }
        }
        RDocument d = new RDocument();
        m.forEach((k, v) -> d.put(k, value(v, refs, substitute)));
        return d;
    }

    /** A YAML node as JSON text (for extended-JSON wrappers). */
    static String json(Object y) {
        StringBuilder s = new StringBuilder();
        writeJson(y, s);
        return s.toString();
    }

    private static void writeJson(Object y, StringBuilder s) {
        if (y == null || y instanceof Boolean || y instanceof Number) {
            s.append(y);
        } else if (y instanceof String str) {
            s.append('"');
            for (char c : str.toCharArray()) {
                if (c == '"' || c == '\\') {
                    s.append('\\').append(c);
                } else if (c < 0x20) {
                    s.append(String.format("\\u%04x", (int) c));
                } else {
                    s.append(c);
                }
            }
            s.append('"');
        } else if (y instanceof List<?> l) {
            s.append('[');
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) {
                    s.append(',');
                }
                writeJson(l.get(i), s);
            }
            s.append(']');
        } else {
            s.append('{');
            Iterator<? extends Map.Entry<?, ?>> it = ((Map<?, ?>) y).entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<?, ?> e = it.next();
                writeJson(String.valueOf(e.getKey()), s);
                s.append(':');
                writeJson(e.getValue(), s);
                if (it.hasNext()) {
                    s.append(',');
                }
            }
            s.append('}');
        }
    }

    /** data-model.md §2 type name of a value. */
    static String typeName(Object v) {
        if (v == null) {
            return "null";
        }
        if (v instanceof Boolean) {
            return "bool";
        }
        if (v instanceof Long || v instanceof Integer) {
            return "int64";
        }
        if (v instanceof Double) {
            return "float64";
        }
        if (v instanceof Decimal128) {
            return "decimal128";
        }
        if (v instanceof String) {
            return "string";
        }
        if (v instanceof RBinary) {
            return "binary";
        }
        if (v instanceof Instant) {
            return "datetime";
        }
        if (v instanceof RTimestamp) {
            return "timestamp";
        }
        if (v instanceof ObjectId) {
            return "objectId";
        }
        if (v instanceof UUID) {
            return "uuid";
        }
        if (v instanceof RVector) {
            return "vector_f32";
        }
        if (v instanceof List) {
            return "array";
        }
        if (v instanceof Map) {
            return "object";
        }
        return v.getClass().getSimpleName();
    }

    /** Canonical extended JSON of a scalar: equal texts mean equal value and type. */
    static String scalar(Object v) {
        Object x = v instanceof Integer i ? Long.valueOf(i) : v;
        return ExtendedJson.valueToJson(x, JsonMode.CANONICAL);
    }

    /**
     * Compares {@code actual} with {@code expected}.
     *
     * @param subset extra document fields allowed
     * @param ordered lists compared in order (top level only when {@code false})
     * @param fieldOrder document field order compared
     * @return {@code null} when they match, else the first difference
     */
    static String mismatch(Object expected, Object actual, boolean subset, boolean ordered,
            boolean fieldOrder) {
        return compare(expected, actual, subset, ordered, fieldOrder, "$", true);
    }

    private static String compare(Object e, Object a, boolean subset, boolean ordered,
            boolean fieldOrder, String at, boolean top) {
        if (e == ANY) {
            return null;
        }
        if (e instanceof TypeOf t) {
            return t.type().equals(typeName(a)) ? null
                    : at + ": expected a " + t.type() + ", got " + describe(a);
        }
        if (e instanceof Map<?, ?> em) {
            if (!(a instanceof Map<?, ?> am)) {
                return at + ": expected a document, got " + describe(a);
            }
            List<Object> actualKeys = new ArrayList<>();
            for (Object k : am.keySet()) {
                if (!SYSTEM_FIELDS.contains(k) || em.containsKey(k)) {
                    actualKeys.add(k);
                }
            }
            for (Map.Entry<?, ?> f : em.entrySet()) {
                if (!am.containsKey(f.getKey())) {
                    return at + "." + f.getKey() + ": missing";
                }
                String d = compare(f.getValue(), am.get(f.getKey()), subset, true, fieldOrder,
                        at + "." + f.getKey(), false);
                if (d != null) {
                    return d;
                }
            }
            if (!subset && actualKeys.size() != em.size()) {
                actualKeys.removeAll(em.keySet());
                return at + ": unexpected fields " + actualKeys;
            }
            if (fieldOrder && !subset && !actualKeys.equals(new ArrayList<>(em.keySet()))) {
                return at + ": field order " + actualKeys + ", expected " + em.keySet();
            }
            return null;
        }
        if (e instanceof List<?> el) {
            if (!(a instanceof List<?> al)) {
                return at + ": expected an array, got " + describe(a);
            }
            if (!ordered && top) {
                return multiset(el, al, subset, fieldOrder, at);
            }
            if (el.size() != al.size()) {
                return at + ": " + al.size() + " elements, expected " + el.size() + " (got "
                        + describe(a) + ")";
            }
            for (int i = 0; i < el.size(); i++) {
                String d = compare(el.get(i), al.get(i), subset, true, fieldOrder,
                        at + "[" + i + "]", false);
                if (d != null) {
                    return d;
                }
            }
            return null;
        }
        if (e == null || a == null) {
            return e == a ? null : at + ": expected " + describe(e) + ", got " + describe(a);
        }
        if (a instanceof Map || a instanceof List) {
            return at + ": expected " + describe(e) + ", got " + describe(a);
        }
        return scalar(e).equals(scalar(a)) ? null
                : at + ": expected " + scalar(e) + ", got " + scalar(a);
    }

    /**
     * Unordered top-level lists: the same length (README §5, also under {@code subset}) and
     * every expected element matches a distinct actual one.
     */
    private static String multiset(List<?> expected, List<?> actual, boolean subset,
            boolean fieldOrder, String at) {
        if (expected.size() != actual.size()) {
            return at + ": " + actual.size() + " elements, expected " + expected.size()
                    + " (got " + describe(actual) + ")";
        }
        List<Object> left = new ArrayList<>(actual);
        for (Object e : expected) {
            boolean found = false;
            for (Iterator<Object> it = left.iterator(); it.hasNext(); ) {
                if (compare(e, it.next(), subset, true, fieldOrder, at, false) == null) {
                    it.remove();
                    found = true;
                    break;
                }
            }
            if (!found) {
                return at + ": no element matches " + describe(e) + " in " + describe(actual);
            }
        }
        return null;
    }

    static String describe(Object v) {
        if (v == null) {
            return "null";
        }
        if (v instanceof Map<?, ?> m) {
            try {
                return ExtendedJson.toJson(m, JsonMode.CANONICAL);
            } catch (RuntimeException ex) {
                return m.toString(); // holds placeholders
            }
        }
        if (v instanceof List<?> l) {
            List<String> parts = new ArrayList<>();
            for (Object x : l) {
                parts.add(describe(x));
            }
            return parts.toString();
        }
        if (v == ANY || v instanceof TypeOf) {
            return v.toString();
        }
        try {
            return scalar(v);
        } catch (RuntimeException ex) {
            return String.valueOf(v);
        }
    }
}
