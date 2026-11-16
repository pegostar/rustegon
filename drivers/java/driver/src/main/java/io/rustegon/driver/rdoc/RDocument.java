// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A schemaless document: an insertion-ordered {@code Map<String, Object>} (java-driver.md §5).
 *
 * <p>Field order is part of a document (data-model.md §4), so iteration follows insertion order;
 * {@link #equals} is the {@link Map} contract (order-insensitive) — compare {@link #toJson()} or
 * the RDoc bytes for an order-sensitive check.
 *
 * <p>Value types when read (decoded or parsed): {@code null}, {@link Boolean}, {@link Long}
 * (int64), {@link Double} (float64), {@link Decimal128}, {@link String}, {@link RBinary},
 * {@link java.time.Instant} (datetime, millisecond precision), {@link RTimestamp},
 * {@link ObjectId}, {@link java.util.UUID}, {@link java.util.List} (array), {@code RDocument}
 * (object), {@link RVector}, {@link RCounter}, {@link MinKey}, {@link MaxKey}. When written, these
 * plus {@link Integer}/{@link Short}/{@link Byte} (int64), {@link Float} (float64),
 * {@link java.math.BigDecimal} (decimal128, at most 34 digits), {@code byte[]} (generic binary),
 * {@code float[]} (vector), {@link java.time.OffsetDateTime} and
 * {@link java.time.ZonedDateTime} (datetime; sub-millisecond digits are truncated), any
 * {@link Map} with string keys and any {@link java.util.Collection} are accepted.
 */
public final class RDocument extends LinkedHashMap<String, Object> {
    private static final long serialVersionUID = 1L;

    /** An empty document. */
    public RDocument() {
        super();
    }

    /**
     * A document with the entries of {@code fields}, in its iteration order.
     *
     * @param fields the fields to copy
     */
    public RDocument(Map<String, ?> fields) {
        super(fields);
    }

    /**
     * A one-field document.
     *
     * @param name the field name
     * @param value the value
     * @return the document
     */
    public static RDocument of(String name, Object value) {
        return new RDocument().append(name, value);
    }

    /**
     * Adds (or replaces) a field and returns this document, for chaining.
     *
     * @param name the field name
     * @param value the value
     * @return this document
     */
    public RDocument append(String name, Object value) {
        put(name, value);
        return this;
    }

    /**
     * Parses a JSON object (canonical or extended JSON, data-model.md §2).
     *
     * @param json the text
     * @return the document
     * @throws RDocException on invalid JSON or values
     */
    public static RDocument parse(String json) {
        return ExtendedJson.parseDocument(json);
    }

    /**
     * Canonical JSON (compact, fields in order, plain numbers where lossless).
     *
     * @return the JSON text
     * @throws RDocException if a value is not representable
     */
    public String toJson() {
        return ExtendedJson.toJson(this, JsonMode.CANONICAL);
    }

    /**
     * JSON in the given mode.
     *
     * @param mode canonical or extended
     * @return the JSON text
     * @throws RDocException if a value is not representable
     */
    public String toJson(JsonMode mode) {
        return ExtendedJson.toJson(this, mode);
    }

    /**
     * Canonical RDoc v1 bytes ({@link RDocWriter#encode(Map)}).
     *
     * @return the encoded document
     * @throws RDocException if the document breaks a limit or holds an invalid value
     */
    public byte[] toRDoc() {
        return RDocWriter.encode(this);
    }

    /**
     * Decodes RDoc v1 bytes ({@link RDocReader#decode(byte[])}).
     *
     * @param rdoc the bytes
     * @return the document
     * @throws RDocException on malformed input
     */
    public static RDocument fromRDoc(byte[] rdoc) {
        return RDocReader.decode(rdoc);
    }
}
