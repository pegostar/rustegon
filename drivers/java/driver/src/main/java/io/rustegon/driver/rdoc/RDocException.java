// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

/**
 * A value cannot be encoded, decoded or parsed: malformed RDoc bytes or JSON, a limit exceeded,
 * an invalid field name or vector (data-model.md §2, §4).
 *
 * <p>It carries the error code the server would report for the same input, so client-side and
 * server-side rejections are comparable: {@link #INVALID_ARGUMENT} (malformed input),
 * {@link #DOCUMENT_TOO_LARGE}, {@link #NESTING_TOO_DEEP}, {@link #INVALID_FIELD_NAME} and
 * {@link #INVALID_VECTOR}. It is an {@link IllegalArgumentException}: the input is wrong.
 */
public final class RDocException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    /** RGN-1001: malformed bytes or text. */
    public static final int INVALID_ARGUMENT = 1001;
    /** RGN-1002: the encoded document exceeds 16 MiB. */
    public static final int DOCUMENT_TOO_LARGE = 1002;
    /** RGN-1003: nesting deeper than 100 levels. */
    public static final int NESTING_TOO_DEEP = 1003;
    /** RGN-1004: a field name breaks data-model.md §2.2, or duplicates another one. */
    public static final int INVALID_FIELD_NAME = 1004;
    /** RGN-1040: a vector element is not finite. */
    public static final int INVALID_VECTOR = 1040;

    /** The error code (one of the constants of this class). */
    private final int code;

    /**
     * Creates the exception.
     *
     * @param code one of the code constants of this class
     * @param message reason (never contains document contents)
     */
    public RDocException(int code, String message) {
        super(message);
        this.code = code;
    }

    /**
     * The Rustegon error code of the rejection.
     *
     * @return the code, e.g. {@link #INVALID_FIELD_NAME}
     */
    public int code() {
        return code;
    }

    static RDocException malformed(long at, String reason) {
        return new RDocException(INVALID_ARGUMENT, "malformed RDoc at byte " + at + ": " + reason);
    }

    static RDocException invalid(String reason) {
        return new RDocException(INVALID_ARGUMENT, reason);
    }

    static RDocException fieldName(String reason) {
        return new RDocException(INVALID_FIELD_NAME, reason);
    }
}
