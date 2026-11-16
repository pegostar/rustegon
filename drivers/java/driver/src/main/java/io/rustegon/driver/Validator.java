// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Objects;

/**
 * A collection validator (data-model.md §5): a JSON Schema checked on every write.
 *
 * @param jsonSchema the schema as JSON text (sent wrapped as the {@code $jsonSchema} member)
 * @param level which writes are checked ({@code null} = the server default, strict)
 * @param action what a violation does ({@code null} = the server default, error)
 */
public record Validator(String jsonSchema, Level level, Action action) {
    /** Which writes are validated. */
    public enum Level {
        /** None. */
        OFF,
        /** Every insert and update. */
        STRICT,
        /** Updates of documents that were valid. */
        MODERATE
    }

    /** What a violation does. */
    public enum Action {
        /** Reject the write (RGN-1006). */
        ERROR,
        /** Accept it with a warning. */
        WARN
    }

    /**
     * Checks the schema text is present.
     *
     * @param jsonSchema the schema
     * @param level the level
     * @param action the action
     */
    public Validator {
        Objects.requireNonNull(jsonSchema, "jsonSchema");
    }

    /**
     * A validator with the server's default level and action.
     *
     * @param jsonSchema the schema as JSON text
     * @return the validator
     */
    public static Validator of(String jsonSchema) {
        return new Validator(jsonSchema, null, null);
    }
}
