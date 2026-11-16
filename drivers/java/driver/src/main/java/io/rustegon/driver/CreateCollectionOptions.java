// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@code createCollection}.
 *
 * @param ifNotExists succeed (with {@code false}) when the collection exists
 * @param validator the document validator, or {@code null}
 */
public record CreateCollectionOptions(boolean ifNotExists, Validator validator) {
    /**
     * No validator; fail when the collection exists (RGN-1031).
     *
     * @return the options
     */
    public static CreateCollectionOptions defaults() {
        return new CreateCollectionOptions(false, null);
    }

    /**
     * These options, succeeding when the collection exists.
     *
     * @return the options
     */
    public CreateCollectionOptions whenMissing() {
        return new CreateCollectionOptions(true, validator);
    }

    /**
     * These options with a validator.
     *
     * @param v the validator
     * @return the options
     */
    public CreateCollectionOptions withValidator(Validator v) {
        return new CreateCollectionOptions(ifNotExists, v);
    }
}
