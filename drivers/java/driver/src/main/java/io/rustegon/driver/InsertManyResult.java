// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Result of {@code insertMany}.
 *
 * @param insertedIds the ids, in input order
 */
public record InsertManyResult(List<Object> insertedIds) {
    /**
     * Copies the list.
     *
     * @param insertedIds the ids
     */
    public InsertManyResult {
        insertedIds = Collections.unmodifiableList(new ArrayList<>(insertedIds));
    }
}
