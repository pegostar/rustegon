// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

/**
 * A {@code counter} projection (data-model.md §2, type tag 0x0F, §10): appears in documents
 * returned by the server; it is a read-only projection, so JSON input rejects
 * {@code {"$counter":…}} and the server rejects it in written documents.
 *
 * @param value the counter value
 */
public record RCounter(long value) {}
