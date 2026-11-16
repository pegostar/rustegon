// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.samples.model;

import io.rustegon.driver.mapping.RgnId;
import io.rustegon.driver.mapping.RgnRev;
import io.rustegon.driver.mapping.RustegonDocument;
import java.math.BigDecimal;
import java.time.Instant;

/**
 * An order: rustegon-processor generates {@code Order_RgnCodec} and the metamodel
 * {@code Order_} (java-driver.md §3, §5).
 *
 * @param id the document id ({@code _id})
 * @param rev the revision ({@code _rev}, read only)
 * @param status the status
 * @param total the total
 * @param createdAt the creation time
 */
@RustegonDocument
public record Order(@RgnId String id, @RgnRev String rev, String status, BigDecimal total,
        Instant createdAt) {}
