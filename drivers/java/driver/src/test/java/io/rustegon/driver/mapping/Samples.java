// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import io.rustegon.driver.mapping.MappingModel.Address;
import io.rustegon.driver.mapping.MappingModel.Order;
import io.rustegon.driver.mapping.MappingModel.Status;
import io.rustegon.driver.rdoc.ObjectId;
import io.rustegon.driver.rdoc.RDocWriter;
import io.rustegon.driver.rdoc.RDocument;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Sample values and the generated-vs-run-time comparison shared by the mapping tests. */
final class Samples {
    private Samples() {}

    static final Address HOME = new Address("Via Roma 1", "Padova", "35100");

    static Order order() {
        Map<String, Long> scores = new LinkedHashMap<>();
        scores.put("b", 2L);
        scores.put("a", null);
        return new Order("o-1", "ignored-rev", Status.PAID, 7L, -3, (short) 12, 19.5, 0.25f, true,
                Long.MIN_VALUE, Integer.MAX_VALUE, Short.MIN_VALUE, -0.0, 1.5f, false, null,
                new BigDecimal("12.50"), new byte[] {1, 2, 3},
                Instant.parse("2026-11-12T10:15:30.123456789Z"),
                OffsetDateTime.of(2026, 1, 2, 3, 4, 5, 999_999, ZoneOffset.ofHours(2)),
                ZonedDateTime.of(2025, 6, 1, 0, 0, 0, 0, ZoneId.of("Europe/Rome")),
                UUID.fromString("0190e3c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f"),
                ObjectId.parse("6553f0a1b2c3d4e5f6a7b8c9"), new float[] {1f, 2f, 3f},
                new float[] {0.5f}, new double[] {11.87, 45.41}, List.of("x", "y"),
                List.of(HOME, new Address(null, "Roma", "00100")), scores,
                Map.of("home", HOME), Optional.of("fragile"), Optional.empty(), HOME,
                RDocument.of("free", 1L), List.of(1L, "two"), "not stored", 99L,
                List.of(List.of(1, 2), List.of()));
    }

    /** RDoc bytes of {@code value} through the generated and the run-time codec. */
    static <T> byte[] sameBytes(Class<T> type, T value) {
        byte[] generated = RDocWriter.encode(Mapper.codec(type).encode(value));
        byte[] reflective = RDocWriter.encode(Mapper.reflective(type).encode(value));
        assertArrayEquals(generated, reflective, "generated and MethodHandles codecs differ");
        return generated;
    }
}
