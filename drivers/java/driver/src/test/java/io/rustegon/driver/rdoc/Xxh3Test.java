// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import net.openhft.hashing.LongHashFunction;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-001: the hand-written XXH3-64 (field-name hash of data-model.md §4) equals an
 * independent implementation ({@code zero-allocation-hashing}, test scope only) on every path
 * of the algorithm: lengths 0–2048 cover the 0, 1–3, 4–8, 9–16, 17–128, 129–240 and long
 * (stripes, full blocks, block remainders) cases. The RDoc fixtures (TC-DRV-JAVA-001) pin the
 * server's actual hashes.
 */
class Xxh3Test {
    private static final LongHashFunction REFERENCE = LongHashFunction.xx3();

    @Test
    void tc_drv_java_001_matches_the_reference_for_every_length() {
        Random random = new Random(20261109L);
        for (int len = 0; len <= 2048; len++) {
            byte[] data = new byte[len];
            random.nextBytes(data);
            assertEquals(REFERENCE.hashBytes(data), Xxh3.hash64(data, 0, len), "length " + len);
            // Pattern of the twox-hash tests: i % 251.
            for (int i = 0; i < len; i++) {
                data[i] = (byte) (i % 251);
            }
            assertEquals(REFERENCE.hashBytes(data), Xxh3.hash64(data, 0, len), "length " + len);
        }
    }

    @Test
    void tc_drv_java_001_hashes_slices_and_large_inputs() {
        Random random = new Random(7);
        byte[] big = new byte[70_000];
        random.nextBytes(big);
        for (int off : new int[] {0, 1, 13, 1000}) {
            for (int len : new int[] {0, 5, 200, 1024, 3071, 3072, 3073, 65_536}) {
                assertEquals(REFERENCE.hashBytes(big, off, len), Xxh3.hash64(big, off, len),
                        off + "+" + len);
            }
        }
    }

    @Test
    void tc_drv_java_001_name_hash_is_the_low_16_bits() {
        byte[] name = "_id".getBytes(StandardCharsets.UTF_8);
        assertEquals(REFERENCE.hashBytes(name) & 0xFFFF, Xxh3.nameHash16(name));
    }
}
