// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.mapping.MappingModel.Address;
import io.rustegon.driver.mapping.MappingModel.Customer;
import io.rustegon.driver.mapping.MappingModel.Node;
import io.rustegon.driver.mapping.MappingModel.Order;
import io.rustegon.driver.mapping.MappingModel.Status;
import io.rustegon.driver.rdoc.RCounter;
import io.rustegon.driver.rdoc.RDocReader;
import io.rustegon.driver.rdoc.RDocWriter;
import io.rustegon.driver.rdoc.RDocument;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-022 (FR-DRV-002, java-driver.md §5, PD-111): records and POJOs. Generated codecs
 * and the {@code MethodHandles} mapper write byte-identical RDoc; {@code _id}/{@code _rev},
 * nulls, optionals, ignored and unknown fields follow PD-111.
 */
class RecordPojoMappingTest {
    private static <T> T roundTrip(Class<T> type, T value) {
        byte[] bytes = Samples.sameBytes(type, value);
        RDocument doc = RDocReader.decode(bytes);
        T generated = Mapper.codec(type).decode(doc, "");
        T reflective = Mapper.reflective(type).decode(doc, "");
        // Decoding is identical as well: both re-encode to the same bytes.
        assertArrayEquals(bytes, RDocWriter.encode(Mapper.codec(type).encode(generated)));
        assertArrayEquals(bytes, RDocWriter.encode(Mapper.codec(type).encode(reflective)));
        return generated;
    }

    @Test
    void tc_drv_java_022_record_round_trip_generated_equals_method_handles() {
        Order o = Samples.order();
        Order back = roundTrip(Order.class, o);
        assertEquals(o.orderId(), back.orderId());
        assertEquals(o.status(), back.status());
        assertEquals(o.tags(), back.tags());
        assertEquals(o.addresses(), back.addresses());
        assertEquals(o.scores(), back.scores());
        assertEquals(o.comment(), back.comment());
        assertEquals(Optional.empty(), back.billing());
        assertArrayEquals(o.embedding(), back.embedding());
        assertArrayEquals(o.location(), back.location());
        assertEquals(List.of(List.of(1, 2), List.of()), back.matrix());
        assertNull(back.transientNote(), "@RgnIgnore is not stored");
        assertNull(back.rev(), "_rev is never written");
        assertNull(back.views(), "counters are never written");
    }

    @Test
    void tc_drv_java_022_document_layout() {
        RDocument doc = Mapper.codec(Order.class).encode(Samples.order());
        List<String> keys = new ArrayList<>(doc.keySet());
        assertEquals("_id", keys.get(0));
        assertFalse(doc.containsKey("_rev"));
        assertFalse(doc.containsKey("views"));
        assertFalse(doc.containsKey("transientNote"));
        assertFalse(doc.containsKey("billing"), "empty Optional is omitted");
        assertTrue(doc.containsKey("note") && doc.get("note") == null, "null is written");
        assertEquals("PAID", doc.get("status"));
        assertEquals(RDocument.of("street", "Via Roma 1").append("city", "Padova")
                .append("zip", "35100"), doc.get("shipping"));
        assertEquals(RDocument.of("type", "Point").append("coordinates", List.of(11.87, 45.41)),
                doc.get("location"));
    }

    @Test
    void tc_drv_java_022_id_rev_counter_and_unknown_fields_on_read() {
        RDocument doc = Mapper.codec(Order.class).encode(Samples.order());
        doc.put("_rev", "0123456789abcdefghij");
        doc.put("_createdAt", java.time.Instant.EPOCH);
        doc.put("views", new RCounter(42));
        doc.put("somethingNew", List.of(1L));
        Order back = Mapper.codec(Order.class).decode(doc, "");
        assertEquals("0123456789abcdefghij", back.rev());
        assertEquals(42L, back.views());
        assertEquals(back.rev(), Mapper.reflective(Order.class).decode(doc, "").rev());
    }

    @Test
    void tc_drv_java_022_null_id_is_omitted_and_missing_fields_get_defaults() {
        Address a = new Address(null, null, null);
        assertEquals(RDocument.of("street", null).append("city", null).append("zip", null),
                Mapper.codec(Address.class).encode(a));
        Customer c = new Customer();
        c.name = "Ada";
        RDocument doc = Mapper.codec(Customer.class).encode(c);
        assertFalse(doc.containsKey("_id"), "a null _id lets the server generate one");
        Samples.sameBytes(Customer.class, c);

        Customer empty = Mapper.codec(Customer.class).decode(new RDocument(), "");
        assertEquals(0, empty.getAge());
        assertFalse(empty.isVip());
        assertEquals(Optional.empty(), empty.nickname);
        RDocument nullAge = RDocument.of("age", null);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Mapper.codec(Customer.class).decode(nullAge, ""));
        assertTrue(e.getMessage().contains("age: null for a primitive"), e.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> Mapper.reflective(Customer.class).decode(nullAge, ""));
    }

    @Test
    void tc_drv_java_022_pojo_round_trip() {
        Customer c = new Customer();
        c.id = "c1";
        c.name = "Ada";
        c.setAge(36);
        c.setVip(true);
        c.cache = "transient";
        c.ignored = "ignored";
        c.nickname = Optional.of("ada");
        c.history = List.of(Status.NEW, Status.SHIPPED);
        RDocument doc = Mapper.codec(Customer.class).encode(c);
        assertEquals(List.of("_id", "name", "age", "vip", "nickname", "history"),
                new ArrayList<>(doc.keySet()));
        Customer back = roundTrip(Customer.class, c);
        assertEquals("c1", back.id);
        assertEquals(36, back.getAge());
        assertTrue(back.isVip());
        assertNull(back.cache);
        assertNull(back.ignored);
        assertEquals(Optional.of("ada"), back.nickname);
        assertEquals(c.history, back.history);
    }

    @Test
    void tc_drv_java_022_recursive_types() {
        Node tree = new Node("root", List.of(new Node("a", List.of()), new Node("b",
                List.of(new Node("c", null)))));
        assertEquals(tree, roundTrip(Node.class, tree));
    }
}
