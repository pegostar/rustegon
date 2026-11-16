// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.rustegon.driver.Cursor;
import io.rustegon.driver.DropOptions;
import io.rustegon.driver.Filters;
import io.rustegon.driver.Params;
import io.rustegon.driver.ReplaceOptions;
import io.rustegon.driver.RustegonClient;
import io.rustegon.driver.RustegonCollection;
import io.rustegon.driver.RustegonDatabase;
import io.rustegon.driver.RustegonException;
import io.rustegon.driver.Sorts;
import io.rustegon.driver.UpdateOptions;
import io.rustegon.driver.Updates;
import io.rustegon.driver.mapping.MappingModel.Address;
import io.rustegon.driver.mapping.MappingModel.Circle;
import io.rustegon.driver.mapping.MappingModel.Drawing;
import io.rustegon.driver.mapping.MappingModel.Product;
import io.rustegon.driver.mapping.MappingModel.Rect;
import io.rustegon.driver.mapping.MappingModel.Status;
import io.rustegon.driver.testing.RustegonTestServer;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-022 / TC-DRV-JAVA-024, against a real {@code rustegond} (PD-072 fixture,
 * {@code RUSTEGON_BIN_DIR}; skipped without the binaries, fails under {@code CI=true}): typed
 * collection handles ({@code collection(name, Class<T>)}, the transaction equivalent and
 * {@code query(..., Class<T>)}) insert, read, filter with metamodel paths, update with
 * {@code ifRev} from an {@link RgnRev} property, replace and delete mapped records.
 */
@Tag("integration")
class MappingIntegrationTest {
    private static final Instant CREATED = Instant.parse("2026-11-12T08:00:00.123Z");

    @Test
    void tc_drv_java_022_typed_crud_against_rustegond() {
        RustegonTestServer server = RustegonTestServer.shared();
        try (RustegonClient client = RustegonClient.create(server.adminSettings().build())) {
            client.dropDatabase("mapping_it", DropOptions.whenExists());
            client.createDatabase("mapping_it");
            RustegonDatabase db = client.database("mapping_it");
            db.createCollection("products");
            RustegonCollection<Product> products = db.collection("products", Product.class);

            Product p1 = new Product("p1", null, "Bolt", new BigDecimal("0.25"), Status.NEW,
                    CREATED, List.of("hw", "small"), Optional.empty(), Samples.HOME);
            Product p2 = new Product("p2", null, "Nut", new BigDecimal("0.10"), Status.PAID,
                    CREATED, List.of("hw"), Optional.of("M8"), null);
            assertEquals("p1", products.insertOne(p1).insertedId());
            products.insertMany(List.of(p2));

            Product read = products.findById("p1").orElseThrow();
            assertNotNull(read.rev(), "_rev is read into the @RgnRev property");
            assertEquals(new Product("p1", read.rev(), "Bolt", new BigDecimal("0.25"),
                    Status.NEW, CREATED, List.of("hw", "small"), Optional.empty(),
                    Samples.HOME), read);

            // Filters keep string paths; the generated metamodel names them.
            List<Product> paid = products.find(Filters.eq(MappingModel_Product_.status, "PAID"))
                    .toList();
            assertEquals(List.of("p2"), paid.stream().map(Product::sku).toList());
            assertEquals(Optional.of("M8"), paid.get(0).description());
            assertEquals(List.of("p1", "p2"), products.find().sort(Sorts.asc(
                    MappingModel_Product_.sku)).toList().stream().map(Product::sku).toList());

            // Optimistic concurrency through the mapped revision.
            products.updateOne(Filters.id("p1"), Updates.set(MappingModel_Product_.status,
                    "SHIPPED"), UpdateOptions.ifRev(read.rev()));
            assertThrows(RustegonException.class, () -> products.updateOne(Filters.id("p1"),
                    Updates.set("name", "x"), UpdateOptions.ifRev(read.rev())));
            Product shipped = products.findById("p1").orElseThrow();
            assertEquals(Status.SHIPPED, shipped.status());

            Product renamed = new Product("p1", null, "Bolt M6", shipped.price(),
                    shipped.status(), CREATED, List.of(), Optional.of("zinc"), new Address(
                            "Via Po 2", "Torino", "10100"));
            products.replaceOne(Filters.id("p1"), renamed, ReplaceOptions.ifRev(shipped.rev()));
            Product replaced = products.findById("p1").orElseThrow();
            assertEquals("Bolt M6", replaced.name());
            assertEquals(Optional.of("zinc"), replaced.description());
            assertEquals("Torino", replaced.origin().city());

            // Typed RGQL rows and a typed handle inside a transaction.
            try (Cursor<Product> c = db.query("FROM products WHERE price < $max",
                    Params.of("max", new BigDecimal("0.2")), Product.class)) {
                List<String> skus = new java.util.ArrayList<>();
                c.forEach(x -> skus.add(x.sku()));
                assertEquals(List.of("p2"), skus);
            }
            String name = client.withTransaction(txn -> {
                RustegonCollection<Product> t = txn.collection("mapping_it.products",
                        Product.class);
                Product n = t.findById("p2").orElseThrow();
                t.deleteOne(Filters.id("p2"));
                return n.name();
            });
            assertEquals("Nut", name);
            assertFalse(products.findById("p2").isPresent());

            // A sealed hierarchy stored and read back.
            db.createCollection("drawings");
            RustegonCollection<Drawing> drawings = db.collection("drawings", Drawing.class);
            Drawing d = new Drawing("d1", List.of(new Circle(2), new Rect("r", 1, 2)),
                    new Circle(1), Optional.of(new MappingModel.Dog("Rex")));
            drawings.insertOne(d);
            assertEquals(d, drawings.findById("d1").orElseThrow());
            assertEquals(List.of("d1"), drawings.find(Filters.eq("main.kind", "circle")).toList()
                    .stream().map(Drawing::id).toList());

            // A record without an id: the server generates the _id; unknown fields are ignored.
            db.createCollection("nodes");
            RustegonCollection<MappingModel.Node> nodes = db.collection("nodes",
                    MappingModel.Node.class);
            Object id = nodes.insertOne(new MappingModel.Node("root", List.of())).insertedId();
            assertNotNull(id, "the server generates the omitted _id");
            assertEquals("root", nodes.findById(id).orElseThrow().name());
            client.dropDatabase("mapping_it");
        }
    }
}
