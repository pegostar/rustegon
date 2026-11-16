// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import io.rustegon.driver.rdoc.ObjectId;
import io.rustegon.driver.rdoc.RDocument;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The mapped test model of TC-DRV-JAVA-021…025, compiled with {@code rustegon-processor}: every
 * annotated type (and every type they use) has a generated {@code MappingModel_<Name>_RgnCodec}
 * and metamodel {@code MappingModel_<Name>_}.
 */
final class MappingModel {
    private MappingModel() {}

    enum Status { NEW, PAID, SHIPPED }

    /** Nested document, renamed field. Not annotated: generated because Order uses it. */
    record Address(String street, String city, @RgnField("zip") String postalCode) {}

    /** Every type of java-driver.md §5 plus the property annotations. */
    @RustegonDocument
    record Order(
            @RgnId String orderId,
            @RgnRev String rev,
            Status status,
            long qty,
            int count,
            short small,
            double price,
            float ratio,
            boolean paid,
            Long boxedLong,
            Integer boxedInt,
            Short boxedShort,
            Double boxedDouble,
            Float boxedFloat,
            Boolean boxedBool,
            String note,
            BigDecimal total,
            byte[] blob,
            Instant createdAt,
            OffsetDateTime shippedAt,
            ZonedDateTime zoned,
            UUID ref,
            ObjectId oid,
            @RgnVector(3) float[] embedding,
            float[] anyVector,
            @RgnGeoPoint double[] location,
            List<String> tags,
            List<Address> addresses,
            Map<String, Long> scores,
            Map<String, Address> byName,
            Optional<String> comment,
            Optional<Address> billing,
            Address shipping,
            RDocument extra,
            Object anything,
            @RgnIgnore String transientNote,
            @RgnCounter Long views,
            List<List<Integer>> matrix) {}

    /** Superclass fields of a POJO come first. */
    static class Base {
        String id;
    }

    /** A POJO: package-private, private-with-accessors, transient and ignored fields. */
    @RustegonDocument
    static class Customer extends Base {
        String name;
        private int age;
        private boolean vip;
        transient String cache;
        @RgnIgnore
        String ignored;
        Optional<String> nickname = Optional.empty();
        List<Status> history;

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }

        public boolean isVip() {
            return vip;
        }

        public void setVip(boolean vip) {
            this.vip = vip;
        }
    }

    /** A sealed hierarchy with a custom discriminator field; Polygon is flattened. */
    @RustegonDocument
    @RgnDiscriminator(field = "kind")
    sealed interface Shape permits Circle, Polygon {}

    @RgnDiscriminator("circle")
    record Circle(double radius) implements Shape {}

    sealed interface Polygon extends Shape permits Square, Rect {}

    record Square(double side) implements Polygon {}

    @RgnDiscriminator("rect")
    record Rect(@RgnId String id, double w, double h) implements Polygon {}

    /** Sealed values in properties and lists; default discriminator field {@code _type}. */
    @RustegonDocument
    record Drawing(String id, List<Shape> shapes, Shape main, Optional<Pet> pet) {}

    sealed interface Pet permits Dog, Cat {}

    record Dog(String name) implements Pet {}

    record Cat(String name, int lives) implements Pet {}

    /** A recursive type. */
    @RustegonDocument
    record Node(String name, List<Node> children) {}

    /** The typed CRUD document of the rustegond test. */
    @RustegonDocument
    record Product(@RgnId String sku, @RgnRev String rev, String name, BigDecimal price,
            Status status, Instant created, List<String> tags, Optional<String> description,
            Address origin) {}
}
