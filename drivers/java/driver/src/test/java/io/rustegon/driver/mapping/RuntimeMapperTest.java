// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.rdoc.RDocument;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * TC-DRV-JAVA-025 (FR-DRV-002, java-driver.md §5): the run-time {@code MethodHandles} mapper,
 * used when no generated codec exists (types never seen by the processor), and its mapping
 * errors ({@link IllegalArgumentException} naming the property, when the codec is built).
 */
class RuntimeMapperTest {
    // Not annotated and not used by an annotated type: no generated codec exists.
    record Plain(String id, int n, List<Inner> inner) {}

    record Inner(@RgnField("v") String value) {}

    private static final class PrivatePojo {
        private String name;
        private long count;

        private PrivatePojo() {}
    }

    record Generic<T>(T v) {}

    interface NotSealed {}

    static class FinalField {
        final String a = "";
    }

    static class NoDefaultCtor {
        String a;

        NoDefaultCtor(String a) {
            this.a = a;
        }
    }

    record TwoIds(@RgnId String a, @RgnId String b) {}

    record BadMap(Map<Integer, String> m) {}

    record BadRev(@RgnRev int rev) {}

    record BadType(LocalDate d) {}

    record Holder(NotSealed x) {}

    @Test
    void tc_drv_java_025_runtime_mapper_without_processor() {
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName(Mapper.generatedCodecName(Plain.class)));
        DocumentCodec<Plain> codec = Mapper.codec(Plain.class);
        assertInstanceOf(ObjectCodec.class, codec);
        assertSame(codec, Mapper.codec(Plain.class), "codecs are cached");
        Plain p = new Plain("p1", 3, List.of(new Inner("x")));
        RDocument doc = codec.encode(p);
        assertEquals(RDocument.of("_id", "p1").append("n", 3L).append("inner",
                List.of(RDocument.of("v", "x"))), doc);
        assertEquals(p, codec.decode(doc, ""));
    }

    @Test
    void tc_drv_java_025_private_pojo_through_private_lookup() {
        PrivatePojo p = new PrivatePojo();
        p.name = "n";
        p.count = 5;
        RDocument doc = Mapper.codec(PrivatePojo.class).encode(p);
        assertEquals(RDocument.of("name", "n").append("count", 5L), doc);
        PrivatePojo back = Mapper.codec(PrivatePojo.class).decode(doc, "");
        assertEquals("n", back.name);
        assertEquals(5, back.count);
    }

    static Stream<Arguments> errors() {
        return Stream.of(
                Arguments.of(Generic.class, "generic types are not mapped"),
                Arguments.of(NotSealed.class, "is not a mappable document type"),
                Arguments.of(FinalField.class, "final fields of a class are not mapped"),
                Arguments.of(NoDefaultCtor.class, "needs a no-argument constructor"),
                Arguments.of(TwoIds.class, "more than one @RgnId"),
                Arguments.of(BadMap.class, "BadMap.m: map keys must be String"),
                Arguments.of(BadRev.class, "BadRev.rev: @RgnRev needs a String"),
                Arguments.of(BadType.class, "BadType.d: unsupported type java.time.LocalDate"),
                Arguments.of(String.class, "is not a mappable document type"),
                Arguments.of(MappingModel.Status.class, "is not a mappable document type"));
    }

    @ParameterizedTest
    @MethodSource("errors")
    void tc_drv_java_025_mapping_errors(Class<?> type, String message) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Mapper.codec(type));
        assertTrue(e.getMessage().contains(message), e.getMessage());
    }

    @Test
    void tc_drv_java_025_nested_errors_surface_on_first_use() {
        // Nested codecs resolve lazily (recursive types): the error comes when encoding.
        DocumentCodec<Holder> codec = Mapper.codec(Holder.class);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> codec.encode(new Holder(new NotSealed() {})));
        assertTrue(e.getMessage().contains("not a mappable document type"), e.getMessage());
    }
}
