// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.mapping.MappingModel.Cat;
import io.rustegon.driver.mapping.MappingModel.Circle;
import io.rustegon.driver.mapping.MappingModel.Dog;
import io.rustegon.driver.mapping.MappingModel.Drawing;
import io.rustegon.driver.mapping.MappingModel.Rect;
import io.rustegon.driver.mapping.MappingModel.Shape;
import io.rustegon.driver.mapping.MappingModel.Square;
import io.rustegon.driver.rdoc.RDocReader;
import io.rustegon.driver.rdoc.RDocument;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-024 (FR-DRV-002, java-driver.md §5): sealed hierarchies with
 * {@link RgnDiscriminator}: discriminator field and values (custom and default), nested sealed
 * interfaces flattened, placement after {@code _id}, sealed values in properties, lists and
 * optionals, missing/unknown discriminators; generated and {@code MethodHandles} codecs agree.
 */
class SealedMappingTest {
    private static final Drawing DRAWING = new Drawing("d1", List.of(new Circle(1.5),
            new Square(2), new Rect("r1", 3, 4)), new Rect(null, 1, 1),
            Optional.of(new Cat("Tom", 9)));

    @Test
    void tc_drv_java_024_round_trip_and_layout() {
        byte[] bytes = Samples.sameBytes(Drawing.class, DRAWING);
        RDocument doc = RDocReader.decode(bytes);
        @SuppressWarnings("unchecked")
        List<RDocument> shapes = (List<RDocument>) doc.get("shapes");
        assertEquals(RDocument.of("kind", "circle").append("radius", 1.5), shapes.get(0));
        assertEquals(RDocument.of("kind", "Square").append("side", 2.0), shapes.get(1));
        assertEquals(List.of("_id", "kind", "w", "h"), new ArrayList<>(shapes.get(2).keySet()),
                "the discriminator follows _id");
        assertEquals(RDocument.of("kind", "rect").append("w", 1.0).append("h", 1.0),
                doc.get("main"), "a null _id is omitted");
        assertEquals(RDocument.of("_type", "Cat").append("name", "Tom").append("lives", 9L),
                doc.get("pet"), "default field _type, default value the simple name");
        for (Function<RDocument, Drawing> decode : decoders()) {
            assertEquals(DRAWING, decode.apply(doc));
        }
    }

    @Test
    void tc_drv_java_024_root_codec_directly() {
        for (Shape s : List.of(new Circle(0), new Square(-1), new Rect("x", 0, 0))) {
            byte[] bytes = Samples.sameBytes(Shape.class, s);
            assertEquals(s, Mapper.codec(Shape.class).decode(RDocReader.decode(bytes), ""));
            assertEquals(s, Mapper.reflective(Shape.class).decode(RDocReader.decode(bytes), ""));
        }
        Samples.sameBytes(MappingModel.Pet.class, new Dog("Rex"));
    }

    @Test
    void tc_drv_java_024_missing_or_unknown_discriminator_is_rejected() {
        RDocument doc = Mapper.codec(Drawing.class).encode(DRAWING);
        doc.put("main", RDocument.of("kind", "hexagon"));
        for (Function<RDocument, Drawing> decode : decoders()) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> decode.apply(doc));
            assertTrue(e.getMessage().contains("main.kind: unknown discriminator"),
                    e.getMessage());
        }
        doc.put("main", RDocument.of("w", 1.0));
        for (Function<RDocument, Drawing> decode : decoders()) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> decode.apply(doc));
            assertTrue(e.getMessage().contains("main.kind: missing discriminator"),
                    e.getMessage());
        }
    }

    private static List<Function<RDocument, Drawing>> decoders() {
        return List.of(d -> Mapper.codec(Drawing.class).decode(d, ""),
                d -> Mapper.reflective(Drawing.class).decode(d, ""));
    }
}
