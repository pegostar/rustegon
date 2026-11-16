// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.Filters;
import io.rustegon.driver.mapping.MappingModel.Customer;
import io.rustegon.driver.mapping.MappingModel.Order;
import io.rustegon.driver.mapping.MappingModel.Shape;
import io.rustegon.driver.rdoc.RDocument;
import io.rustegon.processor.RustegonProcessor;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * TC-DRV-JAVA-021 (FR-DRV-002, java-driver.md §5): the {@code @RustegonDocument} annotation
 * processor. The test model is compiled with it by the build (its codecs and metamodels are used
 * here); further sources are compiled in-process with {@code javax.tools} to check that the
 * output compiles and runs on its own and that mapping errors are compile errors.
 */
class ProcessorTest {
    @TempDir
    Path tmp;

    @Test
    void tc_drv_java_021_generated_codecs_are_used_by_the_mapper() throws Exception {
        for (Class<?> type : List.of(Order.class, Customer.class, Shape.class,
                MappingModel.Address.class, MappingModel.Pet.class)) {
            Class<?> generated = Class.forName(Mapper.generatedCodecName(type));
            assertSame(generated.getField("INSTANCE").get(null), Mapper.codec(type),
                    type.getName());
        }
        assertEquals("io.rustegon.driver.mapping.MappingModel_Order_RgnCodec",
                Mapper.generatedCodecName(Order.class));
    }

    @Test
    void tc_drv_java_021_metamodel_holds_document_field_names() {
        assertEquals("_id", MappingModel_Order_.orderId);
        assertEquals("_rev", MappingModel_Order_.rev);
        assertEquals("_id", MappingModel_Customer_.id);
        assertEquals("zip", MappingModel_Address_.postalCode);
        // Usable wherever a path is expected (java-driver.md §3).
        assertEquals(Filters.eq("status", "PAID"), Filters.eq(MappingModel_Order_.status,
                "PAID"));
    }

    @Test
    void tc_drv_java_021_processor_output_compiles_and_round_trips() throws Exception {
        Result r = compile(Map.of("gen/Item.java", """
                package gen;
                import io.rustegon.driver.mapping.*;
                import java.util.*;
                @RustegonDocument
                public record Item(@RgnId String sku, int qty, List<Part> parts,
                        Optional<String> note, Kind kind) {
                    public enum Kind { A, B }
                    public record Part(@RgnField("n") String name) {}
                }
                """, "gen/Check.java", """
                package gen;
                import java.util.*;
                public final class Check implements java.util.function.Supplier<String> {
                    public String get() {
                        Item i = new Item("s1", 3, List.of(new Item.Part("bolt")),
                                Optional.empty(), Item.Kind.B);
                        var doc = Item_RgnCodec.INSTANCE.encode(i);
                        Item back = Item_RgnCodec.INSTANCE.decode(doc, "");
                        if (!back.equals(i)) throw new AssertionError(back);
                        return doc.toJson() + " " + Item_.sku + " " + Item_Part_.name;
                    }
                }
                """));
        assertTrue(r.ok, r.diagnostics);
        assertTrue(Files.isRegularFile(r.out.resolve("gen/Item_RgnCodec.class")));
        assertTrue(Files.isRegularFile(r.out.resolve("gen/Item_Part_RgnCodec.class")));
        try (URLClassLoader cl = new URLClassLoader(new URL[] {r.out.toUri().toURL()},
                getClass().getClassLoader())) {
            @SuppressWarnings("unchecked")
            Supplier<String> check = (Supplier<String>) cl.loadClass("gen.Check")
                    .getDeclaredConstructor().newInstance();
            assertEquals("{\"_id\":\"s1\",\"qty\":3,\"parts\":[{\"n\":\"bolt\"}],\"kind\":\"B\"}"
                    + " _id n", check.get());
        }
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', textBlock = """
            generic record      | record G<T>(T v) {}                                   | generic types are not mapped
            two ids             | record G(@RgnId String a, @RgnId String b) {}         | more than one @RgnId
            unsupported type    | record G(java.time.LocalDate d) {}                    | unsupported type java.time.LocalDate
            vector on String    | record G(@RgnVector(3) String v) {}                   | @RgnVector needs a float[]
            geo on float[]      | record G(@RgnGeoPoint float[] v) {}                   | @RgnGeoPoint needs a double[]
            rev on int          | record G(@RgnRev int r) {}                            | @RgnRev needs a String
            counter on String   | record G(@RgnCounter String c) {}                     | @RgnCounter needs a long or Long
            map key             | record G(java.util.Map<Integer, String> m) {}         | map keys must be String
            raw list            | record G(java.util.List l) {}                         | raw type
            private field       | class G { private String a; }                         | needs an accessible getter
            final field         | class G { final String a = ""; }                      | final fields of a class are not mapped
            no constructor      | class G { G(int x) {} String a; }                     | no-argument constructor
            plain interface     | interface G {}                                        | not a mappable document type
            non-sealed subtype  | sealed interface G permits H {} non-sealed interface H extends G {} | non-sealed abstract subtype
            """)
    void tc_drv_java_021_mapping_errors_are_compile_errors(String name, String decl,
            String expected) throws Exception {
        Result r = compile(Map.of("bad/G.java", "package bad;\n"
                + "import io.rustegon.driver.mapping.*;\n@RustegonDocument\n" + decl + "\n"));
        assertFalse(r.ok, name);
        assertTrue(r.diagnostics.contains(expected), r.diagnostics);
    }

    // ------------------------------------------------------------------ javax.tools

    private record Result(boolean ok, String diagnostics, Path out) {}

    private Result compile(Map<String, String> sources) throws Exception {
        Path src = Files.createDirectories(tmp.resolve("src"));
        Path out = Files.createDirectories(tmp.resolve("out"));
        List<File> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path f = src.resolve(e.getKey());
            Files.createDirectories(f.getParent());
            Files.writeString(f, e.getValue());
            files.add(f.toFile());
        }
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diags = new DiagnosticCollector<>();
        try (StandardJavaFileManager fm = javac.getStandardFileManager(diags, Locale.ROOT,
                null)) {
            // Only the driver is needed by generated code: no other dependency leaks in.
            String cp = location(DocumentCodec.class) + File.pathSeparator
                    + location(RDocument.class);
            JavaCompiler.CompilationTask task = javac.getTask(null, fm, diags, List.of("-d",
                    out.toString(), "-s", out.toString(), "-cp", cp, "-proc:full"), null,
                    fm.getJavaFileObjectsFromFiles(files));
            task.setProcessors(List.of(new RustegonProcessor()));
            boolean ok = task.call();
            String text = diags.getDiagnostics().stream()
                    .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                    .map(d -> d.getMessage(Locale.ROOT)).collect(Collectors.joining("\n"));
            return new Result(ok, text, out);
        }
    }

    private static String location(Class<?> c) throws URISyntaxException {
        return Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    }
}
