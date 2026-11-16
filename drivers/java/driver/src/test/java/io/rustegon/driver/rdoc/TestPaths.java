// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/** Locations of the shared test vectors in the repository. */
public final class TestPaths {
    private TestPaths() {}

    /**
     * The repository root ({@code rustegon.repoRoot}, set by the Gradle build).
     *
     * @return the root
     */
    public static Path repoRoot() {
        return Path.of(System.getProperty("rustegon.repoRoot", "../../..")).toAbsolutePath()
                .normalize();
    }

    /**
     * The server's RDoc v1 golden fixtures (data-model.md §4, frozen at M2 exit).
     *
     * @return the directory
     */
    public static Path rdocFixtures() {
        return repoRoot().resolve("crates/rustegon-doc/tests/fixtures/formats/rdoc/1");
    }

    /**
     * The cross-driver conformance suite ({@code drivers/conformance}, lane DK), if present;
     * {@code rustegon.conformanceDir} (set by the Gradle build from
     * {@code -Prustegon.conformanceDir} or {@code RUSTEGON_CONFORMANCE_DIR}) points at another
     * checkout of it.
     *
     * @return the directory, empty before the suite is merged
     */
    public static Optional<Path> conformance() {
        String override = System.getProperty("rustegon.conformanceDir");
        Path p = override != null ? Path.of(override)
                : repoRoot().resolve("drivers/conformance");
        return Files.isDirectory(p) ? Optional.of(p) : Optional.empty();
    }

    /**
     * Every {@code <name>.rdoc} below {@code dir} with a {@code <name>.json} next to it.
     *
     * @param dir the directory
     * @return the {@code .rdoc} files, sorted
     */
    public static List<Path> rdocPairs(Path dir) {
        try (Stream<Path> s = Files.walk(dir)) {
            List<Path> out = new ArrayList<>();
            s.filter(p -> p.toString().endsWith(".rdoc"))
                    .filter(p -> Files.exists(json(p)))
                    .sorted()
                    .forEach(out::add);
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * The JSON twin of an {@code .rdoc} file.
     *
     * @param rdoc the file
     * @return the {@code .json} path
     */
    public static Path json(Path rdoc) {
        String name = rdoc.getFileName().toString();
        return rdoc.resolveSibling(name.substring(0, name.length() - ".rdoc".length()) + ".json");
    }
}
