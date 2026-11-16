// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.robustness;

import io.rustegon.driver.RustegonClientSettings;
import io.rustegon.driver.RustegonCredential;
import io.rustegon.driver.TlsSettings;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Assumptions;

/**
 * A {@code rustegond} owned by one test class (TC-DRV-JAVA-029/030), separate from the shared
 * {@code RustegonTestServer}: it can be killed and restarted on the same data directory and
 * gRPC port, and runs with the rate limits off so that 1000 concurrent operations measure the
 * driver, not the node's admission control. Same binaries and skip rules as the shared fixture
 * (PD-072: {@code RUSTEGON_BIN_DIR}, default {@code <repo>/target/debug}; skipped without them,
 * failing under {@code CI=true}).
 */
final class OwnedServer implements AutoCloseable {
    private static final long START_SECONDS = 90;
    private static final String READY = "rustegond ready ";

    private final Path daemon;
    private final Path root;
    private final Path dataDir;
    private final Path passwordFile;
    private final char[] password;
    private Process process;
    private String grpcEndpoint;
    private int starts;

    private OwnedServer(Path daemon, Path root, char[] password) {
        this.daemon = daemon;
        this.root = root;
        this.dataDir = root.resolve("data");
        this.passwordFile = root.resolve("admin-password");
        this.password = password;
    }

    /**
     * Initialises a data directory and starts the node on a free port.
     *
     * @return the running server
     */
    static OwnedServer start() throws IOException, InterruptedException {
        String env = System.getenv("RUSTEGON_BIN_DIR");
        Path bin = env != null && !env.isEmpty() ? Path.of(env)
                : Path.of(System.getProperty("rustegon.repoRoot", "../.."), "target", "debug");
        String suffix = System.getProperty("os.name").toLowerCase().startsWith("windows")
                ? ".exe" : "";
        Path cli = bin.resolve("rustegon" + suffix);
        Path daemon = bin.resolve("rustegond" + suffix);
        if (!Files.isExecutable(cli) || !Files.isExecutable(daemon)) {
            String why = "rustegon/rustegond not found in " + bin;
            if ("true".equalsIgnoreCase(System.getenv("CI"))) {
                throw new IllegalStateException("integration tests need the server: " + why);
            }
            Assumptions.abort("integration test skipped: " + why);
        }
        char[] password = new char[24];
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!";
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < password.length; i++) {
            password[i] = alphabet.charAt(random.nextInt(alphabet.length()));
        }
        OwnedServer server = new OwnedServer(daemon,
                Files.createTempDirectory("rustegon-java-robustness"), password);
        Files.writeString(server.passwordFile, new String(password), StandardCharsets.UTF_8);
        ProcessBuilder init = new ProcessBuilder(cli.toString(), "init",
                "--data-dir", server.dataDir.toString(), "--grpc-port", "0", "--http-port", "0",
                "--admin-password-file", server.passwordFile.toString(), "--non-interactive",
                "--tls")
                .directory(server.root.toFile()).redirectErrorStream(true)
                .redirectOutput(server.root.resolve("init.log").toFile());
        init.environment().keySet().removeIf(k -> k.toUpperCase().startsWith("RUSTEGON_"));
        Process p = init.start();
        p.getOutputStream().close();
        if (!p.waitFor(START_SECONDS, TimeUnit.SECONDS) || p.exitValue() != 0) {
            p.destroyForcibly();
            throw new IllegalStateException("rustegon init failed: "
                    + Files.readString(server.root.resolve("init.log")));
        }
        server.launch(null);
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        return server;
    }

    /**
     * Starts {@code rustegond} on the data directory; {@code grpc} pins the listen address of
     * a restart (the config written by {@code init} asks for port 0).
     */
    private void launch(String grpc) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>(List.of(daemon.toString(),
                "--config", dataDir.resolve("rustegon.toml").toString(),
                "--stop-on-stdin-eof",
                "--set", "auth.scram_iterations=100000",
                "--set", "rate_limit.enabled=false",
                "--set", "log.stderr=false",
                "--set", "listen.shutdown_grace_secs=5"));
        if (grpc == null) {
            // The first start creates the administrator from the password file.
            cmd.addAll(List.of("--admin-password-file", passwordFile.toString()));
        } else {
            cmd.addAll(List.of("--set", "listen.grpc=" + grpc));
        }
        starts++;
        Path stderr = root.resolve("rustegond-" + starts + ".stderr");
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(root.toFile())
                .redirectError(stderr.toFile());
        pb.environment().keySet().removeIf(k -> k.toUpperCase().startsWith("RUSTEGON_"));
        Process p = pb.start();
        CompletableFuture<String> ready = new CompletableFuture<>();
        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.startsWith(READY)) {
                        ready.complete(line.substring(READY.length()));
                    }
                }
                ready.completeExceptionally(new IOException("rustegond exited before ready"));
            } catch (IOException e) {
                ready.completeExceptionally(e);
            }
        }, "rustegond-stdout");
        reader.setDaemon(true);
        reader.start();
        String line;
        try {
            line = ready.get(START_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException | ExecutionException e) {
            p.destroyForcibly();
            throw new IllegalStateException("rustegond did not become ready; stderr: "
                    + Files.readString(stderr), e);
        }
        String endpoint = null;
        for (String kv : line.split(" ")) {
            if (kv.startsWith("grpc=")) {
                endpoint = kv.substring("grpc=".length());
            }
        }
        if (endpoint == null || (grpc != null && !grpc.equals(endpoint))) {
            p.destroyForcibly();
            throw new IllegalStateException("unexpected ready line: " + line);
        }
        process = p;
        grpcEndpoint = endpoint;
    }

    /** Kills the node without a shutdown (a crash: no graceful drain, no final flush). */
    void kill() throws InterruptedException {
        process.destroyForcibly();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            throw new IllegalStateException("rustegond did not exit after a kill");
        }
    }

    /** Starts the node again on the same data directory and gRPC address. */
    void restart() throws IOException, InterruptedException {
        launch(grpcEndpoint);
    }

    /**
     * Settings logging in as the administrator, against this node's CA.
     *
     * @return a builder to complete
     */
    RustegonClientSettings.Builder adminSettings() {
        return RustegonClientSettings.builder()
                .endpoints(grpcEndpoint)
                .tls(TlsSettings.builder()
                        .caCertificate(dataDir.resolve("certs").resolve("ca.crt")).build())
                .credential(RustegonCredential.scram("admin", password))
                .applicationName("rustegon-java-robustness");
    }

    /** Graceful stop (standard input closed), forced after 30 s. */
    @Override
    public void close() {
        Process p = process;
        if (p == null || !p.isAlive()) {
            return;
        }
        try {
            p.getOutputStream().close();
            if (!p.waitFor(30, TimeUnit.SECONDS)) {
                p.destroyForcibly();
            }
        } catch (IOException e) {
            p.destroyForcibly();
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }
}
