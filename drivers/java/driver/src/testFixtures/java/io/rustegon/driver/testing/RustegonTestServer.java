// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.testing;

import io.rustegon.driver.RustegonClientSettings;
import io.rustegon.driver.RustegonCredential;
import io.rustegon.driver.TlsSettings;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Assumptions;

/**
 * A real {@code rustegond} for integration tests (PD-072, option (a)): one server per test JVM,
 * started on first use and stopped at JVM exit.
 *
 * <p>Binaries: {@code rustegon} and {@code rustegond} from {@code RUSTEGON_BIN_DIR}, default
 * {@code <repo>/target/debug} ({@code <repo>} from the {@code rustegon.repoRoot} system
 * property set by the Gradle build). Without them the calling test is skipped with a message —
 * or fails when {@code CI=true}, so CI cannot silently skip the integration tests.
 *
 * <p>Start: {@code rustegon init --data-dir D --grpc-port 0 --http-port 0
 * --admin-password-file F --tls --client-user conf_x509 --non-interactive} (TLS is opt-in,
 * ADR-034; the tests keep it on: fresh CA P-256, node
 * certificate for {@code 127.0.0.1}, a client certificate for X.509 login as
 * {@code x509:CN=conf_x509}), then {@code rustegond --config D/rustegon.toml
 * --admin-password-file F --stop-on-stdin-eof --set auth.scram_iterations=100000} (the smallest
 * accepted count, so debug builds log in quickly) {@code --set tls.client_cert=optional} (client
 * certificates are requested and verified against the cluster CA, so the conformance tests can
 * log in with X.509) and the four {@code rate_limit.*_per_min=0} settings (PD-098: no RGN-4003
 * on the shared test node). The server prints {@code rustegond ready grpc=… http=…} and
 * stops when its standard input closes. The administrator is {@code admin} with a random
 * password; no secret is printed.
 */
public final class RustegonTestServer {
    /** The first administrator created by {@code rustegon init} / the first start. */
    public static final String ADMIN_USER = "admin";
    /** Subject CN of the client certificate issued by {@code rustegon init}. */
    public static final String X509_USER = "conf_x509";
    private static final Duration START_TIMEOUT = Duration.ofSeconds(90);
    private static final Duration STOP_TIMEOUT = Duration.ofSeconds(30);
    private static final String READY = "rustegond ready ";
    private static final ReentrantLock LOCK = new ReentrantLock();
    private static RustegonTestServer shared;
    private static String unavailable;

    private final Process process;
    private final OutputStream stdin;
    private final String grpcEndpoint;
    private final Path caCertificate;
    private final Path dataDir;
    private volatile char[] adminPassword;

    private RustegonTestServer(Process process, String grpcEndpoint, Path dataDir,
            char[] adminPassword) {
        this.process = process;
        this.stdin = process.getOutputStream();
        this.grpcEndpoint = grpcEndpoint;
        this.dataDir = dataDir;
        this.caCertificate = dataDir.resolve("certs").resolve("ca.crt");
        this.adminPassword = adminPassword;
    }

    /**
     * The shared server, started on first call; skips (or, with {@code CI=true}, fails) the
     * calling test when the binaries are missing.
     *
     * @return the running server
     */
    public static RustegonTestServer shared() {
        LOCK.lock();
        try {
            if (shared == null && unavailable == null) {
                Path bin = binDir();
                Path cli = bin.resolve(exe("rustegon"));
                Path daemon = bin.resolve(exe("rustegond"));
                if (!Files.isExecutable(cli) || !Files.isExecutable(daemon)) {
                    unavailable = "rustegon/rustegond not found in " + bin
                            + " (build them with `cargo build -p rustegond -p rustegon-cli` or "
                            + "set RUSTEGON_BIN_DIR)";
                } else {
                    shared = start(cli, daemon);
                    Runtime.getRuntime().addShutdownHook(new Thread(shared::stop));
                }
            }
            if (shared == null) {
                if ("true".equalsIgnoreCase(System.getenv("CI"))) {
                    throw new IllegalStateException("integration tests need the server: "
                            + unavailable);
                }
                Assumptions.abort("integration test skipped: " + unavailable);
            }
            return shared;
        } finally {
            LOCK.unlock();
        }
    }

    private static String exe(String name) {
        return System.getProperty("os.name").toLowerCase().startsWith("windows")
                ? name + ".exe" : name;
    }

    private static Path binDir() {
        String env = System.getenv("RUSTEGON_BIN_DIR");
        if (env != null && !env.isEmpty()) {
            return Path.of(env);
        }
        String root = System.getProperty("rustegon.repoRoot", "../..");
        return Path.of(root, "target", "debug");
    }

    private static RustegonTestServer start(Path cli, Path daemon) {
        try {
            Path root = Files.createTempDirectory("rustegon-java-it");
            Path dataDir = root.resolve("data");
            char[] password = randomPassword();
            Path passwordFile = root.resolve("admin-password");
            Files.writeString(passwordFile, new String(password), StandardCharsets.UTF_8);
            run(List.of(cli.toString(), "init", "--data-dir", dataDir.toString(),
                    "--grpc-port", "0", "--http-port", "0",
                    "--admin-password-file", passwordFile.toString(),
                    "--tls", "--client-user", X509_USER, "--non-interactive"),
                    root);
            List<String> cmd = new ArrayList<>(List.of(daemon.toString(),
                    "--config", dataDir.resolve("rustegon.toml").toString(),
                    "--admin-password-file", passwordFile.toString(),
                    "--stop-on-stdin-eof",
                    "--set", "auth.scram_iterations=100000",
                    "--set", "tls.client_cert=optional",
                    "--set", "log.stderr=false",
                    "--set", "listen.shutdown_grace_secs=5",
                    // PD-098: one node serves every test of a run from one address; the
                    // conformance suite logs in (and fails logins on purpose) far more often than
                    // the per-IP/per-user defaults allow. 0 = unlimited (test node only).
                    "--set", "rate_limit.auth_per_ip_per_min=0",
                    "--set", "rate_limit.auth_per_user_per_min=0",
                    "--set", "rate_limit.session_per_user_per_min=0",
                    "--set", "rate_limit.admin_per_user_per_min=0"));
            ProcessBuilder pb = new ProcessBuilder(cmd).directory(root.toFile())
                    .redirectError(root.resolve("rustegond.stderr").toFile());
            scrubEnvironment(pb.environment());
            Process p = pb.start();
            CompletableFuture<String> ready = new CompletableFuture<>();
            Thread reader = new Thread(() -> readStdout(p, ready), "rustegond-stdout");
            reader.setDaemon(true);
            reader.start();
            String line;
            try {
                line = ready.get(START_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            } catch (TimeoutException | java.util.concurrent.ExecutionException e) {
                p.destroyForcibly();
                throw new IllegalStateException("rustegond did not become ready; stderr: "
                        + Files.readString(root.resolve("rustegond.stderr")), e);
            }
            String grpc = null;
            for (String kv : line.split(" ")) {
                if (kv.startsWith("grpc=")) {
                    grpc = kv.substring("grpc=".length());
                }
            }
            if (grpc == null) {
                p.destroyForcibly();
                throw new IllegalStateException("unexpected ready line: " + line);
            }
            return new RustegonTestServer(p, grpc, dataDir, password);
        } catch (IOException e) {
            throw new IllegalStateException("cannot start rustegond", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while starting rustegond", e);
        }
    }

    private static void readStdout(Process p, CompletableFuture<String> ready) {
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
    }

    /** The child must not inherit this machine's RUSTEGON_* configuration. */
    private static void scrubEnvironment(Map<String, String> env) {
        env.keySet().removeIf(k -> k.toUpperCase().startsWith("RUSTEGON_"));
    }

    private static void run(List<String> cmd, Path dir) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(dir.toFile())
                .redirectErrorStream(true)
                .redirectOutput(dir.resolve("init.log").toFile());
        scrubEnvironment(pb.environment());
        Process p = pb.start();
        p.getOutputStream().close();
        if (!p.waitFor(START_TIMEOUT.toSeconds(), TimeUnit.SECONDS) || p.exitValue() != 0) {
            p.destroyForcibly();
            throw new IllegalStateException("rustegon init failed: "
                    + Files.readString(dir.resolve("init.log")));
        }
    }

    /** 24 random characters from four classes: comfortably above the server's policy. */
    private static char[] randomPassword() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!";
        SecureRandom random = new SecureRandom();
        char[] out = new char[24];
        for (int i = 0; i < out.length; i++) {
            out[i] = alphabet.charAt(random.nextInt(alphabet.length()));
        }
        return out;
    }

    /**
     * The gRPC endpoint ({@code 127.0.0.1:port}).
     *
     * @return the endpoint
     */
    public String grpcEndpoint() {
        return grpcEndpoint;
    }

    /**
     * The CA certificate that signed the node certificate.
     *
     * @return the PEM file
     */
    public Path caCertificate() {
        return caCertificate;
    }

    /**
     * The client certificate of {@link #X509_USER} (PEM), issued by the cluster CA.
     *
     * @return the file
     */
    public Path clientCertificate() {
        return dataDir.resolve("certs").resolve("client-" + X509_USER).resolve("client.crt");
    }

    /**
     * The private key of {@link #clientCertificate()} (PEM).
     *
     * @return the file
     */
    public Path clientKey() {
        return dataDir.resolve("certs").resolve("client-" + X509_USER).resolve("client.key");
    }

    /**
     * The data directory of the node.
     *
     * @return the directory
     */
    public Path dataDir() {
        return dataDir;
    }

    /**
     * A copy of the administrator's current password.
     *
     * @return the password
     */
    public char[] adminPassword() {
        return adminPassword.clone();
    }

    /**
     * Records a changed administrator password (tests that call {@code changePassword}).
     *
     * @param password the new password
     */
    public void adminPasswordChanged(char[] password) {
        this.adminPassword = password.clone();
    }

    /**
     * Settings for this server: its endpoint, its CA, the given credential.
     *
     * @param credential the credential
     * @return a builder to complete
     */
    public RustegonClientSettings.Builder settings(RustegonCredential credential) {
        return RustegonClientSettings.builder()
                .endpoints(grpcEndpoint)
                .tls(TlsSettings.builder().caCertificate(caCertificate).build())
                .credential(credential)
                .applicationName("rustegon-java-tests");
    }

    /**
     * Settings logging in as the administrator.
     *
     * @return a builder to complete
     */
    public RustegonClientSettings.Builder adminSettings() {
        return settings(RustegonCredential.scram(ADMIN_USER, adminPassword));
    }

    /** Closes standard input (graceful shutdown) and waits for the exit. */
    private void stop() {
        try {
            stdin.close();
            if (!process.waitFor(STOP_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (IOException e) {
            process.destroyForcibly();
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }
}
