// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.internal.ErrorMappingTest;
import io.rustegon.driver.internal.ScramTest;
import io.rustegon.driver.internal.proto.AdminServiceGrpc;
import io.rustegon.driver.internal.proto.CreateApiKeyRequest;
import io.rustegon.driver.internal.proto.CreateUserRequest;
import io.rustegon.driver.internal.proto.DropUserRequest;
import io.rustegon.driver.internal.proto.RoleGrant;
import io.rustegon.driver.rdoc.ConformanceCodecTest;
import io.rustegon.driver.rdoc.ExtendedJson;
import io.rustegon.driver.rdoc.JsonMode;
import io.rustegon.driver.rdoc.ObjectId;
import io.rustegon.driver.rdoc.RDocument;
import io.rustegon.driver.rdoc.TestPaths;
import io.rustegon.driver.testing.RustegonTestServer;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.TestMethodOrder;
import org.opentest4j.TestAbortedException;

/**
 * The conformance runner of the Java driver (TC-DRV-JAVA-011…020, TC-DRV-CONF-*; FR-DRV-003,
 * AC-DRV-003): every test file of {@code drivers/conformance} runs per README §5–§7 against the
 * {@code rustegond} fixture (PD-072) — a fresh database per file, collections, indexes, data
 * and users per test, then the operations and the {@code outcome} — and the results are
 * written to {@code build/conformance-results-jdk<21|25>.json} (README §6). The last test checks that every
 * {@code r1} operation of {@code model.yaml} is covered by a passed test.
 *
 * <p>Runner operations of the unit kind delegate to the DJ1 runners (codec, error mapping,
 * connection strings, SCRAM) and to {@link AstVectors} / {@link RetryScenarios}. Required
 * capabilities ({@code admin}, {@code api-key}, {@code x509-client-cert}, {@code slow},
 * {@code fixture-connection-string}) are all provided; without the server binaries the tests
 * that need the server are skipped (or fail under {@code CI=true}).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ConformanceSuiteTest {
    private static final Set<String> CAPABILITIES = Set.of("admin", "api-key",
            "x509-client-cert", "slow", "fixture-connection-string");
    private static final Map<String, Map<String, Object>> RESULTS = new ConcurrentHashMap<>();
    private static final Map<String, List<String>> COVERS = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static String apiKey;
    private static String serverVersion = "";

    @TestFactory
    @Order(1)
    Stream<DynamicNode> tc_drv_java_011_conformance_crud() throws IOException {
        return files("crud/find-by-id.yaml", "crud/insert.yaml", "crud/replace-delete.yaml",
                "crud/update.yaml");
    }

    @TestFactory
    @Order(2)
    Stream<DynamicNode> tc_drv_java_012_conformance_find_and_cursors() throws IOException {
        return files("query/filters.yaml", "query/find-options.yaml", "cursor/cursor.yaml");
    }

    @TestFactory
    @Order(3)
    Stream<DynamicNode> tc_drv_java_013_conformance_rgql() throws IOException {
        return files("query/rgql.yaml");
    }

    @TestFactory
    @Order(4)
    Stream<DynamicNode> tc_drv_java_014_conformance_bulk() throws IOException {
        return files("bulk/bulk.yaml");
    }

    @TestFactory
    @Order(5)
    Stream<DynamicNode> tc_drv_java_015_conformance_schema() throws IOException {
        return files("schema/collections.yaml");
    }

    @TestFactory
    @Order(6)
    Stream<DynamicNode> tc_drv_java_016_conformance_transactions() throws IOException {
        return files("txn/transactions.yaml");
    }

    @TestFactory
    @Order(7)
    Stream<DynamicNode> tc_drv_java_018_conformance_auth() throws IOException {
        return files("auth/auth.yaml");
    }

    @TestFactory
    @Order(8)
    Stream<DynamicNode> tc_drv_java_020_conformance_client_and_errors() throws IOException {
        return files("client/vectors.yaml", "errors/errors.yaml");
    }

    @Test
    @Order(9)
    @SuppressWarnings("unchecked")
    void tc_drv_java_020_every_r1_operation_is_covered_and_results_are_written()
            throws IOException {
        Path dir = ClientApiUnitTest.conformance(".");
        Assumptions.assumeTrue(!RESULTS.isEmpty(), "the conformance tests did not run");
        writeResults();
        Set<String> covered = new LinkedHashSet<>();
        RESULTS.forEach((id, r) -> {
            if ("passed".equals(r.get("status"))) {
                covered.addAll(COVERS.getOrDefault(id, List.of()));
            }
        });
        Map<String, Object> model = ConformanceValues.load(dir.resolve("model.yaml"));
        List<String> missing = new ArrayList<>();
        int r1 = 0;
        for (Map<String, Object> op : (List<Map<String, Object>>) model.get("operations")) {
            if ("r1".equals(op.get("status"))) {
                r1++;
                if (!covered.contains((String) op.get("id"))) {
                    missing.add((String) op.get("id"));
                }
            }
        }
        System.out.println("conformance: " + RESULTS.size() + " tests, r1 operations covered "
                + (r1 - missing.size()) + "/" + r1);
        assertTrue(missing.isEmpty(), "r1 operations without a passed test: " + missing);
    }

    // ------------------------------------------------------------------ files and tests

    @SuppressWarnings("unchecked")
    private Stream<DynamicNode> files(String... relative) throws IOException {
        Path dir = ClientApiUnitTest.conformance(".");
        List<DynamicNode> nodes = new ArrayList<>();
        for (String rel : relative) {
            Path file = dir.resolve(rel);
            Map<String, Object> root = ConformanceValues.load(file);
            List<Map<String, Object>> tests = (List<Map<String, Object>>) root.get("tests");
            FileRun run = new FileRun(dir, rel, (Map<String, Object>) root.get("setup"),
                    Files.readString(file));
            List<DynamicTest> dyn = new ArrayList<>();
            for (int i = 0; i < tests.size(); i++) {
                Map<String, Object> t = tests.get(i);
                boolean last = i == tests.size() - 1;
                dyn.add(DynamicTest.dynamicTest(t.get("id") + " " + t.get("description"),
                        () -> run.test(t, last)));
            }
            nodes.add(DynamicContainer.dynamicContainer(rel, dyn));
        }
        return nodes.stream();
    }

    /** One test file: its database and default client, created on first need. */
    private static final class FileRun {
        private final Path dir;
        private final String rel;
        private final Map<String, Object> fileSetup;
        private final String text;
        private RustegonTestServer server;
        private String database;
        private RustegonClient admin;

        FileRun(Path dir, String rel, Map<String, Object> fileSetup, String text) {
            this.dir = dir;
            this.rel = rel;
            this.fileSetup = fileSetup;
            this.text = text;
        }

        @SuppressWarnings("unchecked")
        void test(Map<String, Object> t, boolean last) throws Exception {
            String id = (String) t.get("id");
            COVERS.put(id, (List<String>) t.get("covers"));
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", id);
            RESULTS.put(id, result);
            OpRunner runner = null;
            try {
                for (Object cap : (List<Object>) t.getOrDefault("requires", List.of())) {
                    if (!CAPABILITIES.contains(cap)) {
                        throw new TestAbortedException("requires " + cap);
                    }
                }
                Map<String, Object> setup = t.containsKey("setup")
                        ? (Map<String, Object>) t.get("setup") : fileSetup;
                List<Map<String, Object>> ops = (List<Map<String, Object>>) t.get("operations");
                boolean needsServer = setup != null || ops.stream().anyMatch(
                        o -> !"runner".equals(o.get("object")));
                if (needsServer) {
                    open();
                }
                runner = new OpRunner(admin, database, defaultCollection(setup), env());
                List<String> users = needsServer ? setUp(setup, t, runner) : List.of();
                try {
                    for (Map<String, Object> op : ops) {
                        runner.run(op);
                    }
                    if (t.get("outcome") instanceof Map<?, ?> outcome) {
                        result.put("outcome", checkOutcome((Map<String, Object>) outcome,
                                runner));
                    }
                } finally {
                    runner.closeOpened();
                    for (String u : users) {
                        dropUser(u);
                    }
                }
                result.put("status", "passed");
            } catch (TestAbortedException e) {
                result.put("status", "skipped");
                result.put("reason", e.getMessage());
                throw e;
            } catch (Exception | AssertionError e) {
                result.put("status", "failed");
                result.put("reason", String.valueOf(e.getMessage()));
                throw e;
            } finally {
                if (runner != null) {
                    result.put("observations", runner.observations);
                }
                result.put("text", text);
                if (last) {
                    close();
                }
            }
        }

        private void open() {
            if (admin != null) {
                return;
            }
            server = RustegonTestServer.shared();
            String category = rel.substring(0, rel.indexOf('/'));
            String stem = rel.substring(rel.indexOf('/') + 1, rel.lastIndexOf('.'))
                    .replace('-', '_');
            byte[] random = new byte[4];
            RANDOM.nextBytes(random);
            database = "conf_" + category + "_" + stem + "_" + HexFormat.of().formatHex(random);
            admin = RustegonClient.create(server.adminSettings().defaultDatabase(database)
                    .build());
            serverVersion = admin.serverInfo().serverVersion();
            admin.createDatabase(database);
        }

        private void close() {
            if (admin != null) {
                try {
                    admin.dropDatabase(database, DropOptions.whenExists());
                } finally {
                    admin.close();
                    admin = null;
                }
            }
        }

        private static String defaultCollection(Map<String, Object> setup) {
            if (setup != null && setup.get("collections") instanceof List<?> l && !l.isEmpty()) {
                return (String) ((Map<?, ?>) l.get(0)).get("name");
            }
            return "items";
        }

        @SuppressWarnings("unchecked")
        private List<String> setUp(Map<String, Object> setup, Map<String, Object> t,
                OpRunner runner) {
            RustegonDatabase db = admin.database(database);
            for (String c : db.listCollectionNames()) {
                db.dropCollection(c, DropOptions.whenExists());
            }
            List<String> users = new ArrayList<>();
            if (((List<Object>) t.getOrDefault("requires", List.of())).contains(
                    "x509-client-cert")) {
                String name = "x509:CN=" + RustegonTestServer.X509_USER;
                dropUser(name);
                createUser(CreateUserRequest.newBuilder().setName(name).addRoles(grant(
                        "read_write@" + database)).build());
                users.add(name);
            }
            if (setup == null) {
                return users;
            }
            for (Map<String, Object> c : (List<Map<String, Object>>) setup.getOrDefault(
                    "collections", List.of())) {
                CreateCollectionOptions o = CreateCollectionOptions.defaults();
                if (c.get("validator") instanceof Map<?, ?> v) {
                    o = o.withValidator(OpRunner.validator((Map<String, Object>) v));
                }
                db.createCollection((String) c.get("name"), o);
            }
            for (Map<String, Object> ix : (List<Map<String, Object>>) setup.getOrDefault(
                    "indexes", List.of())) {
                List<IndexKey> keys = new ArrayList<>();
                for (Map<String, Object> k : (List<Map<String, Object>>) ix.get("keys")) {
                    keys.add(new IndexKey((String) k.get("path"),
                            Boolean.TRUE.equals(k.get("descending"))));
                }
                db.collection((String) ix.get("collection")).createIndex((String) ix.get("name"),
                        new IndexKeys(keys), new CreateIndexOptions(Boolean.TRUE.equals(
                                ix.get("unique"))));
            }
            if (setup.get("data") instanceof Map<?, ?> data) {
                for (Map.Entry<String, Object> e : ((Map<String, Object>) data).entrySet()) {
                    List<RDocument> docs = new ArrayList<>();
                    for (Object d : (List<Object>) e.getValue()) {
                        docs.add((RDocument) runner.v(d));
                    }
                    if (!docs.isEmpty()) {
                        db.collection(e.getKey()).insertMany(docs);
                    }
                }
            }
            for (Map<String, Object> u : (List<Map<String, Object>>) setup.getOrDefault(
                    "users", List.of())) {
                String name = (String) u.get("name");
                dropUser(name);
                CreateUserRequest.Builder r = CreateUserRequest.newBuilder().setName(name)
                        .setPassword((String) u.get("password"))
                        .setMustChangePassword(Boolean.TRUE.equals(u.get("mustChangePassword")));
                for (Object role : (List<Object>) u.get("roles")) {
                    r.addRoles(grant(substitute((String) role)));
                }
                createUser(r.build());
                users.add(name);
            }
            return users;
        }

        /** {@code role@db} / {@code role@db.coll} / {@code role} → {@code RoleGrant} (PD-051). */
        private static RoleGrant grant(String text) {
            int at = text.indexOf('@');
            if (at < 0) {
                return RoleGrant.newBuilder().setRole(text).build();
            }
            String scope = text.substring(at + 1);
            return RoleGrant.newBuilder().setRole(text.substring(0, at)).setResource(
                    (scope.contains(".") ? "collection:" : "database:") + scope).build();
        }

        private void createUser(CreateUserRequest r) {
            admin.ops().unary(AdminServiceGrpc.getCreateUserMethod(), r, Operations.Kind.NONE,
                    OpContext.NONE);
        }

        private void dropUser(String name) {
            try {
                admin.ops().unary(AdminServiceGrpc.getDropUserMethod(), DropUserRequest
                        .newBuilder().setName(name).build(), Operations.Kind.NONE,
                        OpContext.NONE);
            } catch (RustegonException e) {
                // not there
            }
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> checkOutcome(Map<String, Object> outcome, OpRunner runner) {
            Map<String, Object> actual = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : outcome.entrySet()) {
                List<RDocument> docs = admin.database(database).collection(e.getKey()).find()
                        .sort(Sorts.asc("_id")).toList();
                actual.put(e.getKey(), docs);
                String d = ConformanceValues.mismatch(runner.v(e.getValue()), docs, false, true,
                        false);
                if (d != null) {
                    throw new AssertionError("outcome " + e.getKey() + ": " + d);
                }
            }
            return actual;
        }

        private String substitute(String s) {
            if (!s.contains("${")) {
                return s;
            }
            Map<String, String> vars = new LinkedHashMap<>();
            vars.put("database", database);
            if (server != null) {
                String endpoint = server.grpcEndpoint();
                vars.put("host", endpoint.substring(0, endpoint.lastIndexOf(':')));
                vars.put("port", endpoint.substring(endpoint.lastIndexOf(':') + 1));
                vars.put("adminUser", RustegonTestServer.ADMIN_USER);
                vars.put("adminPassword", new String(server.adminPassword()));
                vars.put("adminUserEncoded", encode(RustegonTestServer.ADMIN_USER));
                vars.put("adminPasswordEncoded", encode(new String(server.adminPassword())));
                vars.put("caFile", server.caCertificate().toString());
                vars.put("caFileEncoded", encode(server.caCertificate().toString()));
                vars.put("clientCertFile", server.clientCertificate().toString());
                vars.put("clientKeyFile", server.clientKey().toString());
                if (s.contains("${apiKey}")) {
                    vars.put("apiKey", apiKey());
                }
            }
            String out = s;
            for (Map.Entry<String, String> e : vars.entrySet()) {
                if (e.getValue() != null) {
                    out = out.replace("${" + e.getKey() + "}", e.getValue());
                }
            }
            return out;
        }

        private static String encode(String s) {
            // The connection string reads '+' as a plus sign: spaces must be %20.
            return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
        }

        private String apiKey() {
            synchronized (ConformanceSuiteTest.class) {
                if (apiKey == null) {
                    apiKey = admin.ops().unary(AdminServiceGrpc.getCreateApiKeyMethod(),
                            CreateApiKeyRequest.newBuilder().setDescription(
                                    "java driver conformance").addRoles(RoleGrant.newBuilder()
                                    .setRole("root").setResource("cluster")).build(),
                            Operations.Kind.NONE,
                            OpContext.NONE).getSecret();
                }
                return apiKey;
            }
        }

        private OpRunner.Env env() {
            return new OpRunner.Env() {
                @Override
                public String substitute(String s) {
                    return FileRun.this.substitute(s);
                }

                @Override
                @SuppressWarnings("unchecked")
                public RustegonClient open(Map<String, Object> args, OpRunner runner) {
                    Map<String, Object> cred = (Map<String, Object>) args.get("credential");
                    RustegonClientSettings.Builder b;
                    if (cred.get("scram") instanceof Map<?, ?> s) {
                        b = server.settings(RustegonCredential.scram(substitute(
                                (String) s.get("user")), substitute((String) s.get("password"))
                                .toCharArray()));
                    } else if (cred.get("apiKey") instanceof String k) {
                        b = server.settings(RustegonCredential.apiKey(substitute(k)));
                    } else {
                        Map<String, Object> x = (Map<String, Object>) cred.get("x509");
                        b = server.settings(RustegonCredential.x509()).tls(TlsSettings.builder()
                                .caCertificate(server.caCertificate())
                                .clientCertificate(Path.of(substitute((String) x.get(
                                        "certificateFile"))), Path.of(substitute((String) x.get(
                                        "keyFile")))).build());
                    }
                    return RustegonClient.create(b.defaultDatabase(database)
                            .allowPasswordChangeOnly(Boolean.TRUE.equals(args.get(
                                    "allowPasswordChangeOnly"))).build());
                }

                @Override
                public Object runner(String name, Map<String, Object> args, OpRunner runner)
                        throws Exception {
                    String file = (String) args.get("file");
                    switch (name) {
                        case "sleep" -> Thread.sleep(((Number) args.get("ms")).longValue());
                        case "throwApplicationError" -> throw new OpRunner.ApplicationError();
                        case "assertLastErrorHasTraceId" -> {
                            if (!(runner.lastError() instanceof RustegonException e)
                                    || e.traceId().isEmpty()) {
                                throw new AssertionError("the last error has no trace id: "
                                        + runner.lastError());
                            }
                        }
                        case "checkAstVectors" -> none(AstVectors.check(dir.resolve(file)));
                        case "runRetryScenarios" -> none(RetryScenarios.run(dir.resolve(file)));
                        // The unit-level runners of TC-DRV-JAVA-001…008 (lane DJ1).
                        case "checkValueVectors" ->
                                new ConformanceCodecTest().tc_drv_java_001_conformance_values();
                        case "checkDocumentVectors" ->
                                new ConformanceCodecTest().tc_drv_java_001_conformance_documents();
                        case "checkInvalidVectors" ->
                                new ConformanceCodecTest().tc_drv_java_003_conformance_invalid_inputs();
                        case "checkErrorMapping" ->
                                new ErrorMappingTest().tc_drv_java_006_conformance_errors_map();
                        case "checkConnectionStrings" -> new ConnectionStringTest()
                                .tc_drv_java_008_conformance_connstring_cases();
                        case "checkScramVectors" -> {
                            new ScramTest().tc_drv_java_007_conformance_saslprep();
                            new ScramTest().tc_drv_java_007_conformance_exchanges();
                        }
                        default -> throw new AssertionError("runner." + name);
                    }
                    return null;
                }
            };
        }
    }

    private static void none(List<String> failures) {
        if (!failures.isEmpty()) {
            throw new AssertionError(failures.size() + " failures:\n"
                    + String.join("\n", failures));
        }
    }

    // ------------------------------------------------------------------ results file

    /** README §6: canonical extended JSON, sorted keys, volatile values as tokens. */
    @SuppressWarnings("unchecked")
    private static void writeResults() throws IOException {
        StringBuilder out = new StringBuilder();
        out.append("{\"driver\":\"java\",\"driverVersion\":").append(ExtendedJson.valueToJson(
                RustegonClient.DRIVER_VERSION, JsonMode.CANONICAL)).append(",\"serverVersion\":")
                .append(ExtendedJson.valueToJson(serverVersion, JsonMode.CANONICAL))
                .append(",\"results\":[");
        boolean first = true;
        for (Map<String, Object> r : new TreeMap<>(RESULTS).values()) {
            Map<String, Object> entry = new TreeMap<>(r);
            String text = (String) entry.remove("text");
            Tokens tokens = new Tokens(text == null ? "" : text);
            out.append(first ? "" : ",");
            first = false;
            out.append(tokens.json(entry));
        }
        out.append("]}\n");
        // One file per test task (JDK 21 and JDK 25), set by the Gradle build.
        Path file = Path.of(System.getProperty("rustegon.conformanceResults",
                "build/conformance-results.json"));
        Files.createDirectories(file.getParent());
        Files.writeString(file, out.toString());
    }

    /** Token replacement of one test's values (README §6). */
    private static final class Tokens {
        private static final Set<String> SYSTEM_FIELDS = Set.of("_rev", "_createdAt",
                "_updatedAt");
        private final String text;
        private final Map<String, String> oids = new LinkedHashMap<>();

        Tokens(String text) {
            this.text = text;
        }

        String json(Object v) {
            if (v instanceof Map<?, ?> m) {
                StringBuilder s = new StringBuilder("{");
                boolean first = true;
                for (Map.Entry<?, ?> e : new TreeMap<>(m).entrySet()) {
                    if (SYSTEM_FIELDS.contains(e.getKey())) {
                        continue;
                    }
                    s.append(first ? "" : ",");
                    first = false;
                    s.append(ExtendedJson.valueToJson(String.valueOf(e.getKey()),
                            JsonMode.CANONICAL)).append(':').append(json(e.getValue()));
                }
                return s.append('}').toString();
            }
            if (v instanceof List<?> l) {
                StringBuilder s = new StringBuilder("[");
                for (int i = 0; i < l.size(); i++) {
                    s.append(i == 0 ? "" : ",").append(json(l.get(i)));
                }
                return s.append(']').toString();
            }
            if (v instanceof ObjectId o && !text.contains(o.toString())) {
                return "\"" + oids.computeIfAbsent(o.toString(),
                        k -> "<oid:" + (oids.size() + 1) + ">") + "\"";
            }
            if (v instanceof Instant t) {
                String iso = ConformanceValues.scalar(t);
                String inner = iso.substring(iso.indexOf(":\"") + 2, iso.lastIndexOf('"'));
                return text.contains(inner) ? iso : "\"<datetime>\"";
            }
            if (v instanceof RustegonClient || v instanceof Cursor || v instanceof ClientSession
                    || v instanceof Transaction) {
                return "\"<handle>\"";
            }
            try {
                return ConformanceValues.scalar(v);
            } catch (RuntimeException e) {
                return ExtendedJson.valueToJson(String.valueOf(v), JsonMode.CANONICAL);
            }
        }
    }
}
