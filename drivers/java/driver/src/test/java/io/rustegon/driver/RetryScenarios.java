// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The runner operation {@code runRetryScenarios} (drivers/conformance/README.md §7–§8): every
 * scenario of {@code retry.yaml} runs against a fresh {@link FakeServer} with a fresh client,
 * and the outcome, the call counts, the request ids, the deadlines and the backoff delays are
 * checked against the scenario (rules R1–R6 of the file header).
 */
final class RetryScenarios {
    /** Tolerance of the delay check (retry.yaml header). */
    private static final long DELAY_TOLERANCE_MS = 250;

    private RetryScenarios() {}

    /** Runs every scenario; the failures, one line each (empty when all pass). */
    @SuppressWarnings("unchecked")
    static List<String> run(Path file) throws Exception {
        Map<String, Object> root = ConformanceValues.load(file);
        Map<String, Object> defaults = (Map<String, Object>) root.get("defaults");
        Map<String, Object> backoff = (Map<String, Object>) defaults.get("backoff");
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> s : (List<Map<String, Object>>) root.get("scenarios")) {
            try {
                String d = scenario(s, (Map<String, Object>) defaults.get("settings"), backoff);
                if (d != null) {
                    failures.add(s.get("name") + ": " + d);
                }
            } catch (Exception | AssertionError e) {
                failures.add(s.get("name") + ": " + e);
            }
        }
        return failures;
    }

    @SuppressWarnings("unchecked")
    private static String scenario(Map<String, Object> s, Map<String, Object> defaultSettings,
            Map<String, Object> backoff) throws Exception {
        Map<String, Object> settings = new HashMap<>(defaultSettings);
        if (s.get("settings") instanceof Map<?, ?> m) {
            settings.putAll((Map<String, Object>) m);
        }
        Map<String, List<Map<String, Object>>> script = s.get("server") == null ? Map.of()
                : (Map<String, List<Map<String, Object>>>) s.get("server");
        OpRunner.Env env = env();
        try (FakeServer server = new FakeServer(script,
                y -> ConformanceValues.value(y, r -> null, x -> x))) {
            RustegonClientSettings.Builder b = RustegonClientSettings.builder()
                    .endpoints(server.endpoint()).tls(TlsSettings.disabled())
                    .defaultDatabase("fake")
                    .retryReads((Boolean) settings.get("retryReads"))
                    .retryWrites((Boolean) settings.get("retryWrites"))
                    .maxRetries(((Number) settings.get("maxRetries")).intValue())
                    .defaultOperationTimeout(Duration.ofMillis(((Number) settings.get(
                            "operationTimeoutMs")).longValue()));
            b.credential("scram".equals(s.get("credential"))
                    ? RustegonCredential.scram(FakeServer.SCRAM_USER,
                            FakeServer.SCRAM_PASSWORD.toCharArray())
                    : RustegonCredential.apiKey("rgn_fake_key"));
            Map<String, Object> expect = (Map<String, Object>) s.get("expect");
            Map<String, Object> outcome = (Map<String, Object>) expect.get("outcome");
            Map<String, Object> op = new HashMap<>((Map<String, Object>) s.get("operation"));
            op.put("expect", outcome);
            if (outcome.containsKey("result")) {
                op.put("match", "subset");
            }
            try (RustegonClient client = RustegonClient.create(b.build())) {
                OpRunner runner = new OpRunner(client, "fake", "c", env);
                try {
                    runner.run(op);
                } catch (AssertionError e) {
                    return "outcome: " + e.getMessage();
                } catch (Exception e) {
                    return "unexpected " + e;
                } finally {
                    runner.closeOpened();
                }
            }
            return calls(server, expect, backoff);
        }
    }

    @SuppressWarnings("unchecked")
    private static String calls(FakeServer server, Map<String, Object> expect,
            Map<String, Object> backoff) {
        if (expect.get("calls") instanceof Map<?, ?> counts) {
            for (Map.Entry<String, Object> c : ((Map<String, Object>) counts).entrySet()) {
                int got = server.calls(c.getKey()).size();
                if (got != ((Number) c.getValue()).intValue()) {
                    return c.getKey() + " called " + got + " times, expected " + c.getValue();
                }
            }
        }
        if (expect.get("sameRequestId") instanceof List<?> rpcs) {
            for (Object rpc : rpcs) {
                Set<String> ids = new java.util.HashSet<>();
                for (FakeServer.Call c : server.calls((String) rpc)) {
                    ids.add(c.requestId == null ? "" : c.requestId);
                }
                if (ids.size() != 1 || ids.contains("")) {
                    return rpc + " request ids " + ids + ", expected one non-empty id";
                }
            }
        }
        if (Boolean.TRUE.equals(expect.get("grpcTimeoutSent"))) {
            for (FakeServer.Call c : server.calls()) {
                if (!c.deadline) {
                    return c.rpc + " without grpc-timeout";
                }
            }
        }
        if (expect.get("delays") instanceof List<?> delays) {
            long base = ((Number) backoff.get("baseMs")).longValue();
            long cap = ((Number) backoff.get("capMs")).longValue();
            List<Long> gaps = gaps(server);
            for (Object d : delays) {
                Map<String, Object> delay = (Map<String, Object>) d;
                int n = ((Number) delay.get("retry")).intValue();
                if (gaps.size() < n) {
                    return "no retry " + n + " (gaps " + gaps + ")";
                }
                long gap = gaps.get(n - 1);
                if (delay.get("minMs") instanceof Number min) {
                    if (gap < min.longValue()) {
                        return "retry " + n + " after " + gap + " ms, expected >= " + min;
                    }
                } else {
                    long max = Math.min(cap, base << (n - 1)) + DELAY_TOLERANCE_MS;
                    if (gap > max) {
                        return "retry " + n + " after " + gap + " ms, expected <= " + max;
                    }
                }
            }
        }
        return null;
    }

    /**
     * For each failed reply (in order; best-effort rollbacks excluded), the gap in ms until the
     * next call of the same RPC.
     */
    private static List<Long> gaps(FakeServer server) {
        List<FakeServer.Call> calls = server.calls();
        List<Long> out = new ArrayList<>();
        for (int i = 0; i < calls.size(); i++) {
            FakeServer.Call c = calls.get(i);
            if (!c.failed || c.rpc.equals("TransactionService.Rollback")) {
                continue;
            }
            for (int j = i + 1; j < calls.size(); j++) {
                if (calls.get(j).rpc.equals(c.rpc)) {
                    out.add((calls.get(j).arrivalNanos - c.replyNanos) / 1_000_000);
                    break;
                }
            }
        }
        return out;
    }

    private static OpRunner.Env env() {
        return new OpRunner.Env() {
            @Override
            public String substitute(String s) {
                return s;
            }

            @Override
            public RustegonClient open(Map<String, Object> args, OpRunner runner) {
                throw new AssertionError("retry scenarios do not open clients");
            }

            @Override
            public Object runner(String name, Map<String, Object> args, OpRunner runner) {
                if (name.equals("throwApplicationError")) {
                    throw new OpRunner.ApplicationError();
                }
                throw new AssertionError("runner." + name + " in a retry scenario");
            }
        };
    }
}
