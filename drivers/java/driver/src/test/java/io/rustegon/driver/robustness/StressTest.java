// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.robustness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.rustegon.driver.DropOptions;
import io.rustegon.driver.Filters;
import io.rustegon.driver.RustegonClient;
import io.rustegon.driver.RustegonCollection;
import io.rustegon.driver.rdoc.RDocument;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-029 (java-driver.md §1, §9; FR-DRV-002): 1000 concurrent operations through one
 * client against a real {@code rustegond}, once from 1000 platform threads and once from 1000
 * virtual threads. Each operation is an insert followed by a read of the same document, all
 * released together by a latch. Pass: every operation succeeds, the collection holds exactly
 * the written documents, everything finishes within {@link #BOUND} (a deadlock or a lost
 * wake-up shows as a timeout, reported with a thread dump and the JVM's deadlock detector),
 * and — virtual threads — no {@code jdk.VirtualThreadPinned} JFR event (threshold 0) is
 * recorded on a thread running driver code: blocking calls park the virtual thread instead of
 * its carrier (java-driver.md §1: no {@code synchronized} around blocking I/O). Runs on JDK 21
 * ({@code test}), where {@code synchronized} still pins, and JDK 25 ({@code testJdk25}).
 */
@Tag("integration")
class StressTest {
    private static final int OPERATIONS = 1000;
    /** Generous for debug builds of the server on a shared machine; typical runs take seconds. */
    private static final Duration BOUND = Duration.ofMinutes(3);

    private static OwnedServer server;

    @BeforeAll
    static void start() throws Exception {
        server = OwnedServer.start();
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    void tc_drv_java_029_platform_threads_1000_concurrent_operations() throws Exception {
        run("platform", Thread.ofPlatform().name("stress-", 0).factory());
    }

    @Test
    void tc_drv_java_029_virtual_threads_1000_concurrent_operations_without_pinning()
            throws Exception {
        Path jfr = Files.createTempFile("tc-drv-java-029", ".jfr");
        List<RecordedEvent> pinned = new ArrayList<>();
        try (Recording recording = new Recording()) {
            // Threshold 0: every park of a pinned virtual thread is recorded, not only long ones.
            recording.enable("jdk.VirtualThreadPinned").withThreshold(Duration.ZERO)
                    .withStackTrace();
            recording.start();
            run("virtual", Thread.ofVirtual().name("stress-", 0).factory());
            recording.stop();
            recording.dump(jfr);
            List<RecordedEvent> events = RecordingFile.readAllEvents(jfr);
            System.out.println("TC-DRV-JAVA-029 virtual: " + events.size()
                    + " jdk.VirtualThreadPinned events on Java " + Runtime.version().feature());
            for (RecordedEvent e : events) {
                // The stress threads run driver frames only (and this test's lambda, also
                // io.rustegon.*): a pinning anywhere below a call through the driver counts.
                if (e.getStackTrace() != null && e.getStackTrace().getFrames().stream()
                        .anyMatch(f -> f.getMethod().getType().getName()
                                .startsWith("io.rustegon."))) {
                    pinned.add(e);
                }
            }
        } finally {
            Files.deleteIfExists(jfr);
        }
        assertTrue(pinned.isEmpty(), () -> pinned.size() + " virtual-thread pinning events in "
                + "driver frames, first: " + pinned.get(0));
    }

    private static void run(String kind, ThreadFactory threads) throws Exception {
        String db = "stress_" + kind;
        try (RustegonClient client = RustegonClient.create(server.adminSettings().build())) {
            client.dropDatabase(db, DropOptions.whenExists());
            client.createDatabase(db);
            client.database(db).createCollection("items");
            RustegonCollection<RDocument> items = client.database(db).collection("items");
            CountDownLatch go = new CountDownLatch(1);
            List<Future<?>> futures = new ArrayList<>(OPERATIONS);
            long started;
            ExecutorService pool = Executors.newThreadPerTaskExecutor(threads);
            try {
                for (int i = 0; i < OPERATIONS; i++) {
                    String id = kind + "-" + i;
                    int n = i;
                    futures.add(pool.submit(() -> {
                        go.await();
                        items.insertOne(new RDocument().append("_id", id).append("n", (long) n));
                        RDocument back = items.findById(id).orElseThrow();
                        assertEquals((long) n, back.get("n"));
                        return null;
                    }));
                }
                started = System.nanoTime();
                go.countDown();
                long deadline = started + BOUND.toNanos();
                for (Future<?> f : futures) {
                    try {
                        f.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                    } catch (TimeoutException e) {
                        fail("TC-DRV-JAVA-029 (" + kind + "): not done within " + BOUND
                                + diagnostics());
                    }
                }
            } finally {
                pool.shutdownNow();
            }
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertEquals(OPERATIONS, items.find(Filters.empty()).toList().size());
            // Recorded for the test report only; no performance claim (CLAUDE.md rule 4).
            System.out.println("TC-DRV-JAVA-029 " + kind + ": " + OPERATIONS
                    + " insert+read operations in " + elapsedMs + " ms");
            client.dropDatabase(db);
        }
    }

    /** The JVM's deadlock detector and the stacks of the stuck stress threads. */
    private static String diagnostics() {
        var mx = ManagementFactory.getThreadMXBean();
        long[] deadlocked = mx.findDeadlockedThreads();
        StringBuilder out = new StringBuilder("; deadlocked platform threads: ")
                .append(deadlocked == null ? "none" : Arrays.toString(deadlocked));
        for (ThreadInfo t : mx.dumpAllThreads(true, true)) {
            if (t.getThreadName().startsWith("stress-") || t.getThreadName().startsWith("grpc")) {
                out.append('\n').append(t);
            }
        }
        return out.toString();
    }
}
