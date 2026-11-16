// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.internal.proto.BeginRequest;
import io.rustegon.driver.internal.proto.BulkWriteRequest;
import io.rustegon.driver.internal.proto.DeleteRequest;
import io.rustegon.driver.internal.proto.ExecuteRequest;
import io.rustegon.driver.internal.proto.GetMoreRequest;
import io.rustegon.driver.internal.proto.GetRequest;
import io.rustegon.driver.internal.proto.InsertRequest;
import io.rustegon.driver.internal.proto.KillCursorRequest;
import io.rustegon.driver.internal.proto.ReadConsistencyLevel;
import io.rustegon.driver.internal.proto.UpdateRequest;
import io.rustegon.driver.rdoc.RDocument;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Client API behaviour on the in-process fake server (FR-DRV-002):
 *
 * <ul>
 *   <li>TC-DRV-JAVA-019: read consistency, staleness and write concern are sent on every
 *       data-plane request whose proto has the field, per-handle overrides win, transactions
 *       carry their id instead; the connect timeout is enforced per call (PD-081 option (a));
 *       a session sends the last causality token it received (PD-069);
 *   <li>TC-DRV-JAVA-012: a cursor fetches with GetMore at its batch size and kills an unfinished
 *       server cursor on close;
 *   <li>TC-DRV-JAVA-016: in manual mode RGN-2006 surfaces as
 *       {@link CommitOutcomeUnknownException} whose {@code resolve()} asks
 *       {@code TransactionService.Status}.
 * </ul>
 */
class DataPlaneUnitTest {
    private static FakeServer fake(Map<String, List<Map<String, Object>>> script)
            throws IOException {
        return new FakeServer(script, y -> ConformanceValues.value(y, r -> null, s -> s));
    }

    private static RustegonClientSettings.Builder settings(FakeServer server) {
        return RustegonClientSettings.builder().endpoints(server.endpoint())
                .tls(TlsSettings.disabled()).defaultDatabase("fake")
                .credential(RustegonCredential.apiKey("rgn_fake_key"));
    }

    @SuppressWarnings("unchecked")
    private static <T> T last(FakeServer server, String rpc) {
        List<FakeServer.Call> calls = server.calls(rpc);
        assertFalse(calls.isEmpty(), "no " + rpc);
        return (T) calls.get(calls.size() - 1).request;
    }

    @Test
    void tc_drv_java_019_consistency_and_write_concern_are_sent_on_the_wire() throws Exception {
        try (FakeServer server = fake(Map.of());
                RustegonClient client = RustegonClient.create(settings(server)
                        .readConsistency(ReadConsistency.BOUNDED_STALENESS)
                        .maxStaleness(Duration.ofSeconds(5))
                        .writeConcern(WriteConcern.ALL).build())) {
            RustegonCollection<RDocument> c = client.database().collection("c");
            c.findById(1);
            GetRequest get = last(server, "DocumentService.Get");
            assertEquals(ReadConsistencyLevel.READ_CONSISTENCY_LEVEL_BOUNDED_STALENESS,
                    get.getConsistency().getLevel());
            assertEquals(5000, get.getConsistency().getMaxStalenessMs());

            c.insertOne(RDocument.of("_id", 1));
            InsertRequest insert = last(server, "DocumentService.Insert");
            assertEquals(io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_ALL,
                    insert.getOptions().getWriteConcern());

            c.find(Filters.eq("a", 1)).batchSize(7).toList();
            ExecuteRequest find = last(server, "QueryService.Execute");
            assertEquals(ReadConsistencyLevel.READ_CONSISTENCY_LEVEL_BOUNDED_STALENESS,
                    find.getOptions().getConsistency().getLevel());
            assertEquals(7, find.getOptions().getBatchSize());
            assertEquals(1, find.getOptions().getMaxBatches());
            assertTrue(find.hasAst(), "builders send the AST, never RGQL text (PD-070)");

            c.updateMany(Filters.eq("a", 1), Updates.set("b", 2));
            ExecuteRequest update = last(server, "QueryService.Execute");
            assertEquals(io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_ALL,
                    update.getOptions().getWriteConcern());

            c.updateOne(Filters.id(1), Updates.inc("n", 1));
            UpdateRequest byId = last(server, "DocumentService.Update");
            assertEquals(io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_ALL,
                    byId.getOptions().getWriteConcern());
            c.deleteOne(Filters.id(1));
            DeleteRequest delete = last(server, "DocumentService.Delete");
            assertEquals(io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_ALL,
                    delete.getOptions().getWriteConcern());
            c.bulkWrite(List.of(BulkOperation.delete(1)));
            BulkWriteRequest bulk = last(server, "DocumentService.BulkWrite");
            assertEquals(io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_ALL,
                    bulk.getOptions().getWriteConcern());

            // Per-handle overrides win over the client settings.
            c.withReadConsistency(ReadConsistency.LINEARIZABLE).findById(1);
            GetRequest linear = last(server, "DocumentService.Get");
            assertEquals(ReadConsistencyLevel.READ_CONSISTENCY_LEVEL_LINEARIZABLE,
                    linear.getConsistency().getLevel());
            assertFalse(linear.getConsistency().hasMaxStalenessMs());
            c.withWriteConcern(WriteConcern.MAJORITY).insertOne(RDocument.of("_id", 2));
            assertEquals(io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_MAJORITY,
                    ((InsertRequest) last(server, "DocumentService.Insert")).getOptions()
                            .getWriteConcern());
            assertThrows(IllegalArgumentException.class,
                    () -> c.withReadConsistency(ReadConsistency.BOUNDED_STALENESS));

            // Inside a transaction: the txn id, and the commit concern on Begin instead.
            try (Transaction txn = client.beginTransaction()) {
                txn.collection("c").insertOne(RDocument.of("_id", 3));
                InsertRequest inTxn = last(server, "DocumentService.Insert");
                assertEquals(FakeServer.TXN_ID, inTxn.getTxnId());
                assertEquals(
                        io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_UNSPECIFIED,
                        inTxn.getOptions().getWriteConcern());
                txn.collection("fake.c").findById(3);
                GetRequest getInTxn = last(server, "DocumentService.Get");
                assertEquals(FakeServer.TXN_ID, getInTxn.getTxnId());
                assertFalse(getInTxn.hasConsistency());
                txn.commit();
            }
            BeginRequest begin = last(server, "TransactionService.Begin");
            assertEquals(io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_ALL,
                    begin.getWriteConcern());
            assertFalse(begin.hasConsistency(), "read-write transactions take no consistency");
        }
    }

    @Test
    @Timeout(30)
    void tc_drv_java_019_connect_timeout_is_enforced_per_call() throws Exception {
        // A listener that accepts TCP connections and never answers the TLS handshake: the
        // channel stays CONNECTING, which only the connect timeout ends (PD-081).
        try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
                RustegonClient client = RustegonClient.create(RustegonClientSettings.builder()
                        .endpoints("127.0.0.1:" + silent.getLocalPort())
                        .connectTimeout(Duration.ofMillis(300)).maxRetries(0)
                        .defaultOperationTimeout(Duration.ofSeconds(25)).build())) {
            long start = System.nanoTime();
            RustegonException e = assertThrows(RustegonException.class, client::ping);
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertInstanceOf(UnavailableException.class, e);
            assertEquals(3002, e.code());
            assertTrue(e.isRetryable());
            assertTrue(ms < 5000, "failed after " + ms + " ms, expected about 300 ms");
        }
    }

    @Test
    void tc_drv_java_019_sessions_pass_the_causality_token_through() throws Exception {
        try (FakeServer server = fake(Map.of());
                RustegonClient client = RustegonClient.create(settings(server).build())) {
            ClientSession session = client.startSession();
            RustegonCollection<RDocument> c = client.database().collection("c")
                    .withSession(session);
            assertTrue(session.causalityToken().isEmpty());
            c.findById(1);
            String first = session.causalityToken().orElseThrow();
            assertNull(server.calls("DocumentService.Get").get(0).causalityToken);
            c.findById(2);
            assertEquals(first, server.calls("DocumentService.Get").get(1).causalityToken,
                    "the session sends the token it received");
            assertFalse(first.equals(session.causalityToken().orElseThrow()));
            // A call without the session neither sends nor records a token.
            String now = session.causalityToken().orElseThrow();
            client.database().collection("c").findById(3);
            assertNull(server.calls("DocumentService.Get").get(2).causalityToken);
            assertEquals(now, session.causalityToken().orElseThrow());
            session.close();
            session.close();
            assertThrows(IllegalStateException.class, () -> c.findById(4));
        }
    }

    @Test
    void tc_drv_java_012_cursor_uses_get_more_and_kills_on_close() throws Exception {
        Map<String, List<Map<String, Object>>> script = Map.of(
                "QueryService.Execute", List.of(Map.of("ok", Map.of("batches", List.of(Map.of(
                        "docs", List.of(Map.of("_id", 1)), "cursorId", "c-9"))))),
                "QueryService.GetMore", List.of(Map.of("ok", Map.of("batch", Map.of(
                        "docs", List.of(Map.of("_id", 2)), "cursorId", "c-9")))));
        try (FakeServer server = fake(script);
                RustegonClient client = RustegonClient.create(settings(server).build())) {
            try (Cursor<RDocument> cur = client.database().collection("c").find().batchSize(1)
                    .cursor()) {
                assertEquals(1L, cur.next().get("_id"));
                assertEquals(2L, cur.next().get("_id"));
            }
            GetMoreRequest more = last(server, "QueryService.GetMore");
            assertEquals("c-9", more.getCursorId());
            assertEquals(1, more.getBatchSize());
            KillCursorRequest kill = last(server, "QueryService.KillCursor");
            assertEquals("c-9", kill.getCursorId());
        }
    }

    @Test
    void tc_drv_java_016_with_transaction_failed_status_poll_keeps_polling_without_rerun()
            throws Exception {
        Map<String, List<Map<String, Object>>> script = Map.of(
                "TransactionService.Commit", List.of(Map.of("error", Map.of("code", 2006,
                        "retryable", false))),
                "TransactionService.Status", List.of(
                        Map.of("error", Map.of("code", 3004, "retryable", true)),
                        Map.of("ok", Map.of("state", "TRANSACTION_STATE_COMMITTED"))));
        try (FakeServer server = fake(script);
                RustegonClient client = RustegonClient.create(settings(server).build())) {
            java.util.concurrent.atomic.AtomicInteger runs =
                    new java.util.concurrent.atomic.AtomicInteger();
            String result = client.withTransaction(txn -> {
                runs.incrementAndGet();
                txn.collection("c").insertOne(RDocument.of("_id", 1));
                return "done";
            });
            assertEquals("done", result);
            assertEquals(1, runs.get());
            assertEquals(1, server.calls("TransactionService.Begin").size());
            assertEquals(2, server.calls("TransactionService.Status").size());
            assertEquals(0, server.calls("TransactionService.Rollback").size());
        }
    }

    @Test
    void tc_drv_java_016_with_transaction_status_failing_until_deadline_stays_unknown()
            throws Exception {
        Map<String, List<Map<String, Object>>> script = Map.of(
                "TransactionService.Commit", List.of(Map.of("error", Map.of("code", 2006,
                        "retryable", false))),
                "TransactionService.Status", List.of(
                        Map.of("error", Map.of("code", 3004, "retryable", true))));
        try (FakeServer server = fake(script);
                RustegonClient client = RustegonClient.create(settings(server).build())) {
            java.util.concurrent.atomic.AtomicInteger runs =
                    new java.util.concurrent.atomic.AtomicInteger();
            CommitOutcomeUnknownException e = assertThrows(CommitOutcomeUnknownException.class,
                    () -> client.withTransaction(TransactionOptions.defaults()
                            .maxRetryTime(Duration.ofMillis(300)), txn -> {
                                runs.incrementAndGet();
                                txn.collection("c").insertOne(RDocument.of("_id", 1));
                                return null;
                            }));
            assertEquals(2006, e.code());
            assertEquals(1, runs.get());
            assertEquals(1, server.calls("TransactionService.Begin").size());
            assertTrue(server.calls("TransactionService.Status").size() >= 1);
            assertEquals(0, server.calls("TransactionService.Rollback").size());
        }
    }

    @Test
    void tc_drv_java_016_manual_commit_unknown_resolves_through_the_exception()throws Exception {
        Map<String, List<Map<String, Object>>> script = Map.of(
                "TransactionService.Commit", List.of(Map.of("error", Map.of("code", 2006,
                        "retryable", false))),
                "TransactionService.Status", List.of(
                        Map.of("ok", Map.of("state", "TRANSACTION_STATE_COMMITTING")),
                        Map.of("ok", Map.of("state", "TRANSACTION_STATE_COMMITTED"))));
        try (FakeServer server = fake(script);
                RustegonClient client = RustegonClient.create(settings(server).build())) {
            CommitOutcomeUnknownException e;
            try (Transaction txn = client.beginTransaction()) {
                txn.collection("c").insertOne(RDocument.of("_id", 1));
                e = assertThrows(CommitOutcomeUnknownException.class, txn::commit);
            }
            assertEquals(2006, e.code());
            assertEquals(TransactionOutcome.UNKNOWN, e.resolve());
            assertEquals(TransactionOutcome.COMMITTED, e.resolve());
            // close() after an unknown outcome does not roll back.
            assertEquals(0, server.calls("TransactionService.Rollback").size());
            assertThrows(IllegalStateException.class, () -> new CommitOutcomeUnknownException(
                    "x", e.error(), null).resolve());
        }
    }
}
