// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.CommitRequest;
import io.rustegon.driver.internal.proto.HeartbeatRequest;
import io.rustegon.driver.internal.proto.RollbackRequest;
import io.rustegon.driver.internal.proto.StatusRequest;
import io.rustegon.driver.internal.proto.TransactionServiceGrpc;
import io.rustegon.driver.rdoc.RDocument;
import java.time.Duration;
import java.util.concurrent.ScheduledFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An interactive transaction (transactions.md §3; {@code Transaction.*} of the model), from
 * {@link RustegonClient#beginTransaction}. Collection handles and queries obtained from it run
 * inside it; its operations are never retried one by one (retry rule R2: the whole transaction
 * is the unit of retry, see {@link RustegonClient#withTransaction}).
 *
 * <pre>{@code
 * try (Transaction tx = client.beginTransaction()) {
 *     tx.collection("accounts").updateOne(Filters.id("a1"), Updates.inc("balance", -10));
 *     tx.commit();
 * }   // close() rolls back when commit() was not reached
 * }</pre>
 *
 * <p><b>Liveness.</b> While the transaction is open the driver sends {@code Heartbeat} at the
 * interval the server asked for, so an idle transaction is not aborted after
 * {@code txn.liveness_timeout} (transactions.md §3). <b>Unknown commit.</b> RGN-2006 from
 * {@link #commit()} throws a {@link CommitOutcomeUnknownException} whose
 * {@link CommitOutcomeUnknownException#resolve()} (or {@link #resolve()}) asks the server for the
 * outcome; the driver never resolves it on its own in this mode.
 *
 * <p>Meant for one thread at a time; the heartbeat runs on the client's scheduler thread.
 */
public final class Transaction implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(Transaction.class);

    private enum State {
        ACTIVE, COMMITTED, ROLLED_BACK, UNKNOWN
    }

    private final RustegonClient client;
    private final Operations ops;
    private final String id;
    private final OpContext ctx;
    private final ScheduledFuture<?> heartbeat;
    private volatile State state = State.ACTIVE;

    Transaction(RustegonClient client, Operations ops, String id, long heartbeatMillis) {
        this.client = client;
        this.ops = ops;
        this.id = id;
        this.ctx = OpContext.NONE.withTxn(id);
        this.heartbeat = heartbeatMillis <= 0 ? null : ops.every(heartbeatMillis, () -> beat(
                heartbeatMillis));
    }

    private void beat(long intervalMillis) {
        try {
            ops.unary(TransactionServiceGrpc.getHeartbeatMethod(), HeartbeatRequest.newBuilder()
                    .setTxnId(id).build(), Operations.Kind.NONE,
                    ctx.withTimeout(Duration.ofMillis(Math.max(1000, intervalMillis))));
        } catch (RuntimeException e) {
            // The next operation reports the transaction's fate; a heartbeat must not throw on
            // the scheduler thread (that would cancel the schedule silently).
            LOG.debug("heartbeat of a transaction failed: {}", e.getMessage());
        }
    }

    /**
     * The transaction id (canonical UUID text).
     *
     * @return the id
     */
    public String id() {
        return id;
    }

    /**
     * A collection handle whose calls run in this transaction ({@code Transaction.GetCollection}).
     *
     * @param name {@code "db.coll"}, or {@code "coll"} in the client's default database
     * @param type the document type: {@link RDocument} or a mapped type
     *     ({@link io.rustegon.driver.mapping.Mapper})
     * @param <T> the document type
     * @return the handle
     */
    public <T> RustegonCollection<T> collection(String name, Class<T> type) {
        int dot = name.indexOf('.');
        RustegonDatabase db = dot < 0 ? client.database() : client.database(name.substring(0,
                dot));
        return new RustegonCollection<>(new RustegonDatabase(ops, db.name(), ctx),
                dot < 0 ? name : name.substring(dot + 1), DocCodec.of(type), ctx);
    }

    /**
     * A schemaless collection handle whose calls run in this transaction.
     *
     * @param name {@code "db.coll"} or {@code "coll"}
     * @return the handle
     */
    public RustegonCollection<RDocument> collection(String name) {
        return collection(name, RDocument.class);
    }

    /**
     * Runs RGQL text in this transaction, with the client's default database for unqualified
     * names ({@code Transaction.Query}).
     *
     * @param rgql the statement
     * @param params the parameters
     * @param type the row type
     * @param <T> the row type
     * @return the rows (close the cursor)
     * @throws RustegonException on failure
     */
    public <T> Cursor<T> query(String rgql, Params params, Class<T> type) {
        RustegonDatabase db = client.database();
        return new RustegonDatabase(ops, db.name(), ctx).query(rgql, params,
                QueryOptions.defaults(), type, ctx);
    }

    /**
     * Commits ({@code TransactionService.Commit}). Committing a committed transaction returns
     * the same result (FR-TXN-006).
     *
     * @throws CommitOutcomeUnknownException on RGN-2006, also synthesized when the call fails in
     *     transport after it was sent (PD-122): resolve it, never re-run blindly
     * @throws RustegonException on other failures (the transaction is then aborted)
     */
    public void commit() {
        try {
            ops.commit(TransactionServiceGrpc.getCommitMethod(), CommitRequest.newBuilder()
                    .setTxnId(id).build(), ctx);
            state = State.COMMITTED;
            stopHeartbeat();
        } catch (CommitOutcomeUnknownException e) {
            state = State.UNKNOWN;
            stopHeartbeat();
            throw new CommitOutcomeUnknownException(e.getMessage(), e.error(), e, this::resolve);
        }
    }

    /**
     * Rolls back ({@code TransactionService.Rollback}); idempotent.
     *
     * @throws RustegonException on failure
     */
    public void rollback() {
        stopHeartbeat();
        ops.unary(TransactionServiceGrpc.getRollbackMethod(), RollbackRequest.newBuilder()
                .setTxnId(id).build(), Operations.Kind.NONE, ctx);
        state = State.ROLLED_BACK;
    }

    /**
     * Asks the server whether this transaction committed ({@code TransactionService.Status}).
     *
     * @return {@code COMMITTED}, {@code ABORTED}, or {@code UNKNOWN} while it is active or
     *     committing
     * @throws RustegonException on failure
     */
    public TransactionOutcome resolve() {
        return switch (ops.unary(TransactionServiceGrpc.getStatusMethod(), StatusRequest
                .newBuilder().setTxnId(id).build(), Operations.Kind.NONE, ctx).getState()) {
            case TRANSACTION_STATE_COMMITTED -> TransactionOutcome.COMMITTED;
            case TRANSACTION_STATE_ABORTED -> TransactionOutcome.ABORTED;
            default -> TransactionOutcome.UNKNOWN;
        };
    }

    /**
     * Rolls back unless {@link #commit()} succeeded or the transaction was rolled back already
     * (best effort: the server also aborts an abandoned transaction); stops the heartbeat. An
     * unknown commit outcome is left alone.
     */
    @Override
    public void close() {
        stopHeartbeat();
        if (state == State.ACTIVE) {
            try {
                rollback();
            } catch (RustegonException | IllegalStateException e) {
                LOG.debug("rollback at close failed: {}", e.getMessage());
            }
        }
    }

    void stopHeartbeat() {
        if (heartbeat != null) {
            heartbeat.cancel(false);
        }
    }
}
