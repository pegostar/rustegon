// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.ChannelPool;
import io.rustegon.driver.internal.RequestInterceptor;
import io.rustegon.driver.internal.proto.AdminServiceGrpc;
import io.rustegon.driver.internal.proto.AstIsolation;
import io.rustegon.driver.internal.proto.BeginRequest;
import io.rustegon.driver.internal.proto.BeginResponse;
import io.rustegon.driver.internal.proto.ChangePasswordRequest;
import io.rustegon.driver.internal.proto.CreateDatabaseRequest;
import io.rustegon.driver.internal.proto.DatabaseInfo;
import io.rustegon.driver.internal.proto.DropDatabaseRequest;
import io.rustegon.driver.internal.proto.GetServerInfoRequest;
import io.rustegon.driver.internal.proto.GetServerInfoResponse;
import io.rustegon.driver.internal.proto.ListDatabasesRequest;
import io.rustegon.driver.internal.proto.PingRequest;
import io.rustegon.driver.internal.proto.SchemaServiceGrpc;
import io.rustegon.driver.internal.proto.SessionServiceGrpc;
import io.rustegon.driver.internal.proto.TransactionServiceGrpc;
import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Rustegon client (java-driver.md, FR-DRV-002): thread-safe, long-lived, owns the
 * connection pool; create one per application and {@link #close()} it on shutdown.
 *
 * <pre>{@code
 * try (RustegonClient client = RustegonClient.create(RustegonClientSettings.builder()
 *         .endpoints("node1.example.com:7700")
 *         .credential(RustegonCredential.scram("app_user", password))
 *         .tls(TlsSettings.builder().caCertificate(Path.of("/etc/rustegon/ca.crt")).build())
 *         .defaultDatabase("shop")
 *         .build())) {
 *     RustegonCollection<RDocument> orders = client.database().collection("orders");
 *     orders.insertOne(RDocument.of("_id", 1).append("status", "paid"));
 *     List<RDocument> paid = orders.find(Filters.eq("status", "paid")).toList();
 * }
 * }</pre>
 *
 * <p>The R1 driver offers the synchronous API (java-driver.md §3 "R1 scope"): calls block the
 * calling thread and are well suited to virtual threads (no monitor is held while waiting).
 * Authentication is lazy: the first call that needs it performs the handshake, and an expired
 * session (RGN-4005) is renewed once transparently. Retryable failures are retried by the
 * policy of {@code retry.yaml} (settings {@code retryReads}, {@code retryWrites},
 * {@code maxRetries}).
 */
public final class RustegonClient implements AutoCloseable {
    /** Driver version reported to the server ({@code client_info.driver_version}). */
    public static final String DRIVER_VERSION = version();
    private static final Logger LOG = LoggerFactory.getLogger(RustegonClient.class);

    private final RustegonClientSettings settings;
    private final Operations ops;

    private RustegonClient(RustegonClientSettings settings) {
        RustegonCredential credential = settings.credential().orElse(null);
        if (credential != null && credential.mechanism() == RustegonCredential.Mechanism.X509
                && (!settings.tls().enabled() || (credential.keyManager() == null
                        && !settings.tls().hasClientCertificate()))) {
            throw new IllegalArgumentException(
                    "an X.509 credential needs TLS with a client certificate");
        }
        this.settings = settings;
        ChannelPool pool = ChannelPool.open(settings.endpoints(), settings.tls(),
                settings.connectionsPerEndpoint(),
                new RequestInterceptor(settings.defaultOperationTimeout()),
                "rustegon-java/" + DRIVER_VERSION,
                credential == null ? null : credential.keyManager());
        SessionAuth auth = new SessionAuth(credential, settings.applicationName().orElse(null),
                settings.defaultOperationTimeout(), settings.allowPasswordChangeOnly());
        this.ops = new Operations(settings, pool, auth);
    }

    private static String version() {
        String v = RustegonClient.class.getPackage().getImplementationVersion();
        return v == null ? "0.0.0-dev" : v;
    }

    /**
     * Creates a client. No connection is made until the first call.
     *
     * @param settings the settings
     * @return the client
     * @throws IllegalArgumentException if a TLS file cannot be read, or for an X.509 credential
     *     without a client certificate
     */
    public static RustegonClient create(RustegonClientSettings settings) {
        return new RustegonClient(settings);
    }

    /**
     * Creates a client from a {@code rustegon://} connection string.
     *
     * @param connectionString the string ({@link ConnectionString})
     * @return the client
     * @throws IllegalArgumentException if the string is invalid
     */
    public static RustegonClient create(String connectionString) {
        return create(RustegonClientSettings.fromConnectionString(connectionString));
    }

    /**
     * The settings of this client.
     *
     * @return the settings
     */
    public RustegonClientSettings settings() {
        return settings;
    }

    /** The call runner (tests and the conformance runner use it for admin calls). */
    Operations ops() {
        return ops;
    }

    /**
     * Round trip to a node ({@code SessionService.Ping}); authenticates first when the client
     * has a credential.
     *
     * @throws RustegonException on failure ({@link AuthenticationException} for rejected
     *     credentials, {@link UnavailableException} when no node answers)
     * @throws java.util.concurrent.CancellationException if the calling thread is interrupted
     *     (the interrupt flag stays set)
     * @throws IllegalStateException if the client is closed
     */
    public void ping() {
        ops.unary(SessionServiceGrpc.getPingMethod(), PingRequest.getDefaultInstance(),
                Operations.Kind.READ, OpContext.NONE);
    }

    /**
     * Versions and capabilities of a node ({@code SessionService.GetServerInfo}).
     *
     * @return the server information
     * @throws RustegonException on failure
     */
    public ServerInfo serverInfo() {
        GetServerInfoResponse r = ops.unary(SessionServiceGrpc.getGetServerInfoMethod(),
                GetServerInfoRequest.getDefaultInstance(), Operations.Kind.READ, OpContext.NONE);
        return new ServerInfo(r.getServerVersion(), r.getProtocolVersion(), r.getFeaturesList(),
                r.getNodeAddressesList());
    }

    // ------------------------------------------------------------------ databases

    /**
     * A database handle. No I/O.
     *
     * @param name the database name
     * @return the handle
     */
    public RustegonDatabase database(String name) {
        return new RustegonDatabase(ops, name, OpContext.NONE);
    }

    /**
     * The default database of the settings. No I/O.
     *
     * @return the handle
     * @throws IllegalStateException without a default database
     */
    public RustegonDatabase database() {
        return database(settings.defaultDatabase().orElseThrow(() -> new IllegalStateException(
                "no default database in the settings")));
    }

    /**
     * The database names, sorted ({@code SchemaService.ListDatabases}).
     *
     * @return the names
     * @throws RustegonException on failure
     */
    public List<String> listDatabaseNames() {
        return ops.unary(SchemaServiceGrpc.getListDatabasesMethod(),
                ListDatabasesRequest.getDefaultInstance(), Operations.Kind.READ, OpContext.NONE)
                .getDatabasesList().stream().map(DatabaseInfo::getName).sorted().toList();
    }

    /**
     * Creates a database.
     *
     * @param name the name
     * @return {@code true}
     * @throws RustegonException RGN-1031 when it exists
     */
    public boolean createDatabase(String name) {
        return createDatabase(name, CreateDatabaseOptions.defaults());
    }

    /**
     * Creates a database.
     *
     * @param name the name
     * @param options options (if-not-exists)
     * @return whether it was created
     * @throws RustegonException on failure
     */
    public boolean createDatabase(String name, CreateDatabaseOptions options) {
        return ops.unary(SchemaServiceGrpc.getCreateDatabaseMethod(), CreateDatabaseRequest
                .newBuilder().setName(name).setIfNotExists(options.ifNotExists()).build(),
                Operations.Kind.NONE, OpContext.NONE).getCreated();
    }

    /**
     * Drops a database with its collections.
     *
     * @param name the name
     * @return {@code true}
     * @throws RustegonException RGN-1030 when it does not exist
     */
    public boolean dropDatabase(String name) {
        return dropDatabase(name, DropOptions.defaults());
    }

    /**
     * Drops a database with its collections.
     *
     * @param name the name
     * @param options options (if-exists)
     * @return whether it was dropped
     * @throws RustegonException on failure
     */
    public boolean dropDatabase(String name, DropOptions options) {
        return ops.unary(SchemaServiceGrpc.getDropDatabaseMethod(), DropDatabaseRequest
                .newBuilder().setName(name).setIfExists(options.ifExists()).build(),
                Operations.Kind.NONE, OpContext.NONE).getDropped();
    }

    // ------------------------------------------------------------------ sessions

    /**
     * Starts a session with causal consistency (no server call in R1, PD-069).
     *
     * @return the session
     */
    public ClientSession startSession() {
        return startSession(SessionOptions.defaults());
    }

    /**
     * Starts a session (no server call in R1, PD-069); bind it to handles with
     * {@code withSession}.
     *
     * @param options the options
     * @return the session
     */
    public ClientSession startSession(SessionOptions options) {
        ops.ensureOpen();
        return new ClientSession(Objects.requireNonNull(options, "options"));
    }

    // ------------------------------------------------------------------ transactions

    /**
     * Begins an interactive transaction with the default options.
     *
     * @return the transaction (close it)
     * @throws RustegonException on failure
     */
    public Transaction beginTransaction() {
        return beginTransaction(TransactionOptions.defaults());
    }

    /**
     * Begins an interactive transaction ({@code TransactionService.Begin}); the client's write
     * concern applies at commit.
     *
     * @param options the options
     * @return the transaction (close it: an uncommitted transaction is rolled back)
     * @throws RustegonException on failure
     */
    public Transaction beginTransaction(TransactionOptions options) {
        BeginRequest.Builder r = BeginRequest.newBuilder().setReadOnly(options.isReadOnly())
                .setWriteConcern(ops.writeConcern(OpContext.NONE));
        options.isolation().ifPresent(i -> r.setIsolation(AstIsolation.valueOf(
                "AST_ISOLATION_" + i.name())));
        var consistency = ops.readConsistency(OpContext.NONE);
        // The server accepts a consistency on read-only transactions only.
        if (options.isReadOnly() && consistency != null) {
            r.setConsistency(consistency);
        }
        BeginResponse resp = ops.unary(TransactionServiceGrpc.getBeginMethod(), r.build(),
                Operations.Kind.NONE, OpContext.NONE);
        return new Transaction(this, ops, resp.getTxnId(),
                Integer.toUnsignedLong(resp.getHeartbeatIntervalMs()));
    }

    /**
     * {@link #withTransaction(TransactionOptions, TransactionCallback)} with the default
     * options.
     *
     * @param callback the work
     * @param <T> the result type
     * @return the callback's result
     */
    public <T> T withTransaction(TransactionCallback<T> callback) {
        return withTransaction(TransactionOptions.defaults(), callback);
    }

    /**
     * Runs {@code callback} in a transaction and commits it, retrying the whole transaction on
     * retryable failures (transactions.md §5, normative):
     *
     * <ul>
     *   <li>a failure whose {@code isRetryable()} is true — from the callback or the commit —
     *       rolls back (best effort), waits a full-jitter backoff (base 10 ms, ×2, cap 1 s) and
     *       re-runs the callback in a new transaction while less than
     *       {@link TransactionOptions#maxRetryTime()} has passed since the start;
     *   <li>RGN-2006 on commit is resolved with {@code TransactionService.Status}, never by
     *       re-running blindly: committed → return; aborted → re-run like a retryable failure;
     *       still active or committing → ask again with the same backoff until the budget is
     *       spent, then throw {@link CommitOutcomeUnknownException};
     *   <li>other failures, and any exception thrown by the callback itself, roll back and
     *       propagate unchanged.
     * </ul>
     *
     * <p>The callback must be idempotent with respect to external side effects.
     *
     * @param options the options
     * @param callback the work
     * @param <T> the result type
     * @return the callback's result
     * @throws RustegonException the last failure
     */
    public <T> T withTransaction(TransactionOptions options, TransactionCallback<T> callback) {
        Objects.requireNonNull(callback, "callback");
        long deadline = System.nanoTime() + options.maxRetryTime().toNanos();
        int attempt = 0;
        while (true) {
            Transaction txn = beginTransaction(options);
            RustegonException failure;
            try {
                T result = callback.run(txn);
                try {
                    txn.commit();
                    return result;
                } catch (CommitOutcomeUnknownException unknown) {
                    if (resolveCommit(txn, unknown, deadline)) {
                        return result;
                    }
                    // Status says ABORTED: nothing was written, so re-running is safe.
                    failure = unknown;
                }
            } catch (CommitOutcomeUnknownException e) {
                // Still unknown at the deadline: never roll back or re-run (transactions.md §5).
                throw e;
            } catch (RustegonException e) {
                rollbackQuietly(txn);
                if (!e.isRetryable() || System.nanoTime() - deadline >= 0) {
                    throw e;
                }
                failure = e;
            } catch (RuntimeException | Error e) {
                rollbackQuietly(txn);
                throw e;
            } finally {
                txn.stopHeartbeat();
            }
            if (System.nanoTime() - deadline >= 0) {
                throw failure;
            }
            attempt++;
            LOG.debug("transaction attempt {} failed with RGN-{}; retrying", attempt,
                    failure.code());
            Operations.sleep(Operations.backoffMillis(attempt, null));
        }
    }

    /**
     * Resolves an unknown commit: {@code true} when it committed, {@code false} when it
     * aborted; throws {@code unknown} when the outcome is still open at the deadline.
     */
    private static boolean resolveCommit(Transaction txn, CommitOutcomeUnknownException unknown,
            long deadline) {
        for (int poll = 1; ; poll++) {
            TransactionOutcome outcome;
            try {
                outcome = txn.resolve();
            } catch (RustegonException e) {
                // A failed Status poll leaves the outcome unknown: keep polling, never
                // re-run or roll back while it could have committed (transactions.md §5).
                LOG.debug("transaction status poll failed with RGN-{}", e.code());
                outcome = TransactionOutcome.UNKNOWN;
            }
            switch (outcome) {
                case COMMITTED -> {
                    return true;
                }
                case ABORTED -> {
                    return false;
                }
                default -> {
                    if (System.nanoTime() - deadline >= 0) {
                        throw unknown;
                    }
                    Operations.sleep(Operations.backoffMillis(poll, null));
                }
            }
        }
    }

    private static void rollbackQuietly(Transaction txn) {
        try {
            txn.rollback();
        } catch (RustegonException | IllegalStateException e) {
            // Best effort (transactions.md §5): the server aborts the transaction anyway.
            LOG.debug("rollback after a failed attempt failed: {}", e.getMessage());
        }
    }

    // ------------------------------------------------------------------ passwords and close

    /**
     * Whether the last login reported that the password must be changed (PD-076); only
     * {@link #changePassword} is allowed until it is.
     *
     * @return the flag
     */
    public boolean isPasswordChangeRequired() {
        return ops.auth().passwordChangeRequired();
    }

    /**
     * Changes the password of the authenticated user ({@code AdminService.ChangePassword}); the
     * client then logs in with the new password on its next call.
     *
     * @param currentPassword the current password (not retained)
     * @param newPassword the new password (copied for the next login)
     * @throws IllegalStateException if the client has no SCRAM credential
     * @throws RustegonException on failure (for example RGN-1001 when the new password is too
     *     weak)
     */
    public void changePassword(char[] currentPassword, char[] newPassword) {
        if (settings.credential().map(RustegonCredential::mechanism).orElse(null)
                != RustegonCredential.Mechanism.SCRAM_SHA_256) {
            throw new IllegalStateException("changePassword needs a SCRAM credential");
        }
        // protobuf strings are immutable: the request necessarily holds String copies.
        ChangePasswordRequest request = ChangePasswordRequest.newBuilder()
                .setCurrentPassword(CharBuffer.wrap(currentPassword).toString())
                .setNewPassword(CharBuffer.wrap(newPassword).toString())
                .build();
        ops.passwordChange(AdminServiceGrpc.getChangePasswordMethod(), request);
        ops.auth().passwordChanged(Arrays.copyOf(newPassword, newPassword.length));
    }

    /**
     * Ends the session (best-effort {@code Logout}) and closes the connections: in-flight calls
     * get up to 5 s before they are cancelled. Idempotent; later calls throw
     * {@link IllegalStateException} without I/O.
     */
    @Override
    public void close() {
        ops.close();
    }
}
