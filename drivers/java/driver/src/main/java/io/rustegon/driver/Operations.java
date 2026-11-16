// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.Deadline;
import io.grpc.MethodDescriptor;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.ClientCalls;
import io.rustegon.driver.internal.ChannelPool;
import io.rustegon.driver.internal.ErrorMapper;
import io.rustegon.driver.internal.RequestInterceptor;
import io.rustegon.driver.internal.UuidV7;
import io.rustegon.driver.internal.proto.AuthServiceGrpc;
import io.rustegon.driver.internal.proto.ExecuteRequest;
import io.rustegon.driver.internal.proto.ExecuteResponse;
import io.rustegon.driver.internal.proto.LogoutRequest;
import io.rustegon.driver.internal.proto.QueryServiceGrpc;
import io.rustegon.driver.internal.proto.ReadConsistencyLevel;
import io.rustegon.driver.internal.proto.ResultBatch;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Runs the client's calls: channel selection (with the connect timeout, PD-081), the session's
 * authorization, request metadata, error mapping and the retry policy of
 * {@code drivers/conformance/retry.yaml} (dotnet-driver.md §8, java-driver.md §6):
 *
 * <ul>
 *   <li>R1: a failure is retried only when its {@code ErrorDetail.retryable} (or the transport
 *       fallback) says so, at most {@code maxRetries} times, after a full-jitter backoff
 *       (base {@value #BACKOFF_BASE_MS} ms, ×2, cap {@value #BACKOFF_CAP_MS} ms) that is at least
 *       the server's {@code retry_after_ms};
 *   <li>R2: reads when {@code retryReads}, writes when {@code retryWrites} — every attempt reuses
 *       the first attempt's {@code rgn-request-id}, so the server deduplicates them — and nothing
 *       inside a transaction (the transaction is the unit of retry, {@code withTransaction});
 *   <li>R3: a stream that already delivered a batch, and {@code NONE} calls (GetMore, cursor and
 *       transaction control, DDL), are never retried;
 *   <li>R4: the caller's own deadline maps to RGN-5006 with {@code retryable = false};
 *   <li>R8: the timeout is one deadline for the whole operation, every attempt and backoff
 *       included; no retry once the backoff would pass it (PD-097, PD-101);
 *   <li>R5: RGN-4005 on a session token re-authenticates and resends once, outside the budget.
 * </ul>
 *
 * <p>Blocking and virtual-thread friendly: no monitor is held across a call or a backoff sleep.
 * The heartbeat scheduler of transactions is created on first use and guarded by a
 * {@link ReentrantLock}.
 */
final class Operations {
    /** Full-jitter backoff base (retry.yaml {@code defaults.backoff}). */
    static final long BACKOFF_BASE_MS = 10;
    /** Backoff cap. */
    static final long BACKOFF_CAP_MS = 1000;
    private static final Logger LOG = LoggerFactory.getLogger(Operations.class);
    /** Deadline of the best-effort {@code Logout} at close. */
    private static final long LOGOUT_TIMEOUT_SECONDS = 2;

    /** How an operation may be retried (rule R2/R3). */
    enum Kind {
        /** Retried when {@code retryReads}. */
        READ,
        /** Retried when {@code retryWrites} (same request id on every attempt). */
        WRITE,
        /** Never retried. */
        NONE
    }

    /** One attempt of a call on a chosen channel. */
    @FunctionalInterface
    interface Attempt<T> {
        T run(Channel channel, CallOptions options, AtomicBoolean delivered);
    }

    private final RustegonClientSettings settings;
    private final ChannelPool pool;
    private final SessionAuth auth;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final ReentrantLock schedulerLock = new ReentrantLock();
    /** Guarded by {@link #schedulerLock}. */
    private ScheduledExecutorService scheduler;

    Operations(RustegonClientSettings settings, ChannelPool pool, SessionAuth auth) {
        this.settings = settings;
        this.pool = pool;
        this.auth = auth;
    }

    RustegonClientSettings settings() {
        return settings;
    }

    SessionAuth auth() {
        return auth;
    }

    /** A unary call. */
    <Q, R> R unary(MethodDescriptor<Q, R> method, Q request, Kind kind, OpContext ctx) {
        return run(kind, ctx, false,
                (ch, opts, delivered) -> ClientCalls.blockingUnaryCall(ch, method, opts, request));
    }

    /**
     * {@code TransactionService.Commit} (never retried). A failure without {@code ErrorDetail}
     * after the request was handed to the transport (connection reset, node killed, deadline)
     * may hide a commit that took effect, exactly like a coordinator dying before its ack
     * (transaction-management.md §7: RGN-2006), so it is reported as RGN-2006 and
     * resolved through {@code Status}, never by re-running (PD-122). Failures before the call
     * (connect timeout, login) and server errors keep their own codes.
     */
    <Q, R> R commit(MethodDescriptor<Q, R> method, Q request, OpContext ctx) {
        return run(Kind.NONE, ctx, false, (ch, opts, delivered) -> {
            try {
                return ClientCalls.blockingUnaryCall(ch, method, opts, request);
            } catch (StatusRuntimeException e) {
                if (ErrorMapper.isCallerCancellation(e)
                        || ErrorMapper.errorDetail(e.getTrailers()).isPresent()) {
                    throw e;
                }
                throw ErrorMapper.local(2006, "commit failed in transport ("
                        + e.getStatus().getCode() + "); its outcome is unknown", e);
            }
        });
    }

    /** {@code AdminService.ChangePassword}: allowed while a password change is pending. */
    <Q, R> R passwordChange(MethodDescriptor<Q, R> method, Q request) {
        return run(Kind.NONE, OpContext.NONE, true,
                (ch, opts, delivered) -> ClientCalls.blockingUnaryCall(ch, method, opts, request));
    }

    /**
     * {@code QueryService.Execute}, read to the end of the stream (the driver asks for one batch
     * with {@code max_batches}, the rest comes through GetMore).
     */
    List<ResultBatch> execute(ExecuteRequest request, Kind kind, OpContext ctx) {
        return run(kind, ctx, false, (ch, opts, delivered) -> {
            List<ResultBatch> batches = new ArrayList<>();
            Iterator<ExecuteResponse> it = ClientCalls.blockingServerStreamingCall(ch,
                    QueryServiceGrpc.getExecuteMethod(), opts, request);
            while (it.hasNext()) {
                batches.add(it.next().getBatch());
                delivered.set(true);
            }
            return batches;
        });
    }

    private <T> T run(Kind kind, OpContext ctx, boolean passwordChangeCall, Attempt<T> attempt) {
        ensureOpen();
        if (ctx.session() != null) {
            ctx.session().ensureOpen();
        }
        UUID requestId = UuidV7.next();
        Duration timeout = ctx.timeout() != null ? ctx.timeout()
                : settings.defaultOperationTimeout();
        // R8: one deadline for every attempt and backoff of the operation.
        Deadline deadline = Deadline.after(timeout.toNanos(), TimeUnit.NANOSECONDS);
        boolean reauthenticated = false;
        int retries = 0;
        while (true) {
            AtomicBoolean delivered = new AtomicBoolean();
            String authorization = null;
            RustegonException failure;
            try {
                Channel ch = pool.next(settings.connectTimeout());
                authorization = auth.authorization(ch, passwordChangeCall);
                CallOptions opts = CallOptions.DEFAULT
                        .withOption(RequestInterceptor.REQUEST_ID, requestId)
                        .withDeadline(deadline);
                if (authorization != null) {
                    opts = opts.withOption(RequestInterceptor.AUTHORIZATION, authorization);
                }
                if (ctx.session() != null && ctx.session().tokenRef() != null) {
                    opts = opts.withOption(RequestInterceptor.CAUSALITY_TOKEN,
                            ctx.session().tokenRef());
                }
                return attempt.run(ch, opts, delivered);
            } catch (StatusRuntimeException e) {
                if (ErrorMapper.isCallerCancellation(e)) {
                    throw ErrorMapper.cancelled("the call", e);
                }
                failure = ErrorMapper.map(e);
            } catch (RustegonException e) {
                // Connect timeout or a failed handshake: classified like any other failure.
                failure = e;
            }
            if (failure.code() == 4005 && !reauthenticated && authorization != null
                    && auth.usesSession()) {
                // R5: the session token expired; one fresh login, not counted as a retry.
                LOG.debug("session expired; re-authenticating");
                reauthenticated = true;
                auth.invalidate(authorization);
                continue;
            }
            if (!failure.isRetryable() || delivered.get() || retries >= settings.maxRetries()
                    || !retryAllowed(kind, ctx)) {
                throw failure;
            }
            retries++;
            long backoff = backoffMillis(retries, failure.retryAfter().orElse(null));
            if (deadline.timeRemaining(TimeUnit.MILLISECONDS) <= backoff) {
                throw failure;
            }
            sleep(backoff);
        }
    }

    private boolean retryAllowed(Kind kind, OpContext ctx) {
        if (ctx.txnId() != null) {
            return false;
        }
        return switch (kind) {
            case READ -> settings.retryReads();
            case WRITE -> settings.retryWrites();
            case NONE -> false;
        };
    }

    /**
     * Full-jitter backoff of the {@code n}-th retry (1-based): uniform in
     * [0, min(cap, base·2^(n−1))], and at least {@code retryAfter} when the server asked for it.
     */
    static long backoffMillis(int n, Duration retryAfter) {
        long ceiling = n > 8 ? BACKOFF_CAP_MS
                : Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS << (n - 1));
        long wait = ThreadLocalRandom.current().nextLong(ceiling + 1);
        return retryAfter == null ? wait : Math.max(wait, retryAfter.toMillis());
    }

    /** Sleeps; an interrupt becomes the caller's cancellation (errors-map.yaml). */
    static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw ErrorMapper.cancelled("the retry backoff", e);
        }
    }

    void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("the client is closed");
        }
    }

    /** Proto read consistency of a call outside a transaction, {@code null} for the default. */
    io.rustegon.driver.internal.proto.ReadConsistency readConsistency(OpContext ctx) {
        ReadConsistency level = ctx.readConsistency() != null ? ctx.readConsistency()
                : settings.readConsistency().orElse(null);
        if (level == null || ctx.txnId() != null) {
            return null;
        }
        Duration staleness = ctx.readConsistency() != null ? ctx.maxStaleness()
                : settings.maxStaleness().orElse(null);
        var b = io.rustegon.driver.internal.proto.ReadConsistency.newBuilder()
                .setLevel(ReadConsistencyLevel.valueOf("READ_CONSISTENCY_LEVEL_" + level.name()));
        if (staleness != null) {
            b.setMaxStalenessMs((int) Math.min(Integer.MAX_VALUE, staleness.toMillis()));
        }
        return b.build();
    }

    /** Proto write concern of a write outside a transaction ({@code UNSPECIFIED} = default). */
    io.rustegon.driver.internal.proto.WriteConcern writeConcern(OpContext ctx) {
        WriteConcern wc = ctx.writeConcern() != null ? ctx.writeConcern()
                : settings.writeConcern().orElse(null);
        return wc == null || ctx.txnId() != null
                ? io.rustegon.driver.internal.proto.WriteConcern.WRITE_CONCERN_UNSPECIFIED
                : io.rustegon.driver.internal.proto.WriteConcern.valueOf(
                        "WRITE_CONCERN_" + wc.name());
    }

    /** Schedules {@code task} every {@code periodMillis} on the client's heartbeat thread. */
    ScheduledFuture<?> every(long periodMillis, Runnable task) {
        schedulerLock.lock();
        try {
            ensureOpen();
            if (scheduler == null) {
                scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "rustegon-txn-heartbeat");
                    t.setDaemon(true);
                    return t;
                });
            }
            return scheduler.scheduleAtFixedRate(task, periodMillis, periodMillis,
                    TimeUnit.MILLISECONDS);
        } finally {
            schedulerLock.unlock();
        }
    }

    /**
     * Ends the session (best-effort {@code Logout}) and closes the connections; idempotent.
     */
    void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        schedulerLock.lock();
        try {
            if (scheduler != null) {
                scheduler.shutdownNow();
            }
        } finally {
            schedulerLock.unlock();
        }
        String authorization = auth.current();
        if (authorization != null && auth.usesSession()) {
            try {
                AuthServiceGrpc.newBlockingStub(pool.next())
                        .withOption(RequestInterceptor.AUTHORIZATION, authorization)
                        .withDeadlineAfter(LOGOUT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        .logout(LogoutRequest.getDefaultInstance());
            } catch (StatusRuntimeException e) {
                // The session expires on its own; a failed logout must not fail the shutdown.
                LOG.debug("logout at close failed: {}", e.getStatus().getCode());
            }
        }
        pool.close();
    }
}
