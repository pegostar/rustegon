// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import com.google.protobuf.ByteString;
import io.grpc.Channel;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import io.rustegon.driver.internal.ErrorMapper;
import io.rustegon.driver.internal.ScramClient;
import io.rustegon.driver.internal.ScramException;
import io.rustegon.driver.internal.proto.AuthMechanism;
import io.rustegon.driver.internal.proto.AuthServiceGrpc;
import io.rustegon.driver.internal.proto.AuthSuccess;
import io.rustegon.driver.internal.proto.AuthenticateRequest;
import io.rustegon.driver.internal.proto.AuthenticateResponse;
import io.rustegon.driver.internal.proto.ClientInfo;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Obtains and caches the {@code authorization} value of the client's calls (protocol.md §8).
 *
 * <ul>
 *   <li>SCRAM-SHA-256: one bidirectional {@code Authenticate} stream (client-first → challenge →
 *       client-final → {@code AuthSuccess}); the server signature is verified before the session
 *       token is used ({@code authorization: Bearer <token>});
 *   <li>X.509: {@code Authenticate{X509}} with an empty payload on the mutual-TLS connection;
 *   <li>API key: {@code authorization: ApiKey <key>}, no handshake.
 * </ul>
 *
 * <p><b>Concurrency.</b> {@link #lock} (a {@link ReentrantLock}, not {@code synchronized}, so a
 * virtual thread blocked in the handshake does not pin its carrier) serializes handshakes and
 * guards {@link #credential}; {@link #authorization} is volatile so the fast path reads it
 * without the lock. {@link #invalidate} only clears the value it was given, so a thread holding
 * an expired token cannot discard a token another thread just obtained. The session token is a
 * secret: it is never logged.
 */
final class SessionAuth {
    private static final Logger LOG = LoggerFactory.getLogger(SessionAuth.class);
    private static final String DRIVER_NAME = "rustegon-java";

    private final ReentrantLock lock = new ReentrantLock();
    private final String applicationName;
    private final Duration timeout;
    private final boolean allowPasswordChangeOnly;
    /** Guarded by {@link #lock}. */
    private RustegonCredential credential;
    private volatile String authorization;
    private volatile boolean passwordChangeRequired;

    SessionAuth(RustegonCredential credential, String applicationName, Duration timeout,
            boolean allowPasswordChangeOnly) {
        this.credential = credential;
        this.applicationName = applicationName;
        this.timeout = timeout;
        this.allowPasswordChangeOnly = allowPasswordChangeOnly;
    }

    /** Whether the credential uses a session token (so {@code Logout} makes sense). */
    boolean usesSession() {
        lock.lock();
        try {
            return credential != null
                    && credential.mechanism() != RustegonCredential.Mechanism.API_KEY;
        } finally {
            lock.unlock();
        }
    }

    /** The current value without authenticating ({@code null} when none). */
    String current() {
        return authorization;
    }

    /**
     * The {@code authorization} value, authenticating first when there is none.
     *
     * @param channel channel for the handshake
     * @param passwordChangeCall whether the call is the password change itself (PD-076)
     * @return the value, {@code null} for an anonymous client
     */
    String authorization(Channel channel, boolean passwordChangeCall) {
        String value = authorization;
        if (value == null) {
            lock.lock();
            try {
                value = authorization;
                if (value == null && credential != null) {
                    value = authenticate(channel);
                    authorization = value;
                }
            } finally {
                lock.unlock();
            }
        }
        if (passwordChangeRequired && !passwordChangeCall && !allowPasswordChangeOnly) {
            throw new PasswordChangeRequiredException(
                    "the password must be changed before any other operation",
                    new RustegonError(4002, "PermissionDenied", false, null,
                            Map.of("reason", "must_change_password"), "", null), null);
        }
        return value;
    }

    /** Drops {@code failed} (expired session, RGN-4005) so that the next call re-authenticates. */
    void invalidate(String failed) {
        lock.lock();
        try {
            if (failed != null && failed.equals(authorization)) {
                authorization = null;
            }
        } finally {
            lock.unlock();
        }
    }

    /** After a successful password change: log in with the new password on the next call. */
    void passwordChanged(char[] newPassword) {
        lock.lock();
        try {
            credential = credential.withPassword(newPassword);
            authorization = null;
            passwordChangeRequired = false;
        } finally {
            lock.unlock();
        }
    }

    /** Whether the last login reported {@code must_change_password}. */
    boolean passwordChangeRequired() {
        return passwordChangeRequired;
    }

    /** Runs the handshake of the credential (lock held). */
    private String authenticate(Channel channel) {
        return switch (credential.mechanism()) {
            case API_KEY -> {
                char[] key = credential.secret();
                try {
                    yield "ApiKey " + new String(key);
                } finally {
                    Arrays.fill(key, '\0');
                }
            }
            case X509 -> success(handshake(channel, AuthMechanism.AUTH_MECHANISM_X509, null));
            case SCRAM_SHA_256 -> {
                char[] password = credential.secret();
                try {
                    ScramClient scram = new ScramClient(credential.user(), password);
                    yield success(handshake(channel, AuthMechanism.AUTH_MECHANISM_SCRAM_SHA_256,
                            scram));
                } finally {
                    Arrays.fill(password, '\0');
                }
            }
        };
    }

    private String success(AuthSuccess s) {
        passwordChangeRequired = s.getMustChangePassword();
        LOG.debug("authenticated as {} (password change required: {})", s.getUser(),
                s.getMustChangePassword());
        return "Bearer " + s.getSessionToken();
    }

    /**
     * One {@code Authenticate} stream. Responses are handed from the gRPC thread to the caller
     * through a queue, so the caller blocks (fine on a virtual thread) and the CPU-bound PBKDF2
     * runs on the caller's thread rather than on a transport thread.
     */
    private AuthSuccess handshake(Channel channel, AuthMechanism mechanism, ScramClient scram) {
        BlockingQueue<Object> inbox = new LinkedBlockingQueue<>();
        StreamObserver<AuthenticateRequest> requests = AuthServiceGrpc.newStub(channel)
                .withDeadlineAfter(timeout.toNanos(), TimeUnit.NANOSECONDS)
                .authenticate(new StreamObserver<>() {
                    @Override
                    public void onNext(AuthenticateResponse r) {
                        inbox.add(r);
                    }

                    @Override
                    public void onError(Throwable t) {
                        inbox.add(t);
                    }

                    @Override
                    public void onCompleted() {
                        inbox.add(Boolean.TRUE);
                    }
                });
        try {
            AuthenticateRequest.Builder first = AuthenticateRequest.newBuilder()
                    .setMechanism(mechanism)
                    .setClientInfo(ClientInfo.newBuilder()
                            .setDriverName(DRIVER_NAME)
                            .setDriverVersion(RustegonClient.DRIVER_VERSION)
                            .setApplication(applicationName == null ? "" : applicationName));
            if (scram != null) {
                first.setPayload(utf8(scram.clientFirst()));
            }
            requests.onNext(first.build());
            AuthenticateResponse r = take(inbox);
            if (scram == null) {
                return expectSuccess(r);
            }
            if (r.getStepCase() != AuthenticateResponse.StepCase.CHALLENGE) {
                throw failed("no SCRAM challenge", null);
            }
            String clientFinal = scram.clientFinal(r.getChallenge().toStringUtf8());
            requests.onNext(AuthenticateRequest.newBuilder().setPayload(utf8(clientFinal)).build());
            AuthSuccess s = expectSuccess(take(inbox));
            // Mutual authentication: the server proves it knows the stored key.
            scram.verifyServerFinal(s.getServerFinal().toStringUtf8());
            requests.onCompleted();
            return s;
        } catch (ScramException e) {
            requests.onError(io.grpc.Status.CANCELLED.withDescription("SCRAM failed")
                    .asRuntimeException());
            throw failed(e.getMessage(), e);
        } catch (RuntimeException e) {
            requests.onError(io.grpc.Status.CANCELLED.asRuntimeException());
            throw e;
        }
    }

    private static ByteString utf8(String s) {
        return ByteString.copyFrom(s, StandardCharsets.UTF_8);
    }

    private static AuthSuccess expectSuccess(AuthenticateResponse r) {
        if (r.getStepCase() != AuthenticateResponse.StepCase.SUCCESS) {
            throw failed("no authentication success", null);
        }
        return r.getSuccess();
    }

    private AuthenticateResponse take(BlockingQueue<Object> inbox) {
        Object o;
        try {
            o = inbox.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            throw ErrorMapper.cancelled("authentication", e);
        }
        if (o instanceof AuthenticateResponse r) {
            return r;
        }
        if (o instanceof StatusRuntimeException e) {
            if (ErrorMapper.isCallerCancellation(e)) {
                throw ErrorMapper.cancelled("authentication", e);
            }
            throw ErrorMapper.map(e);
        }
        if (o instanceof Throwable t) {
            throw ErrorMapper.local(3002, "authentication stream failed: " + t, t);
        }
        if (o == null) {
            throw ErrorMapper.local(5006, "authentication timed out", null);
        }
        throw failed("the server ended the authentication stream early", null);
    }

    private static AuthenticationException failed(String reason, Throwable cause) {
        return new AuthenticationException("authentication failed (" + reason + ")",
                new RustegonError(4001, "Unauthenticated", false, null, Map.of(), "", null),
                cause);
    }
}
