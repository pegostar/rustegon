// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.ForwardingClientCallListener;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Adds the common request metadata of protocol.md §2 to every call: {@code rgn-request-id}
 * (UUIDv7, or the caller's id so that a retry reuses it), {@code authorization} when the caller
 * supplied one, the default deadline ({@code grpc-timeout}) when the call has none, and the
 * session's {@code rgn-causality-token}, which is updated from the response headers and trailers
 * (PD-069: sessions are a pass-through of the token).
 *
 * <p>The authorization value is computed by the caller before the call and passed in the call
 * options, so this interceptor never blocks (authentication itself is a gRPC call).
 */
public final class RequestInterceptor implements ClientInterceptor {
    /** The {@code authorization} value of a call ({@code Bearer …} / {@code ApiKey …}). */
    public static final CallOptions.Key<String> AUTHORIZATION =
            CallOptions.Key.create("rustegon-authorization");
    /** An explicit request id (retries reuse the id of the first attempt). */
    public static final CallOptions.Key<UUID> REQUEST_ID =
            CallOptions.Key.create("rustegon-request-id");
    /** The causality token of a session: sent when set, replaced by the server's token. */
    public static final CallOptions.Key<AtomicReference<String>> CAUSALITY_TOKEN =
            CallOptions.Key.create("rustegon-causality-token");
    static final Metadata.Key<String> CAUSALITY_HEADER =
            Metadata.Key.of("rgn-causality-token", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> AUTHORIZATION_HEADER =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> REQUEST_ID_HEADER =
            Metadata.Key.of("rgn-request-id", Metadata.ASCII_STRING_MARSHALLER);

    private final long defaultTimeoutNanos;

    /**
     * Creates the interceptor.
     *
     * @param defaultTimeout deadline of calls without one
     */
    public RequestInterceptor(Duration defaultTimeout) {
        this.defaultTimeoutNanos = defaultTimeout.toNanos();
    }

    @Override
    public <Q, R> ClientCall<Q, R> interceptCall(MethodDescriptor<Q, R> method,
            CallOptions options, Channel next) {
        CallOptions effective = options.getDeadline() == null
                ? options.withDeadlineAfter(defaultTimeoutNanos, TimeUnit.NANOSECONDS)
                : options;
        String authorization = options.getOption(AUTHORIZATION);
        UUID explicitId = options.getOption(REQUEST_ID);
        UUID requestId = explicitId != null ? explicitId : UuidV7.next();
        AtomicReference<String> causality = options.getOption(CAUSALITY_TOKEN);
        return new ForwardingClientCall.SimpleForwardingClientCall<>(
                next.newCall(method, effective)) {
            @Override
            public void start(Listener<R> listener, Metadata headers) {
                headers.put(REQUEST_ID_HEADER, requestId.toString());
                if (authorization != null) {
                    headers.put(AUTHORIZATION_HEADER, authorization);
                }
                if (causality == null) {
                    super.start(listener, headers);
                    return;
                }
                String token = causality.get();
                if (token != null) {
                    headers.put(CAUSALITY_HEADER, token);
                }
                super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<>(
                        listener) {
                    @Override
                    public void onHeaders(Metadata h) {
                        observe(h);
                        super.onHeaders(h);
                    }

                    @Override
                    public void onClose(Status status, Metadata trailers) {
                        observe(trailers);
                        super.onClose(status, trailers);
                    }

                    private void observe(Metadata m) {
                        String t = m == null ? null : m.get(CAUSALITY_HEADER);
                        if (t != null) {
                            causality.set(t);
                        }
                    }
                }, headers);
            }
        };
    }
}
