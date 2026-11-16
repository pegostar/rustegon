// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptors;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.rustegon.driver.RustegonClient;
import io.rustegon.driver.RustegonClientSettings;
import io.rustegon.driver.RustegonException;
import io.rustegon.driver.TlsSettings;
import io.rustegon.driver.UnavailableException;
import io.rustegon.driver.internal.proto.SessionServiceGrpc;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * TC-DRV-JAVA-010, client part (FR-DRV-002, protocol.md §2 and §5.3): the request metadata of
 * every call (UUIDv7 {@code rgn-request-id}, default deadline, explicit values win,
 * {@code authorization} only when given), an unreachable endpoint reported as a retryable
 * {@link UnavailableException}, and an interrupted caller getting a
 * {@link CancellationException} with its interrupt flag kept. The server part is
 * {@code TransportServerTest}.
 */
class TransportTest {
    /** A channel that records the options and headers of the calls made on it. */
    private static final class RecordingChannel extends Channel {
        CallOptions options;
        Metadata headers;

        @Override
        public <Q, R> ClientCall<Q, R> newCall(MethodDescriptor<Q, R> method,
                CallOptions callOptions) {
            options = callOptions;
            return new ClientCall<>() {
                @Override
                public void start(Listener<R> listener, Metadata h) {
                    headers = h;
                }

                @Override
                public void request(int n) {}

                @Override
                public void cancel(String message, Throwable cause) {}

                @Override
                public void halfClose() {}

                @Override
                public void sendMessage(Q message) {}
            };
        }

        @Override
        public String authority() {
            return "recording";
        }
    }

    private static RecordingChannel call(CallOptions options) {
        RecordingChannel recording = new RecordingChannel();
        Channel ch = ClientInterceptors.intercept(recording,
                new RequestInterceptor(Duration.ofSeconds(30)));
        ch.newCall(SessionServiceGrpc.getPingMethod(), options)
                .start(new ClientCall.Listener<>() {}, new Metadata());
        return recording;
    }

    @Test
    void tc_drv_java_010_request_metadata() {
        RecordingChannel plain = call(CallOptions.DEFAULT);
        long remaining = plain.options.getDeadline().timeRemaining(TimeUnit.MILLISECONDS);
        assertTrue(remaining > 29_000 && remaining <= 30_000, "default deadline: " + remaining);
        UUID id = UUID.fromString(plain.headers.get(RequestInterceptor.REQUEST_ID_HEADER));
        assertEquals(7, id.version(), "rgn-request-id is a UUIDv7");
        assertNull(plain.headers.get(RequestInterceptor.AUTHORIZATION_HEADER),
                "no authorization without a credential");
        // Every call gets its own id.
        assertFalse(id.toString().equals(call(CallOptions.DEFAULT).headers
                .get(RequestInterceptor.REQUEST_ID_HEADER)));

        // Explicit values win: deadline, request id (a retry reuses the first attempt's id).
        UUID retryId = UuidV7.next();
        RecordingChannel explicit = call(CallOptions.DEFAULT
                .withDeadlineAfter(5, TimeUnit.SECONDS)
                .withOption(RequestInterceptor.REQUEST_ID, retryId)
                .withOption(RequestInterceptor.AUTHORIZATION, "Bearer t0ken"));
        assertTrue(explicit.options.getDeadline().timeRemaining(TimeUnit.MILLISECONDS) <= 5_000);
        assertEquals(retryId.toString(),
                explicit.headers.get(RequestInterceptor.REQUEST_ID_HEADER));
        assertEquals("Bearer t0ken", explicit.headers.get(RequestInterceptor.AUTHORIZATION_HEADER));
    }

    private static int closedPort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        }
    }

    @Test
    @Timeout(30)
    void tc_drv_java_010_unreachable_endpoint_is_unavailable() throws IOException {
        RustegonClientSettings settings = RustegonClientSettings.builder()
                .endpoints("127.0.0.1:" + closedPort())
                .tls(TlsSettings.defaults())
                .build();
        try (RustegonClient client = RustegonClient.create(settings)) {
            RustegonException e = assertThrows(RustegonException.class, client::ping);
            assertInstanceOf(UnavailableException.class, e);
            assertEquals(3002, e.code());
            assertTrue(e.isRetryable());
        }
    }

    @Test
    @Timeout(30)
    void tc_drv_java_010_interrupted_call_is_cancelled() throws Exception {
        // A peer that accepts TCP connections and never answers: the call stays pending until
        // the caller's thread is interrupted.
        List<Socket> accepted = new CopyOnWriteArrayList<>();
        try (ServerSocket silent = new ServerSocket(0, 8, InetAddress.getLoopbackAddress())) {
            Thread acceptor = Thread.ofVirtual().start(() -> {
                try {
                    while (true) {
                        accepted.add(silent.accept());
                    }
                } catch (IOException closed) {
                    // The test is over.
                }
            });
            RustegonClientSettings settings = RustegonClientSettings.builder()
                    .endpoints("127.0.0.1:" + silent.getLocalPort())
                    .tls(TlsSettings.defaults())
                    .defaultOperationTimeout(Duration.ofSeconds(20))
                    .build();
            try (RustegonClient client = RustegonClient.create(settings)) {
                CompletableFuture<Throwable> outcome = new CompletableFuture<>();
                Thread caller = Thread.ofPlatform().start(() -> {
                    try {
                        client.ping();
                        outcome.complete(null);
                    } catch (Throwable t) {
                        // Record the interrupt flag together with the exception.
                        outcome.complete(Thread.currentThread().isInterrupted()
                                ? t : new AssertionError("interrupt flag cleared", t));
                    }
                });
                Thread.sleep(500);
                caller.interrupt();
                Throwable t = outcome.get(10, TimeUnit.SECONDS);
                assertInstanceOf(CancellationException.class, t);
                caller.join();
            }
            silent.close();
            acceptor.join();
        } finally {
            for (Socket s : accepted) {
                s.close();
            }
        }
    }
}
