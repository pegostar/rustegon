// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import io.grpc.Channel;
import io.grpc.ChannelCredentials;
import io.grpc.ClientInterceptors;
import io.grpc.ConnectivityState;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.TlsChannelCredentials;
import io.rustegon.driver.TlsSettings;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManager;

/**
 * The client's gRPC channels: {@code connectionsPerEndpoint} channels per endpoint, each one
 * HTTP/2 connection (java-driver.md §2 refers to dotnet-driver.md §3; protocol.md §5.3).
 *
 * <p>Transport: the channel is built through the transport-neutral
 * {@link Grpc#newChannelBuilderForAddress} with {@link TlsChannelCredentials}, which selects
 * grpc-netty-shaded (a runtime dependency) without the driver compiling against its shaded
 * classes: the shaded jar carries the module descriptor of its embedded tcnative library, so its
 * packages cannot be required from a named module. TLS: the JDK provider with its default
 * protocols, TLS 1.3 preferred (the node offers only 1.3 by default, FR-TLS-001); trust is the
 * configured CA, a trust manager, or the JDK trust store, and the server name is verified. HTTP/2
 * keepalive ping every {@value #KEEPALIVE_SECONDS} s with a {@value #KEEPALIVE_TIMEOUT_SECONDS}
 * s timeout; gRPC reconnects automatically. Calls are spread round-robin (R1 servers are single
 * nodes; selection by in-flight load and ejection arrive with multi-node clusters, M5).
 *
 * <p><b>Connect timeout (PD-081 option (a)).</b> The transport-neutral builder cannot set the TCP
 * connect timeout without the shaded Netty API, so {@link #next(Duration)} enforces it per call:
 * a channel that is not yet connected is asked to connect and waited for at most the connect
 * timeout; a channel still connecting then fails the call with RGN-3002 (retryable), while a
 * channel in transient failure is handed out at once so that the call fails fast as before.
 * Thread-safe.
 */
public final class ChannelPool implements AutoCloseable {
    /** protocol.md §5.3: keepalive ping interval. */
    static final long KEEPALIVE_SECONDS = 30;
    /** protocol.md §5.3: keepalive ping timeout. */
    static final long KEEPALIVE_TIMEOUT_SECONDS = 10;
    /** Inbound limit: 16 MiB documents plus batch framing; bulk payloads are ≤ 48 MiB. */
    static final int MAX_INBOUND_MESSAGE_BYTES = 64 * 1024 * 1024;
    /** Grace period of a graceful shutdown before in-flight calls are cancelled. */
    private static final long SHUTDOWN_GRACE_SECONDS = 5;

    private final List<ManagedChannel> managed;
    private final List<Channel> channels;
    // Only needs a distinct, roughly even sequence per call; no memory is published with it.
    private final AtomicInteger next = new AtomicInteger();

    private ChannelPool(List<ManagedChannel> managed, List<Channel> channels) {
        this.managed = managed;
        this.channels = channels;
    }

    /**
     * Opens the channels (connections are established lazily by gRPC on first use).
     *
     * @param endpoints {@code host:port} entries ({@code [v6]:port} for IPv6)
     * @param tls TLS settings
     * @param perEndpoint channels per endpoint
     * @param interceptor request metadata interceptor
     * @param userAgent value of the HTTP/2 user agent
     * @param clientKeyManager key manager of an X.509 credential, or {@code null}
     * @return the pool
     * @throws IllegalArgumentException if a TLS file cannot be read
     */
    public static ChannelPool open(List<String> endpoints, TlsSettings tls, int perEndpoint,
            RequestInterceptor interceptor, String userAgent, KeyManager clientKeyManager) {
        ChannelCredentials credentials = tls.enabled() ? credentials(tls, clientKeyManager)
                : InsecureChannelCredentials.create();
        List<ManagedChannel> managed = new ArrayList<>();
        List<Channel> channels = new ArrayList<>();
        for (String endpoint : endpoints) {
            int colon = endpoint.lastIndexOf(':');
            String host = endpoint.substring(0, colon);
            if (host.startsWith("[")) {
                host = host.substring(1, host.length() - 1);
            }
            int port = Integer.parseInt(endpoint.substring(colon + 1));
            for (int i = 0; i < perEndpoint; i++) {
                ManagedChannelBuilder<?> b = Grpc.newChannelBuilderForAddress(host, port,
                                credentials)
                        .keepAliveTime(KEEPALIVE_SECONDS, TimeUnit.SECONDS)
                        .keepAliveTimeout(KEEPALIVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        .maxInboundMessageSize(MAX_INBOUND_MESSAGE_BYTES)
                        .userAgent(userAgent);
                if (tls.enabled()) {
                    tls.serverNameOverride().ifPresent(b::overrideAuthority);
                }
                ManagedChannel ch = b.build();
                managed.add(ch);
                channels.add(ClientInterceptors.intercept(ch, interceptor));
            }
        }
        return new ChannelPool(List.copyOf(managed), List.copyOf(channels));
    }

    private static ChannelCredentials credentials(TlsSettings tls, KeyManager clientKeyManager) {
        try {
            TlsChannelCredentials.Builder b = TlsChannelCredentials.newBuilder();
            if (tls.caCertificate().isPresent()) {
                b.trustManager(tls.caCertificate().get().toFile());
            } else if (tls.trustManagerFactory().isPresent()) {
                b.trustManager(tls.trustManagerFactory().get().getTrustManagers());
            }
            if (clientKeyManager != null) {
                b.keyManager(clientKeyManager);
            } else if (tls.clientCertificate().isPresent()) {
                b.keyManager(tls.clientCertificate().get().toFile(),
                        tls.clientKey().orElseThrow().toFile());
            } else if (tls.keyManagerFactory().isPresent()) {
                b.keyManager(tls.keyManagerFactory().get().getKeyManagers());
            }
            return b.build();
        } catch (IOException | IllegalArgumentException e) {
            throw new IllegalArgumentException("cannot load the TLS configuration (" + tls + "): "
                    + e.getMessage(), e);
        }
    }

    /**
     * The channel of the next call (round robin), without waiting for a connection.
     *
     * @return a channel with the request interceptor applied
     */
    public Channel next() {
        return channels.get(Math.floorMod(next.getAndIncrement(), channels.size()));
    }

    /**
     * The channel of the next call (round robin), connected within {@code connectTimeout}
     * (PD-081, class comment).
     *
     * @param connectTimeout the longest wait for a connection
     * @return a channel with the request interceptor applied
     * @throws io.rustegon.driver.UnavailableException (RGN-3002) if the channel is still
     *     connecting after the timeout
     * @throws java.util.concurrent.CancellationException if the thread is interrupted
     */
    public Channel next(Duration connectTimeout) {
        int i = Math.floorMod(next.getAndIncrement(), channels.size());
        awaitConnection(managed.get(i), connectTimeout);
        return channels.get(i);
    }

    private static void awaitConnection(ManagedChannel ch, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        ConnectivityState state = ch.getState(true);
        while (state == ConnectivityState.IDLE || state == ConnectivityState.CONNECTING) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                throw ErrorMapper.local(3002, "no connection within the connect timeout ("
                        + timeout.toMillis() + " ms)", null);
            }
            CountDownLatch changed = new CountDownLatch(1);
            ch.notifyWhenStateChanged(state, changed::countDown);
            try {
                changed.await(left, TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                throw ErrorMapper.cancelled("connecting", e);
            }
            state = ch.getState(true);
        }
    }

    /**
     * Shuts every channel down: graceful for up to 5 s, then in-flight calls are cancelled.
     */
    @Override
    public void close() {
        for (ManagedChannel ch : managed) {
            ch.shutdown();
        }
        boolean interrupted = false;
        for (ManagedChannel ch : managed) {
            try {
                if (!ch.awaitTermination(SHUTDOWN_GRACE_SECONDS, TimeUnit.SECONDS)) {
                    ch.shutdownNow();
                }
            } catch (InterruptedException e) {
                ch.shutdownNow();
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
