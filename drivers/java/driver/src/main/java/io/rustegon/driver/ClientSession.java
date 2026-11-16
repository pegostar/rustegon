// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A client session (java-driver.md §6; {@code Client.StartSession}). In R1 it is a pass-through
 * of the causality token (PD-069): with causal consistency, every call made through a handle
 * bound to the session ({@link RustegonDatabase#withSession}, {@link RustegonCollection#withSession})
 * sends the last {@code rgn-causality-token} the server returned and keeps the newer one. There
 * is no server-side session; {@link #close()} only ends the use of this object.
 *
 * <p>Thread-safe.
 */
public final class ClientSession implements AutoCloseable {
    private final boolean causalConsistency;
    private final AtomicReference<String> token = new AtomicReference<>();
    private volatile boolean closed;

    ClientSession(SessionOptions options) {
        this.causalConsistency = options.causalConsistency();
    }

    /**
     * Whether causality tokens are propagated.
     *
     * @return the flag
     */
    public boolean isCausallyConsistent() {
        return causalConsistency;
    }

    /**
     * The last causality token the server returned on a call of this session.
     *
     * @return the token, empty before the first call or without causal consistency
     */
    public Optional<String> causalityToken() {
        return Optional.ofNullable(token.get());
    }

    /** The token holder of the request interceptor, {@code null} without causal consistency. */
    AtomicReference<String> tokenRef() {
        return causalConsistency ? token : null;
    }

    void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("the session is closed");
        }
    }

    /** Ends the session; idempotent. Later calls through it fail with
     * {@link IllegalStateException}. */
    @Override
    public void close() {
        closed = true;
    }
}
