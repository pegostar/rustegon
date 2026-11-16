// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable settings of a {@link RustegonClient} (java-driver.md §2; defaults shared with the
 * .NET driver, {@code drivers/conformance/connstring.yaml}).
 *
 * <p>Defaults: plain text (ADR-034; an X.509 credential without TLS settings gets TLS with the
 * JDK trust store), 2 connections per endpoint, connect timeout
 * 10 s, operation timeout 30 s, retryable reads and writes retried, server-default read
 * consistency and write concern, no default database, no credential (anonymous: only
 * {@code SessionService} calls work).
 */
public final class RustegonClientSettings {
    /** Default connect timeout. */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    /** Default deadline of an operation. */
    public static final Duration DEFAULT_OPERATION_TIMEOUT = Duration.ofSeconds(30);
    /** Default number of HTTP/2 connections per endpoint. */
    public static final int DEFAULT_CONNECTIONS_PER_ENDPOINT = 2;
    /** Default number of automatic retries of a retryable operation. */
    public static final int DEFAULT_MAX_RETRIES = 1;

    private final List<String> endpoints;
    private final RustegonCredential credential;
    private final TlsSettings tls;
    private final String defaultDatabase;
    private final ReadConsistency readConsistency;
    private final Duration maxStaleness;
    private final WriteConcern writeConcern;
    private final int connectionsPerEndpoint;
    private final Duration connectTimeout;
    private final Duration defaultOperationTimeout;
    private final boolean retryReads;
    private final boolean retryWrites;
    private final int maxRetries;
    private final String applicationName;
    private final boolean allowPasswordChangeOnly;

    private RustegonClientSettings(Builder b) {
        this.endpoints = List.copyOf(b.endpoints);
        this.credential = b.credential;
        // ADR-034: plain text by default; X.509 needs TLS, so it turns TLS on.
        boolean x509 = b.credential != null
                && b.credential.mechanism() == RustegonCredential.Mechanism.X509;
        this.tls = b.tls != null ? b.tls : x509 ? TlsSettings.defaults() : TlsSettings.disabled();
        this.defaultDatabase = b.defaultDatabase;
        this.readConsistency = b.readConsistency;
        this.maxStaleness = b.maxStaleness;
        this.writeConcern = b.writeConcern;
        this.connectionsPerEndpoint = b.connectionsPerEndpoint;
        this.connectTimeout = b.connectTimeout;
        this.defaultOperationTimeout = b.defaultOperationTimeout;
        this.retryReads = b.retryReads;
        this.retryWrites = b.retryWrites;
        this.maxRetries = b.maxRetries;
        this.applicationName = b.applicationName;
        this.allowPasswordChangeOnly = b.allowPasswordChangeOnly;
    }

    /**
     * A builder with the defaults.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Settings from a {@code rustegon://} connection string ({@link ConnectionString}).
     *
     * @param connectionString the string
     * @return the settings
     * @throws IllegalArgumentException if the string is invalid
     */
    public static RustegonClientSettings fromConnectionString(String connectionString) {
        return ConnectionString.parse(connectionString).applyTo(builder()).build();
    }

    /**
     * Endpoints as {@code host:port}.
     *
     * @return the endpoints (at least one)
     */
    public List<String> endpoints() {
        return endpoints;
    }

    /**
     * The credential.
     *
     * @return the credential, empty for anonymous clients
     */
    public Optional<RustegonCredential> credential() {
        return Optional.ofNullable(credential);
    }

    /**
     * TLS settings.
     *
     * @return the settings
     */
    public TlsSettings tls() {
        return tls;
    }

    /**
     * Default database of {@code client.database()} calls.
     *
     * @return the database, empty when none
     */
    public Optional<String> defaultDatabase() {
        return Optional.ofNullable(defaultDatabase);
    }

    /**
     * Read consistency.
     *
     * @return the level, empty for the server default
     */
    public Optional<ReadConsistency> readConsistency() {
        return Optional.ofNullable(readConsistency);
    }

    /**
     * Maximum staleness of {@link ReadConsistency#BOUNDED_STALENESS} reads.
     *
     * @return the bound, empty when not set
     */
    public Optional<Duration> maxStaleness() {
        return Optional.ofNullable(maxStaleness);
    }

    /**
     * Write concern.
     *
     * @return the concern, empty for the server default
     */
    public Optional<WriteConcern> writeConcern() {
        return Optional.ofNullable(writeConcern);
    }

    /**
     * HTTP/2 connections per endpoint.
     *
     * @return the count (1–64)
     */
    public int connectionsPerEndpoint() {
        return connectionsPerEndpoint;
    }

    /**
     * Connect timeout: the longest a call waits for its channel to connect before it fails with
     * RGN-3002 (enforced per call by node selection, PD-081).
     *
     * @return the timeout
     */
    public Duration connectTimeout() {
        return connectTimeout;
    }

    /**
     * Deadline of an operation without an explicit one.
     *
     * @return the deadline
     */
    public Duration defaultOperationTimeout() {
        return defaultOperationTimeout;
    }

    /**
     * Whether retryable reads are retried.
     *
     * @return the flag
     */
    public boolean retryReads() {
        return retryReads;
    }

    /**
     * Whether retryable idempotent writes are retried.
     *
     * @return the flag
     */
    public boolean retryWrites() {
        return retryWrites;
    }

    /**
     * Automatic retries of a failed retryable operation (dotnet-driver.md §8,
     * {@code drivers/conformance/retry.yaml}).
     *
     * @return the count (0-10, default {@value #DEFAULT_MAX_RETRIES})
     */
    public int maxRetries() {
        return maxRetries;
    }

    /**
     * Application name reported to the server ({@code client_info}).
     *
     * @return the name, empty when not set
     */
    public Optional<String> applicationName() {
        return Optional.ofNullable(applicationName);
    }

    /**
     * Whether a login whose password must be changed is accepted (PD-076).
     *
     * @return the flag
     */
    public boolean allowPasswordChangeOnly() {
        return allowPasswordChangeOnly;
    }

    @Override
    public String toString() {
        return "RustegonClientSettings[endpoints=" + endpoints + ", credential=" + credential
                + ", tls=" + tls + ", defaultDatabase=" + defaultDatabase
                + ", connectionsPerEndpoint=" + connectionsPerEndpoint + ", connectTimeout="
                + connectTimeout + ", defaultOperationTimeout=" + defaultOperationTimeout
                + ", retryReads=" + retryReads + ", retryWrites=" + retryWrites + ", maxRetries="
                + maxRetries + "]";
    }

    /** Builder of {@link RustegonClientSettings}. Not thread-safe. */
    public static final class Builder {
        private static final int MAX_CONNECTIONS_PER_ENDPOINT = 64;
        private static final int MAX_RETRIES = 10;
        private final List<String> endpoints = new ArrayList<>();
        private RustegonCredential credential;
        private TlsSettings tls;
        private String defaultDatabase;
        private ReadConsistency readConsistency;
        private Duration maxStaleness;
        private WriteConcern writeConcern;
        private int connectionsPerEndpoint = DEFAULT_CONNECTIONS_PER_ENDPOINT;
        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration defaultOperationTimeout = DEFAULT_OPERATION_TIMEOUT;
        private boolean retryReads = true;
        private boolean retryWrites = true;
        private int maxRetries = DEFAULT_MAX_RETRIES;
        private String applicationName;
        private boolean allowPasswordChangeOnly;

        private Builder() {}

        /**
         * Replaces the endpoints.
         *
         * @param endpoints {@code host[:port]} entries (port 7700 by default)
         * @return this builder
         */
        public Builder endpoints(String... endpoints) {
            return endpoints(List.of(endpoints));
        }

        /**
         * Replaces the endpoints.
         *
         * @param endpoints {@code host[:port]} entries
         * @return this builder
         */
        public Builder endpoints(List<String> endpoints) {
            this.endpoints.clear();
            for (String e : endpoints) {
                this.endpoints.add(ConnectionString.endpoint(e));
            }
            return this;
        }

        /**
         * Sets the credential.
         *
         * @param credential the credential
         * @return this builder
         */
        public Builder credential(RustegonCredential credential) {
            this.credential = Objects.requireNonNull(credential, "credential");
            return this;
        }

        /**
         * Sets the TLS settings.
         *
         * @param tls the settings
         * @return this builder
         */
        public Builder tls(TlsSettings tls) {
            this.tls = Objects.requireNonNull(tls, "tls");
            return this;
        }

        /**
         * Sets the default database.
         *
         * @param database the database name
         * @return this builder
         */
        public Builder defaultDatabase(String database) {
            this.defaultDatabase = Objects.requireNonNull(database, "database");
            return this;
        }

        /**
         * Sets the read consistency.
         *
         * @param level the level
         * @return this builder
         */
        public Builder readConsistency(ReadConsistency level) {
            this.readConsistency = Objects.requireNonNull(level, "level");
            return this;
        }

        /**
         * Sets the bound of bounded-staleness reads.
         *
         * @param staleness a positive duration
         * @return this builder
         */
        public Builder maxStaleness(Duration staleness) {
            this.maxStaleness = positive(staleness, "maxStaleness");
            return this;
        }

        /**
         * Sets the write concern.
         *
         * @param concern the concern
         * @return this builder
         */
        public Builder writeConcern(WriteConcern concern) {
            this.writeConcern = Objects.requireNonNull(concern, "concern");
            return this;
        }

        /**
         * Sets the HTTP/2 connections per endpoint.
         *
         * @param count 1–64
         * @return this builder
         */
        public Builder connectionsPerEndpoint(int count) {
            if (count < 1 || count > MAX_CONNECTIONS_PER_ENDPOINT) {
                throw new IllegalArgumentException("connectionsPerEndpoint must be 1–64");
            }
            this.connectionsPerEndpoint = count;
            return this;
        }

        /**
         * Sets the connect timeout.
         *
         * @param timeout a positive duration
         * @return this builder
         */
        public Builder connectTimeout(Duration timeout) {
            this.connectTimeout = positive(timeout, "connectTimeout");
            return this;
        }

        /**
         * Sets the default operation deadline.
         *
         * @param timeout a positive duration
         * @return this builder
         */
        public Builder defaultOperationTimeout(Duration timeout) {
            this.defaultOperationTimeout = positive(timeout, "defaultOperationTimeout");
            return this;
        }

        /**
         * Whether retryable reads are retried.
         *
         * @param retry the flag
         * @return this builder
         */
        public Builder retryReads(boolean retry) {
            this.retryReads = retry;
            return this;
        }

        /**
         * Whether retryable idempotent writes are retried.
         *
         * @param retry the flag
         * @return this builder
         */
        public Builder retryWrites(boolean retry) {
            this.retryWrites = retry;
            return this;
        }

        /**
         * Sets the number of automatic retries of a retryable operation.
         *
         * @param retries 0-10 (0 disables automatic retries)
         * @return this builder
         */
        public Builder maxRetries(int retries) {
            if (retries < 0 || retries > MAX_RETRIES) {
                throw new IllegalArgumentException("maxRetries must be 0-10");
            }
            this.maxRetries = retries;
            return this;
        }

        /**
         * Sets the application name reported to the server.
         *
         * @param name the name
         * @return this builder
         */
        public Builder applicationName(String name) {
            this.applicationName = Objects.requireNonNull(name, "name");
            return this;
        }

        /**
         * Accepts a login whose password must be changed (PD-076): the client then only serves
         * {@link RustegonClient#changePassword}; without it such a login raises
         * {@link PasswordChangeRequiredException}.
         *
         * @param allow the flag
         * @return this builder
         */
        public Builder allowPasswordChangeOnly(boolean allow) {
            this.allowPasswordChangeOnly = allow;
            return this;
        }

        /**
         * Applies a connection string on top of the current values.
         *
         * @param connectionString the string
         * @return this builder
         */
        public Builder connectionString(String connectionString) {
            return ConnectionString.parse(connectionString).applyTo(this);
        }

        private static Duration positive(Duration d, String name) {
            Objects.requireNonNull(d, name);
            if (d.isNegative() || d.isZero()) {
                throw new IllegalArgumentException(name + " must be positive");
            }
            return d;
        }

        /**
         * Builds the settings.
         *
         * @return the settings
         * @throws IllegalStateException without endpoints, or with bounded-staleness reads but
         *     no bound
         */
        public RustegonClientSettings build() {
            if (endpoints.isEmpty()) {
                throw new IllegalStateException("at least one endpoint is required");
            }
            // An X.509 credential without a client certificate is representable here (a
            // connection string names the mechanism, the certificate may come from a key
            // manager set later); RustegonClient.create rejects it.
            if (readConsistency == ReadConsistency.BOUNDED_STALENESS && maxStaleness == null) {
                throw new IllegalStateException("BOUNDED_STALENESS needs maxStaleness");
            }
            return new RustegonClientSettings(this);
        }
    }
}
