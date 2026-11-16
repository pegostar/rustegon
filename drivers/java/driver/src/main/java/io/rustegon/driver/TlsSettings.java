// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * TLS of the client connections (java-driver.md §2). Plain text by default, like a single node
 * started with its defaults (ADR-034); a node with {@code security.tls = true}, and every cluster
 * node, needs TLS. Unless {@link Builder#enabled} is called, setting any TLS option (trust, client
 * certificate, server name) turns TLS on; {@code enabled(false)} with such an option is an error.
 *
 * <p>Trust: a PEM CA file ({@link Builder#caCertificate}, e.g. the {@code ca.crt} written by
 * {@code rustegon init}), or a {@link TrustManagerFactory}, else the JDK's default trust store.
 * Client certificate (mutual TLS, X.509 login): PEM certificate chain + PKCS#8 key files, or a
 * {@link KeyManagerFactory}. {@link #disabled()} is plain text (credentials travel in clear text).
 */
public final class TlsSettings {
    private static final TlsSettings DISABLED = new Builder().enabled(false).build();

    private final boolean enabled;
    private final Path caCertificate;
    private final TrustManagerFactory trustManagerFactory;
    private final Path clientCertificate;
    private final Path clientKey;
    private final KeyManagerFactory keyManagerFactory;
    private final String serverNameOverride;

    private TlsSettings(Builder b, boolean enabled) {
        this.enabled = enabled;
        this.caCertificate = b.caCertificate;
        this.trustManagerFactory = b.trustManagerFactory;
        this.clientCertificate = b.clientCertificate;
        this.clientKey = b.clientKey;
        this.keyManagerFactory = b.keyManagerFactory;
        this.serverNameOverride = b.serverNameOverride;
    }

    /**
     * A builder (TLS off until enabled or a TLS option is set; default trust store).
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * TLS on with the JDK's default trust store.
     *
     * @return the settings
     */
    public static TlsSettings defaults() {
        return builder().enabled(true).build();
    }

    /**
     * Plain-text connections (the default; single nodes without {@code security.tls = true}).
     *
     * @return the settings
     */
    public static TlsSettings disabled() {
        return DISABLED;
    }

    /**
     * Whether TLS is used.
     *
     * @return {@code true} unless {@link #disabled()}
     */
    public boolean enabled() {
        return enabled;
    }

    /**
     * The PEM CA file.
     *
     * @return the path, empty when not set
     */
    public Optional<Path> caCertificate() {
        return Optional.ofNullable(caCertificate);
    }

    /**
     * The trust manager factory.
     *
     * @return the factory, empty when not set
     */
    public Optional<TrustManagerFactory> trustManagerFactory() {
        return Optional.ofNullable(trustManagerFactory);
    }

    /**
     * The PEM client certificate chain.
     *
     * @return the path, empty when not set
     */
    public Optional<Path> clientCertificate() {
        return Optional.ofNullable(clientCertificate);
    }

    /**
     * The PKCS#8 PEM client key.
     *
     * @return the path, empty when not set
     */
    public Optional<Path> clientKey() {
        return Optional.ofNullable(clientKey);
    }

    /**
     * The key manager factory.
     *
     * @return the factory, empty when not set
     */
    public Optional<KeyManagerFactory> keyManagerFactory() {
        return Optional.ofNullable(keyManagerFactory);
    }

    /**
     * Host name verified against the server certificate instead of the endpoint host.
     *
     * @return the name, empty when the endpoint host is used
     */
    public Optional<String> serverNameOverride() {
        return Optional.ofNullable(serverNameOverride);
    }

    /**
     * Whether a client certificate is configured.
     *
     * @return {@code true} with certificate files or a key manager
     */
    public boolean hasClientCertificate() {
        return clientCertificate != null || keyManagerFactory != null;
    }

    @Override
    public String toString() {
        if (!enabled) {
            return "TlsSettings[disabled]";
        }
        return "TlsSettings[ca=" + (caCertificate != null ? caCertificate
                : trustManagerFactory != null ? "trustManager" : "default")
                + ", clientCertificate=" + hasClientCertificate()
                + (serverNameOverride != null ? ", serverName=" + serverNameOverride : "") + "]";
    }

    /** Builder of {@link TlsSettings}. Not thread-safe. */
    public static final class Builder {
        private Boolean enabled;
        private Path caCertificate;
        private TrustManagerFactory trustManagerFactory;
        private Path clientCertificate;
        private Path clientKey;
        private KeyManagerFactory keyManagerFactory;
        private String serverNameOverride;

        private Builder() {}

        /**
         * Turns TLS on or off explicitly (default: on exactly when another TLS option is set).
         *
         * @param enabled whether to use TLS
         * @return this builder
         */
        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        /**
         * Trusts the CA certificates of a PEM file.
         *
         * @param path the file
         * @return this builder
         */
        public Builder caCertificate(Path path) {
            this.caCertificate = Objects.requireNonNull(path, "path");
            this.trustManagerFactory = null;
            return this;
        }

        /**
         * Trusts what a trust manager factory trusts.
         *
         * @param factory an initialized factory
         * @return this builder
         */
        public Builder trustManager(TrustManagerFactory factory) {
            this.trustManagerFactory = Objects.requireNonNull(factory, "factory");
            this.caCertificate = null;
            return this;
        }

        /**
         * Presents a client certificate (mutual TLS).
         *
         * @param certificateChain PEM certificate chain file
         * @param privateKey PKCS#8 PEM private key file (unencrypted)
         * @return this builder
         */
        public Builder clientCertificate(Path certificateChain, Path privateKey) {
            this.clientCertificate = Objects.requireNonNull(certificateChain, "certificateChain");
            this.clientKey = Objects.requireNonNull(privateKey, "privateKey");
            this.keyManagerFactory = null;
            return this;
        }

        /**
         * Presents the client certificate of a key manager factory (mutual TLS).
         *
         * @param factory an initialized factory
         * @return this builder
         */
        public Builder keyManager(KeyManagerFactory factory) {
            this.keyManagerFactory = Objects.requireNonNull(factory, "factory");
            this.clientCertificate = null;
            this.clientKey = null;
            return this;
        }

        /**
         * Verifies the server certificate against this name instead of the endpoint host.
         *
         * @param name a DNS name or IP address
         * @return this builder
         */
        public Builder serverNameOverride(String name) {
            this.serverNameOverride = Objects.requireNonNull(name, "name");
            return this;
        }

        /**
         * Builds the settings.
         *
         * @return the settings
         */
        public TlsSettings build() {
            boolean options = caCertificate != null || trustManagerFactory != null
                    || clientCertificate != null || keyManagerFactory != null
                    || serverNameOverride != null;
            if (Boolean.FALSE.equals(enabled) && options) {
                throw new IllegalArgumentException("TLS disabled together with TLS options");
            }
            return new TlsSettings(this, enabled != null ? enabled : options);
        }
    }
}
