// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Arrays;
import java.util.Objects;
import javax.net.ssl.KeyManager;

/**
 * How the client authenticates (java-driver.md §2, protocol.md §8, DEC-014).
 *
 * <ul>
 *   <li>{@link #scram(String, char[])}: user and password, SCRAM-SHA-256 (the default);
 *   <li>{@link #apiKey(char[])}: an API key ({@code rgn_…}) sent as
 *       {@code authorization: ApiKey …}, no handshake;
 *   <li>{@link #x509()}: the TLS client certificate configured in {@link TlsSettings}, or
 *       {@link #x509(KeyManager)} with the certificate in a key manager.
 * </ul>
 *
 * <p>Secrets are kept as {@code char[]} copies and never appear in {@link #toString()}.
 * Immutable and thread-safe (the arrays are never exposed).
 */
public final class RustegonCredential {
    /** Authentication mechanism. */
    public enum Mechanism {
        /** SCRAM-SHA-256 with user and password. */
        SCRAM_SHA_256,
        /** API key. */
        API_KEY,
        /** TLS client certificate. */
        X509
    }

    private final Mechanism mechanism;
    private final String user;
    private final char[] secret;
    private final KeyManager keyManager;

    private RustegonCredential(Mechanism mechanism, String user, char[] secret,
            KeyManager keyManager) {
        this.mechanism = mechanism;
        this.user = user;
        this.secret = secret;
        this.keyManager = keyManager;
    }

    /**
     * User and password (SCRAM-SHA-256).
     *
     * @param user the user name (non-empty)
     * @param password the password (copied; the caller may wipe its array)
     * @return the credential
     */
    public static RustegonCredential scram(String user, char[] password) {
        Objects.requireNonNull(password, "password");
        if (user == null || user.isEmpty()) {
            throw new IllegalArgumentException("the user name must not be empty");
        }
        return new RustegonCredential(Mechanism.SCRAM_SHA_256, user, password.clone(), null);
    }

    /**
     * An API key ({@code rgn_…}).
     *
     * @param key the key (copied)
     * @return the credential
     */
    public static RustegonCredential apiKey(char[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length == 0) {
            throw new IllegalArgumentException("the API key must not be empty");
        }
        for (char c : key) {
            if (c <= 0x20 || c >= 0x7F) {
                throw new IllegalArgumentException("the API key must be visible ASCII");
            }
        }
        return new RustegonCredential(Mechanism.API_KEY, null, key.clone(), null);
    }

    /**
     * An API key ({@code rgn_…}); prefer {@link #apiKey(char[])} when the key can be wiped.
     *
     * @param key the key
     * @return the credential
     */
    public static RustegonCredential apiKey(String key) {
        return apiKey(Objects.requireNonNull(key, "key").toCharArray());
    }

    /**
     * The TLS client certificate of {@link TlsSettings.Builder#clientCertificate} (or its key
     * manager) authenticates; the server maps it to an {@code x509:} user.
     *
     * @return the credential
     */
    public static RustegonCredential x509() {
        return new RustegonCredential(Mechanism.X509, null, new char[0], null);
    }

    /**
     * The client certificate held by {@code keyManager} authenticates (it takes precedence over
     * a client certificate of {@link TlsSettings}); the server maps it to an {@code x509:} user.
     *
     * @param keyManager the key manager offering the certificate and its key
     * @return the credential
     */
    public static RustegonCredential x509(KeyManager keyManager) {
        return new RustegonCredential(Mechanism.X509, null, new char[0],
                Objects.requireNonNull(keyManager, "keyManager"));
    }

    /** The key manager of {@link #x509(KeyManager)}, or {@code null}. */
    KeyManager keyManager() {
        return keyManager;
    }

    /**
     * The mechanism.
     *
     * @return the mechanism
     */
    public Mechanism mechanism() {
        return mechanism;
    }

    /**
     * The user name of a SCRAM credential.
     *
     * @return the user, {@code null} for API keys and X.509
     */
    public String user() {
        return user;
    }

    /** A copy of the password or key, for the driver's authenticator. */
    char[] secret() {
        return secret.clone();
    }

    /**
     * A SCRAM credential for the same user with another password (after a password change).
     *
     * @param password the new password (copied)
     * @return the credential
     */
    RustegonCredential withPassword(char[] password) {
        return scram(user, password);
    }

    @Override
    public String toString() {
        return switch (mechanism) {
            case SCRAM_SHA_256 -> "RustegonCredential[SCRAM-SHA-256, user=" + user
                    + ", password=‹redacted›]";
            case API_KEY -> "RustegonCredential[ApiKey ‹redacted›]";
            case X509 -> "RustegonCredential[X509]";
        };
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RustegonCredential c && mechanism == c.mechanism
                && Objects.equals(user, c.user) && Arrays.equals(secret, c.secret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mechanism, user);
    }
}
