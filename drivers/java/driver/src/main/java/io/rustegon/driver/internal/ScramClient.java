// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Client side of SCRAM-SHA-256 (RFC 5802, RFC 7677; protocol.md §8).
 *
 * <pre>
 * client-first  n,,n=&lt;user&gt;,r=&lt;cnonce&gt;
 * server-first  r=&lt;cnonce&gt;&lt;snonce&gt;,s=&lt;salt b64&gt;,i=&lt;iterations&gt;
 * client-final  c=biws,r=&lt;nonce&gt;,p=&lt;b64(ClientProof)&gt;
 * server-final  v=&lt;b64(ServerSignature)&gt;
 * </pre>
 *
 * <p>No channel binding (gs2 header {@code n,,}, PD-074): grpc-netty-shaded does not expose the
 * TLS exporter, exactly as the Rust CLI. Key derivation: {@code SaltedPassword =
 * PBKDF2-HMAC-SHA256(SASLprep(password), salt, i)}, {@code ClientKey = HMAC(SaltedPassword,
 * "Client Key")}, {@code StoredKey = SHA256(ClientKey)}, {@code ClientProof = ClientKey XOR
 * HMAC(StoredKey, AuthMessage)}; the server proves knowledge of {@code ServerKey} with
 * {@code ServerSignature = HMAC(HMAC(SaltedPassword, "Server Key"), AuthMessage)}, which
 * {@link #verifyServerFinal} checks in constant time before the session token may be used.
 *
 * <p>The iteration count is bounded as the server's client is ({@value #MIN_ITERATIONS} to
 * {@value #MAX_ITERATIONS}): a malicious server could otherwise make the client spin. One
 * instance serves one exchange and is not thread-safe; the password copy is wiped after use.
 */
public final class ScramClient {
    /** RFC 7677 §4: at least 4096 iterations. */
    public static final int MIN_ITERATIONS = 4096;
    /** Largest iteration count accepted (about 20 s of PBKDF2 on current CPUs). */
    public static final int MAX_ITERATIONS = 10_000_000;
    /** Smallest server nonce suffix accepted (characters). */
    private static final int MIN_SERVER_NONCE_LEN = 16;
    /** Characters of the client nonce: 24 base62 characters are about 143 bits. */
    private static final int NONCE_LEN = 24;
    private static final String NONCE_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    /** {@code c=} of the client-final message: base64 of the gs2 header {@code n,,}. */
    private static final String CHANNEL_BINDING = "c=biws";
    private static final String HMAC = "HmacSHA256";

    private final String clientFirstBare;
    private final String clientNonce;
    private char[] password;
    private byte[] serverSignature;
    private String authMessage;

    /**
     * Starts an exchange with a fresh random nonce.
     *
     * @param user user name (sent as a SASL {@code saslname})
     * @param password password (copied; the copy is wiped after the proof is computed)
     */
    public ScramClient(String user, char[] password) {
        this(user, password, randomNonce());
    }

    /**
     * Starts an exchange with a given nonce (test vectors).
     *
     * @param user user name
     * @param password password
     * @param clientNonce printable client nonce
     */
    ScramClient(String user, char[] password, String clientNonce) {
        this.clientNonce = clientNonce;
        this.password = password.clone();
        this.clientFirstBare = "n=" + saslName(user) + ",r=" + clientNonce;
    }

    private static String randomNonce() {
        SecureRandom random = new SecureRandom();
        StringBuilder s = new StringBuilder(NONCE_LEN);
        for (int i = 0; i < NONCE_LEN; i++) {
            s.append(NONCE_ALPHABET.charAt(random.nextInt(NONCE_ALPHABET.length())));
        }
        return s.toString();
    }

    /** RFC 5802 §5.1: {@code =} as {@code =3D} and {@code ,} as {@code =2C}. */
    static String saslName(String user) {
        return user.replace("=", "=3D").replace(",", "=2C");
    }

    /**
     * The client-first message.
     *
     * @return {@code n,,n=<user>,r=<nonce>}
     */
    public String clientFirst() {
        return "n,," + clientFirstBare;
    }

    /**
     * Processes the server-first message and returns the client-final message.
     *
     * @param serverFirst the server's challenge
     * @return the client-final message
     * @throws ScramException if the challenge is malformed, its nonce does not extend ours, or
     *     its iteration count is out of bounds
     */
    public String clientFinal(String serverFirst) {
        String[] parts = serverFirst.split(",", -1);
        if (parts.length < 3 || !parts[0].startsWith("r=") || !parts[1].startsWith("s=")
                || !parts[2].startsWith("i=")) {
            throw new ScramException("malformed server-first message");
        }
        String nonce = parts[0].substring(2);
        if (!nonce.startsWith(clientNonce)
                || nonce.length() < clientNonce.length() + MIN_SERVER_NONCE_LEN
                || !printable(nonce)) {
            throw new ScramException("server nonce does not extend the client nonce");
        }
        byte[] salt;
        int iterations;
        try {
            salt = Base64.getDecoder().decode(parts[1].substring(2));
            iterations = Integer.parseInt(parts[2].substring(2));
        } catch (IllegalArgumentException e) {
            throw new ScramException("malformed server-first message");
        }
        if (salt.length == 0 || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new ScramException("server-first salt or iteration count out of bounds");
        }
        String withoutProof = CHANNEL_BINDING + ",r=" + nonce;
        authMessage = clientFirstBare + "," + serverFirst + "," + withoutProof;
        byte[] salted = null;
        byte[] clientKey = null;
        try {
            byte[] prepared = SaslPrep.prepare(java.nio.CharBuffer.wrap(password))
                    .getBytes(StandardCharsets.UTF_8);
            try {
                salted = pbkdf2(prepared, salt, iterations);
            } finally {
                Arrays.fill(prepared, (byte) 0);
            }
            clientKey = hmac(salted, "Client Key");
            byte[] storedKey = MessageDigest.getInstance("SHA-256").digest(clientKey);
            byte[] clientSignature = hmac(storedKey, authMessage);
            byte[] proof = new byte[clientKey.length];
            for (int i = 0; i < proof.length; i++) {
                proof[i] = (byte) (clientKey[i] ^ clientSignature[i]);
            }
            serverSignature = hmac(hmac(salted, "Server Key"), authMessage);
            return withoutProof + ",p=" + Base64.getEncoder().encodeToString(proof);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 / HmacSHA256 unavailable", e);
        } finally {
            Arrays.fill(password, '\0');
            if (salted != null) {
                Arrays.fill(salted, (byte) 0);
            }
            if (clientKey != null) {
                Arrays.fill(clientKey, (byte) 0);
            }
        }
    }

    /**
     * Verifies the server-final message (mutual authentication).
     *
     * @param serverFinal {@code v=<b64(ServerSignature)>}
     * @throws ScramException if the server reports an error or its signature does not match
     */
    public void verifyServerFinal(String serverFinal) {
        if (serverSignature == null) {
            throw new IllegalStateException("clientFinal has not run");
        }
        if (!serverFinal.startsWith("v=")) {
            throw new ScramException("server-final message carries no verifier");
        }
        byte[] v;
        try {
            v = Base64.getDecoder().decode(serverFinal.substring(2));
        } catch (IllegalArgumentException e) {
            throw new ScramException("malformed server-final message");
        }
        if (!MessageDigest.isEqual(v, serverSignature)) {
            throw new ScramException("server signature mismatch");
        }
    }

    /** RFC 5802 {@code printable}: %x21-2B / %x2D-7E (no comma). */
    private static boolean printable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x21 || c > 0x7E || c == ',') {
                return false;
            }
        }
        return true;
    }

    private static byte[] hmac(byte[] key, String data) throws GeneralSecurityException {
        return hmac(key, data.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key, HMAC));
        return mac.doFinal(data);
    }

    /**
     * PBKDF2-HMAC-SHA256 with a 32-byte output: one block, {@code U1 = HMAC(P, salt || 1)},
     * {@code Ui = HMAC(P, U(i-1))}, result = XOR of all {@code Ui} (RFC 8018 §5.2). Written out
     * rather than through {@code SecretKeyFactory} so the exact password bytes (UTF-8 of the
     * SASLprep output) are under our control.
     */
    static byte[] pbkdf2(byte[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC);
        // SecretKeySpec rejects an empty key; HMAC pads keys with zeros to the block size, so a
        // single zero byte is the same key as the empty one.
        mac.init(new SecretKeySpec(password.length == 0 ? new byte[1] : password, HMAC));
        mac.update(salt);
        byte[] u = mac.doFinal(new byte[] {0, 0, 0, 1});
        byte[] result = u.clone();
        for (int i = 1; i < iterations; i++) {
            u = mac.doFinal(u);
            for (int k = 0; k < result.length; k++) {
                result[k] ^= u[k];
            }
        }
        return result;
    }
}
