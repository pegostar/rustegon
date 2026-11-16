// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * A parsed {@code rustegon://} connection string (DEC-014, dotnet-driver.md §3; same grammar in
 * every driver, {@code drivers/conformance/connstring.yaml}):
 *
 * <pre>
 * rustegon://[user[:password]@]host[:port][,host[:port]...][/[database]][?option=value[&amp;...]]
 * </pre>
 *
 * <p>The grammar and the test cases are {@code drivers/conformance/connstring.yaml}. The scheme
 * is lower case. Hosts are DNS names (compared case-insensitively, kept in lower case), IPv4
 * addresses or bracketed IPv6 addresses; the port defaults to {@value #DEFAULT_PORT}. User,
 * password, database and option values are percent-decoded (UTF-8; {@code +} is a plus sign); a
 * raw {@code @} in the user information is an error. Option names are case-insensitive, each may
 * appear once, and an unknown name is an error (a typo must not silently drop a setting).
 * Options:
 *
 * <ul>
 *   <li>{@code tls} ({@code true}/{@code false}, default false, ADR-034: without an explicit
 *       {@code tls}, any tls* option or {@code authMechanism=X509} turns TLS on, and
 *       {@code tls=false} with either is an error), {@code tlsCaFile}; Java and .NET
 *       extensions: {@code tlsCertificateFile} + {@code tlsKeyFile}, {@code tlsServerName};
 *   <li>{@code authMechanism}: {@code SCRAM-SHA-256} (default with a user), {@code X509} (no
 *       password) or {@code APIKEY} (alias {@code API-KEY}; needs {@code apiKey} and no user);
 *       {@code apiKey} alone implies {@code APIKEY} and is refused with the other mechanisms;
 *   <li>{@code appName}, {@code connectTimeoutMs}, {@code operationTimeoutMs},
 *       {@code connectionsPerEndpoint} (1-64), {@code retryReads}, {@code retryWrites},
 *       {@code maxRetries} (0-10);
 *   <li>{@code readConsistency} ({@code linearizable}, {@code bounded_staleness},
 *       {@code follower}), {@code maxStalenessMs} (required by {@code bounded_staleness}),
 *       {@code writeConcern} ({@code majority},
 *       {@code all}, {@code local_dc_majority}, {@code sync_cross_dc}, {@code async_cross_dc}).
 * </ul>
 *
 * <p>A password or API key in the string is accepted but discouraged: prefer a
 * {@link RustegonCredential}. {@link #toString()} redacts both, {@link #options()} does not hold
 * the API key, and parse errors never quote them. {@code rustegon+srv://}
 * (DNS SRV seeds) is not supported in R1 (PD-069).
 */
public final class ConnectionString {
    /** Default gRPC port (protocol.md §1). */
    public static final int DEFAULT_PORT = 7700;
    private static final String SCHEME = "rustegon://";
    private static final List<String> OPTIONS = List.of("tls", "tlsCaFile",
            "tlsCertificateFile", "tlsKeyFile", "tlsServerName", "authMechanism", "apiKey", "appName",
            "connectTimeoutMs", "operationTimeoutMs", "connectionsPerEndpoint", "retryReads",
            "retryWrites", "maxRetries", "readConsistency", "maxStalenessMs", "writeConcern");

    private final List<String> endpoints;
    private final String user;
    private final char[] password;
    private final String database;
    private final Map<String, String> options;
    private final String apiKey;

    private ConnectionString(List<String> endpoints, String user, char[] password,
            String database, Map<String, String> options) {
        this.endpoints = List.copyOf(endpoints);
        this.user = user;
        this.password = password;
        this.database = database;
        // The API key is a secret: kept out of the public options map.
        this.apiKey = options.remove("apiKey");
        this.options = Collections.unmodifiableMap(options);
    }

    /**
     * Parses a connection string.
     *
     * @param text the string
     * @return the parsed form
     * @throws IllegalArgumentException if the string is malformed (the message never contains
     *     the password)
     */
    public static ConnectionString parse(String text) {
        if (text.startsWith("rustegon+srv://")) {
            throw new IllegalArgumentException(
                    "rustegon+srv:// (DNS SRV seeds) is not supported yet; list the hosts");
        }
        if (!text.startsWith(SCHEME)) {
            throw new IllegalArgumentException("a connection string starts with rustegon://");
        }
        String rest = text.substring(SCHEME.length());
        String query = null;
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        String user = null;
        char[] password = null;
        // The user information ends at the first '@'; a second one means an unescaped '@' in
        // the password (RFC 3986 needs %40), which is rejected rather than guessed at. A '/'
        // in a raw password would otherwise be taken for the start of the path.
        int at = rest.indexOf('@');
        if (at >= 0 && rest.indexOf('@', at + 1) >= 0) {
            throw new IllegalArgumentException(
                    "the user information contains a raw '@': percent-encode it as %40");
        }
        int slash = rest.indexOf('/', at + 1);
        String authority = slash >= 0 ? rest.substring(0, slash) : rest;
        String path = slash >= 0 ? rest.substring(slash + 1) : null;
        at = authority.indexOf('@');
        if (at >= 0) {
            String userInfo = authority.substring(0, at);
            authority = authority.substring(at + 1);
            int colon = userInfo.indexOf(':');
            String rawUser = colon >= 0 ? userInfo.substring(0, colon) : userInfo;
            user = decode(rawUser, "user name");
            if (user.isEmpty()) {
                throw new IllegalArgumentException("the user name is empty");
            }
            if (colon >= 0) {
                password = decodeSecret(userInfo.substring(colon + 1));
            }
        }
        List<String> endpoints = hosts(authority);
        String database = null;
        if (path != null && !path.isEmpty()) {
            if (path.contains("/")) {
                throw new IllegalArgumentException("the database name cannot contain '/'");
            }
            database = decode(path, "database name");
        }
        Map<String, String> options = options(query);
        if (password != null && user == null) {
            throw new IllegalArgumentException("a password needs a user");
        }
        return new ConnectionString(endpoints, user, password, database, options);
    }

    private static List<String> hosts(String authority) {
        if (authority.isEmpty()) {
            throw new IllegalArgumentException("the connection string names no host");
        }
        List<String> out = new ArrayList<>();
        for (String h : authority.split(",", -1)) {
            out.add(endpoint(h));
        }
        return out;
    }

    /** {@code host[:port]} → canonical {@code host:port} ({@code [v6]:port} for IPv6). */
    static String endpoint(String h) {
        String host;
        String port = null;
        if (h.startsWith("[")) {
            int close = h.indexOf(']');
            if (close < 0) {
                throw new IllegalArgumentException("unterminated IPv6 address in " + h);
            }
            host = h.substring(0, close + 1);
            String after = h.substring(close + 1);
            if (!after.isEmpty()) {
                if (!after.startsWith(":")) {
                    throw new IllegalArgumentException("invalid host " + h);
                }
                port = after.substring(1);
            }
            host = host.toLowerCase(Locale.ROOT);
            String inner = host.substring(1, host.length() - 1);
            if (inner.isEmpty() || !inner.chars().allMatch(c -> c == ':' || c == '.'
                    || Character.digit(c, 16) >= 0 && c < 0x80)) {
                throw new IllegalArgumentException("invalid IPv6 address " + host);
            }
        } else {
            int colon = h.indexOf(':');
            if (colon >= 0 && h.indexOf(':', colon + 1) >= 0) {
                throw new IllegalArgumentException("an IPv6 address needs brackets: " + h);
            }
            host = colon >= 0 ? h.substring(0, colon) : h;
            port = colon >= 0 ? h.substring(colon + 1) : null;
            if (host.isEmpty() || !host.chars().allMatch(c -> (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
                    || c == '_')) {
                throw new IllegalArgumentException("invalid host '" + host + "'");
            }
            // Host names are case-insensitive: one spelling for every equal string.
            host = host.toLowerCase(Locale.ROOT);
        }
        int p = DEFAULT_PORT;
        if (port != null) {
            p = parseInt(port, "port");
            if (p < 1 || p > 65_535) {
                throw new IllegalArgumentException("port out of range: " + port);
            }
        }
        return host + ":" + p;
    }

    private static Map<String, String> options(String query) {
        Map<String, String> out = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) {
            return out;
        }
        for (String pair : query.split("&", -1)) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("option without a value: " + pair);
            }
            String rawName = pair.substring(0, eq);
            String name = OPTIONS.stream().filter(o -> o.equalsIgnoreCase(rawName)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("unknown option " + rawName));
            if (out.containsKey(name)) {
                throw new IllegalArgumentException("option " + name + " appears twice");
            }
            out.put(name, decode(pair.substring(eq + 1), "option " + name));
        }
        return out;
    }

    private static int parseInt(String s, String what) {
        if (s.isEmpty() || s.length() > 9 || !s.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new IllegalArgumentException("invalid " + what + ": " + s);
        }
        return Integer.parseInt(s);
    }

    /** Percent-decoding as strict UTF-8; {@code +} stays a plus sign. */
    private static String decode(String s, String what) {
        return new String(decodeBytes(s, what), StandardCharsets.UTF_8);
    }

    private static char[] decodeSecret(String s) {
        byte[] bytes = decodeBytes(s, "password");
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            char[] out = new char[chars.remaining()];
            chars.get(out);
            return out;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("the password is not valid percent-encoded UTF-8");
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    private static byte[] decodeBytes(String s, String what) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 2 >= s.length()) {
                    throw new IllegalArgumentException("truncated percent escape in the " + what);
                }
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi < 0 || lo < 0 || s.charAt(i + 1) >= 0x80 || s.charAt(i + 2) >= 0x80) {
                    throw new IllegalArgumentException("invalid percent escape in the " + what);
                }
                out.write(hi * 16 + lo);
                i += 2;
            } else {
                int cp = s.codePointAt(i);
                if (Character.isSurrogate((char) cp) && cp < 0x10000) {
                    throw new IllegalArgumentException("unpaired surrogate in the " + what);
                }
                out.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
                i += Character.charCount(cp) - 1;
            }
        }
        byte[] bytes = out.toByteArray();
        if (!"password".equals(what)) {
            try {
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes));
            } catch (CharacterCodingException e) {
                throw new IllegalArgumentException("the " + what + " is not valid UTF-8");
            }
        }
        return bytes;
    }

    /**
     * The endpoints as {@code host:port}, in order.
     *
     * @return the endpoints
     */
    public List<String> endpoints() {
        return endpoints;
    }

    /**
     * The user name.
     *
     * @return the user, empty when the string has none
     */
    public Optional<String> user() {
        return Optional.ofNullable(user);
    }

    /**
     * A copy of the password.
     *
     * @return the password, empty when the string has none
     */
    public Optional<char[]> password() {
        return Optional.ofNullable(password).map(char[]::clone);
    }

    /**
     * The default database.
     *
     * @return the database, empty when the string has none
     */
    public Optional<String> database() {
        return Optional.ofNullable(database);
    }

    /**
     * The authentication mechanism of the string: the {@code authMechanism} option in upper
     * case ({@code API-KEY} as {@code APIKEY}), else {@code APIKEY} with an {@code apiKey}, else
     * {@code SCRAM-SHA-256} when the string names a user.
     *
     * @return the mechanism, empty for an anonymous string
     */
    public Optional<String> authMechanism() {
        String m = options.get("authMechanism");
        if (m != null) {
            m = m.toUpperCase(Locale.ROOT);
            return Optional.of(m.equals("API-KEY") ? "APIKEY" : m);
        }
        if (apiKey != null) {
            return Optional.of("APIKEY");
        }
        return user != null ? Optional.of("SCRAM-SHA-256") : Optional.empty();
    }

    /**
     * The options, by canonical name (as listed in the class documentation).
     *
     * @return an unmodifiable map
     */
    public Map<String, String> options() {
        return options;
    }

    /**
     * Applies the string to a settings builder: endpoints, credential, database and options.
     *
     * @param b the builder
     * @return the builder
     * @throws IllegalArgumentException for invalid option values
     */
    public RustegonClientSettings.Builder applyTo(RustegonClientSettings.Builder b) {
        b.endpoints(endpoints);
        if (database != null) {
            b.defaultDatabase(database);
        }
        String mechanism = authMechanism().orElse(null);
        if (mechanism != null) {
            switch (mechanism) {
                case "APIKEY" -> {
                    if (apiKey == null || user != null) {
                        throw new IllegalArgumentException(
                                "authMechanism=APIKEY needs apiKey=... and no user");
                    }
                    b.credential(RustegonCredential.apiKey(apiKey));
                }
                case "SCRAM-SHA-256" -> {
                    if (apiKey != null) {
                        throw new IllegalArgumentException(
                                "apiKey is only valid with authMechanism=APIKEY");
                    }
                    // Without a user the string only names the mechanism: the credential is
                    // set on the builder (connstring.yaml case spec_example_dotnet).
                    if (user != null) {
                        b.credential(RustegonCredential.scram(user,
                                password == null ? new char[0] : password));
                    }
                }
                case "X509" -> {
                    // The certificate is the credential; a password would be silently unused.
                    if (password != null || apiKey != null) {
                        throw new IllegalArgumentException("X509 takes no password or apiKey");
                    }
                    b.credential(RustegonCredential.x509());
                }
                default -> throw new IllegalArgumentException(
                        "unknown authMechanism " + mechanism);
            }
        }
        b.tls(tls());
        option("appName").ifPresent(b::applicationName);
        option("connectTimeoutMs").ifPresent(v -> b.connectTimeout(millis(v, "connectTimeoutMs")));
        option("operationTimeoutMs")
                .ifPresent(v -> b.defaultOperationTimeout(millis(v, "operationTimeoutMs")));
        option("connectionsPerEndpoint")
                .ifPresent(v -> b.connectionsPerEndpoint(parseInt(v, "connectionsPerEndpoint")));
        option("retryReads").ifPresent(v -> b.retryReads(bool(v, "retryReads")));
        option("retryWrites").ifPresent(v -> b.retryWrites(bool(v, "retryWrites")));
        option("maxRetries").ifPresent(v -> b.maxRetries(parseInt(v, "maxRetries")));
        option("readConsistency").ifPresent(v -> b.readConsistency(
                enumValue(ReadConsistency.class, v, "readConsistency")));
        option("maxStalenessMs").ifPresent(v -> b.maxStaleness(millis(v, "maxStalenessMs")));
        option("writeConcern").ifPresent(v -> b.writeConcern(
                enumValue(WriteConcern.class, v, "writeConcern")));
        if (option("readConsistency").map(v -> v.equalsIgnoreCase("bounded_staleness"))
                .orElse(false) && option("maxStalenessMs").isEmpty()) {
            throw new IllegalArgumentException(
                    "readConsistency=bounded_staleness needs maxStalenessMs");
        }
        return b;
    }

    private TlsSettings tls() {
        // ADR-034: plain text unless tls=true, a tls* option or X.509 (which needs TLS).
        boolean x509 = authMechanism().map("X509"::equals).orElse(false);
        boolean others = options.keySet().stream()
                .anyMatch(k -> k.startsWith("tls") && !k.equals("tls"));
        boolean enabled = option("tls").map(v -> bool(v, "tls")).orElse(x509 || others);
        if (!enabled) {
            if (x509 || others) {
                throw new IllegalArgumentException(
                        "tls=false contradicts the other tls options or authMechanism=X509");
            }
            return TlsSettings.disabled();
        }
        TlsSettings.Builder t = TlsSettings.builder();
        option("tlsCaFile").ifPresent(v -> t.caCertificate(Path.of(v)));
        Optional<String> cert = option("tlsCertificateFile");
        Optional<String> key = option("tlsKeyFile");
        if (cert.isPresent() != key.isPresent()) {
            throw new IllegalArgumentException("tlsCertificateFile and tlsKeyFile go together");
        }
        cert.ifPresent(c -> t.clientCertificate(Path.of(c), Path.of(key.orElseThrow())));
        option("tlsServerName").ifPresent(v -> {
            if (v.isEmpty()) {
                throw new IllegalArgumentException("tlsServerName must not be empty");
            }
            t.serverNameOverride(v);
        });
        return t.enabled(true).build();
    }

    private Optional<String> option(String name) {
        return Optional.ofNullable(options.get(name));
    }

    private static boolean bool(String v, String name) {
        return switch (v.toLowerCase(Locale.ROOT)) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new IllegalArgumentException(name + " must be true or false");
        };
    }

    private static Duration millis(String v, String name) {
        int ms = parseInt(v, name);
        if (ms <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return Duration.ofMillis(ms);
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, String v, String name) {
        for (E e : type.getEnumConstants()) {
            if (e.name().equalsIgnoreCase(v)) {
                return e;
            }
        }
        throw new IllegalArgumentException("unknown " + name + " " + v);
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder(SCHEME);
        if (user != null) {
            s.append(user);
            if (password != null) {
                s.append(":‹redacted›");
            }
            s.append('@');
        }
        s.append(String.join(",", endpoints));
        if (database != null) {
            s.append('/').append(database);
        }
        if (!options.isEmpty()) {
            s.append('?');
            boolean first = true;
            for (Map.Entry<String, String> e : options.entrySet()) {
                if (!first) {
                    s.append('&');
                }
                first = false;
                s.append(e.getKey()).append('=').append(e.getValue());
            }
        }
        if (apiKey != null) {
            s.append(options.isEmpty() ? '?' : '&').append("apiKey=‹redacted›");
        }
        return s.toString();
    }
}
