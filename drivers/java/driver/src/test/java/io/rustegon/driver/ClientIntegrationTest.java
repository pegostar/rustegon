// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ClientInterceptors;
import io.grpc.Grpc;
import io.grpc.MethodDescriptor;
import io.rustegon.driver.internal.ChannelPool;
import io.rustegon.driver.internal.RequestInterceptor;
import io.rustegon.driver.internal.proto.PingRequest;
import io.rustegon.driver.internal.proto.SessionServiceGrpc;
import io.rustegon.driver.testing.RustegonTestServer;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLSession;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * The driver stack end to end against a real {@code rustegond} (PD-072 process fixture,
 * binaries from {@code RUSTEGON_BIN_DIR}). TC-DRV-JAVA-009 (FR-DRV-002, FR-SEC-001, protocol.md
 * §8): SCRAM-SHA-256 login as the {@code rustegon init} administrator (server signature
 * verified), {@code Ping}, {@code GetServerInfo}, connection-string login, rejected credentials
 * and the password change of PD-076. TC-DRV-JAVA-010, server part (FR-TLS-001, protocol.md
 * §5.3): TLS 1.3 negotiated, the server certificate must chain to the configured CA and match
 * the expected name, concurrent use from virtual threads. Skipped without the Rust binaries
 * (fails under {@code CI=true}).
 */
@Tag("integration")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ClientIntegrationTest {
    @Test
    @Order(1)
    void tc_drv_java_009_scram_login_ping_and_server_info() {
        RustegonTestServer server = RustegonTestServer.shared();
        try (RustegonClient client = RustegonClient.create(server.adminSettings().build())) {
            client.ping();
            ServerInfo info = client.serverInfo();
            assertFalse(info.serverVersion().isEmpty());
            assertTrue(info.protocolVersion().startsWith("1."), info.protocolVersion());
            assertFalse(client.isPasswordChangeRequired());
        }
    }

    @Test
    @Order(2)
    void tc_drv_java_009_connection_string_login() {
        RustegonTestServer server = RustegonTestServer.shared();
        String cs = "rustegon://" + RustegonTestServer.ADMIN_USER + "@" + server.grpcEndpoint()
                + "/admin?tlsCaFile=" + server.caCertificate().toString().replace('\\', '/');
        // The password travels separately (DEC-014: credential object preferred).
        RustegonClientSettings settings = RustegonClientSettings.builder().connectionString(cs)
                .credential(RustegonCredential.scram(RustegonTestServer.ADMIN_USER,
                        server.adminPassword()))
                .build();
        try (RustegonClient client = RustegonClient.create(settings)) {
            client.ping();
        }
    }

    @Test
    @Order(3)
    void tc_drv_java_009_wrong_password_is_an_authentication_error() {
        RustegonTestServer server = RustegonTestServer.shared();
        RustegonClientSettings settings = server.settings(RustegonCredential.scram(
                RustegonTestServer.ADMIN_USER, "not-the-password-1234".toCharArray())).build();
        try (RustegonClient client = RustegonClient.create(settings)) {
            AuthenticationException e = assertThrows(AuthenticationException.class,
                    client::ping);
            assertEquals(4001, e.code());
            assertEquals("Unauthenticated", e.name());
            assertFalse(e.getMessage().contains("not-the-password"));
        }
        RustegonClientSettings unknown = server.settings(RustegonCredential.scram("nobody",
                "whatever-password-1".toCharArray())).build();
        try (RustegonClient client = RustegonClient.create(unknown)) {
            assertEquals(4001, assertThrows(AuthenticationException.class, client::ping).code(),
                    "unknown users and wrong passwords look the same (protocol.md §8)");
        }
    }

    @Test
    @Order(4)
    void tc_drv_java_010_untrusted_server_certificate_is_unavailable() {
        RustegonTestServer server = RustegonTestServer.shared();
        RustegonClientSettings settings = RustegonClientSettings.builder()
                .endpoints(server.grpcEndpoint())
                .tls(TlsSettings.defaults()) // JDK trust store: does not know the test CA
                .build();
        try (RustegonClient client = RustegonClient.create(settings)) {
            RustegonException e = assertThrows(RustegonException.class, client::ping);
            assertInstanceOf(UnavailableException.class, e);
        }
        assertThrows(IllegalArgumentException.class, () -> RustegonClient.create(
                RustegonClientSettings.builder().endpoints(server.grpcEndpoint())
                        .tls(TlsSettings.builder().caCertificate(Path.of("missing-ca.crt"))
                                .build()).build()));
    }

    @Test
    @Order(4)
    void tc_drv_java_010_server_name_must_match_the_certificate() {
        RustegonTestServer server = RustegonTestServer.shared();
        RustegonClientSettings settings = RustegonClientSettings.builder()
                .endpoints(server.grpcEndpoint())
                .tls(TlsSettings.builder().caCertificate(server.caCertificate())
                        .serverNameOverride("not-the-node.example.com").build())
                .build();
        try (RustegonClient client = RustegonClient.create(settings)) {
            assertInstanceOf(UnavailableException.class,
                    assertThrows(RustegonException.class, client::ping));
        }
    }

    @Test
    @Order(4)
    void tc_drv_java_010_tls_1_3_is_negotiated() {
        // FR-TLS-001: the node listens with TLS 1.3 by default; the driver offers the JDK's
        // protocols (1.3 first) and must end up on 1.3 with the configured CA.
        RustegonTestServer server = RustegonTestServer.shared();
        AtomicReference<ClientCall<?, ?>> last = new AtomicReference<>();
        ClientInterceptor capture = new ClientInterceptor() {
            @Override
            public <Q, R> ClientCall<Q, R> interceptCall(MethodDescriptor<Q, R> method,
                    CallOptions options, Channel next) {
                ClientCall<Q, R> call = next.newCall(method, options);
                last.set(call);
                return call;
            }
        };
        try (ChannelPool pool = ChannelPool.open(List.of(server.grpcEndpoint()),
                TlsSettings.builder().caCertificate(server.caCertificate()).build(), 1,
                new RequestInterceptor(Duration.ofSeconds(30)), "rustegon-java-tests", null)) {
            SessionServiceGrpc.newBlockingStub(ClientInterceptors.intercept(pool.next(), capture))
                    .ping(PingRequest.getDefaultInstance());
            SSLSession session = last.get().getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
            assertEquals("TLSv1.3", session.getProtocol());
        }
    }

    @Test
    @Order(5)
    void tc_drv_java_010_concurrent_calls_on_virtual_threads() throws Exception {
        RustegonTestServer server = RustegonTestServer.shared();
        try (RustegonClient client = RustegonClient.create(server.adminSettings().build());
                ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<ServerInfo>> calls = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                calls.add(pool.submit(() -> {
                    client.ping();
                    return client.serverInfo();
                }));
            }
            String version = null;
            for (Future<ServerInfo> f : calls) {
                String v = f.get().serverVersion();
                if (version != null) {
                    assertEquals(version, v);
                }
                version = v;
            }
        }
    }

    @Test
    @Order(6)
    void tc_drv_java_009_change_password_then_log_in_with_the_new_one() {
        RustegonTestServer server = RustegonTestServer.shared();
        char[] old = server.adminPassword();
        char[] fresh = ("Nw-" + java.util.UUID.randomUUID()).toCharArray();
        try (RustegonClient client = RustegonClient.create(server.adminSettings().build())) {
            client.ping();
            client.changePassword(old, fresh);
            server.adminPasswordChanged(fresh);
            // The next call logs in again, with the new password.
            client.ping();
        }
        try (RustegonClient client = RustegonClient.create(server.adminSettings().build())) {
            client.ping();
        }
        RustegonClientSettings stale = server.settings(RustegonCredential.scram(
                RustegonTestServer.ADMIN_USER, old)).build();
        try (RustegonClient client = RustegonClient.create(stale)) {
            assertThrows(AuthenticationException.class, client::ping);
        }
    }
}
