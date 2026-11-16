// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.samples;

import io.rustegon.driver.RustegonClient;
import io.rustegon.driver.RustegonClientSettings;
import io.rustegon.driver.RustegonCredential;
import io.rustegon.driver.TlsSettings;
import io.rustegon.driver.UnavailableException;
import io.rustegon.driver.mapping.DocumentCodec;
import io.rustegon.driver.mapping.Mapper;
import io.rustegon.driver.rdoc.RDocument;
import io.rustegon.samples.model.Order;
import io.rustegon.samples.model.Order_RgnCodec;
import java.io.IOException;
import java.math.BigDecimal;
import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;

/**
 * TC-DRV-JAVA-026: the driver as a named module. Run by the Gradle tasks {@code jpmsSmoke}
 * (JDK 21) and {@code jpmsSmokeJdk25} with every jar on the module path; exits non-zero on the
 * first failed check.
 *
 * <ol>
 *   <li>this class and the driver are named modules ({@code io.rustegon.samples},
 *       {@code io.rustegon.driver}) and the gRPC transport module
 *       ({@code io.grpc.netty.shaded}, a run-time-only dependency) is resolved;
 *   <li>{@link Mapper#codec} returns the codec rustegon-processor generated for {@link Order}
 *       (PD-113: found through the qualified export of the model package) and it round-trips
 *       through RDoc bytes;
 *   <li>a client loads the gRPC/Netty/TLS stack: a ping to a closed port fails with
 *       {@link UnavailableException} (RGN-3002), not with a linkage or service-loading error.
 * </ol>
 */
public final class JpmsSmoke {
    private JpmsSmoke() {}

    /**
     * Runs the checks.
     *
     * @param args unused
     * @throws IOException if no free port can be found
     */
    public static void main(String[] args) throws IOException {
        Module self = JpmsSmoke.class.getModule();
        check("io.rustegon.samples".equals(self.getName()), "samples module: " + self);
        check("io.rustegon.driver".equals(RustegonClient.class.getModule().getName()),
                "driver module: " + RustegonClient.class.getModule());
        check(ModuleLayer.boot().findModule("io.grpc.netty.shaded").isPresent(),
                "io.grpc.netty.shaded is not in the boot layer");

        DocumentCodec<Order> codec = Mapper.codec(Order.class);
        check(codec == Order_RgnCodec.INSTANCE, "expected the generated codec "
                + Mapper.generatedCodecName(Order.class) + ", got " + codec);
        Order order = new Order("o-1", null, "paid", new BigDecimal("12.50"),
                Instant.parse("2026-11-12T08:00:00.123Z"));
        Order back = codec.decode(RDocument.fromRDoc(codec.encode(order).toRDoc()), "");
        check(order.equals(back), "round trip: " + back);

        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        RustegonClientSettings settings = RustegonClientSettings.builder()
                .endpoints("127.0.0.1:" + port)
                .credential(RustegonCredential.scram("smoke", "not-a-secret".toCharArray()))
                .tls(TlsSettings.defaults()) // load the TLS stack too (plain text is the default)
                .connectTimeout(Duration.ofSeconds(5))
                .maxRetries(0)
                .build();
        try (RustegonClient client = RustegonClient.create(settings)) {
            client.ping();
            check(false, "ping to a closed port succeeded");
        } catch (UnavailableException expected) {
            check(expected.code() == 3002, "unexpected code " + expected.code());
        }
        System.out.println("TC-DRV-JAVA-026 JPMS smoke passed on Java "
                + Runtime.version().feature() + " (module path: " + self.getDescriptor().name()
                + " -> io.rustegon.driver)");
    }

    private static void check(boolean ok, String message) {
        if (!ok) {
            throw new AssertionError("TC-DRV-JAVA-026: " + message);
        }
    }
}
