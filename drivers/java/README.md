# Rustegon Java driver (`com.rustegon:rustegon-driver`)

Official Java driver of Rustegon (spec: [`docs/specifications/java-driver.md`](../../docs/specifications/java-driver.md)).
Baseline **Java 21**, tested on 21 and 25 (DEC-020); JPMS module `io.rustegon.driver`; synchronous API,
friendly to virtual threads (R1 scope, PD-069). Tests and their TC ids: [`TESTS.md`](TESTS.md);
differences from the specification and from the .NET driver: [`../DIVERGENCES.md`](../DIVERGENCES.md) §5.

## Artifacts

| Coordinates | Content |
|---|---|
| `com.rustegon:rustegon-driver` | the driver (exports `io.rustegon.driver`, `.errors`, `.rdoc`, `.mapping`) |
| `com.rustegon:rustegon-processor` | `@RustegonDocument` annotation processor: generated codecs and the `Order_` metamodel (compile time only, PD-113) |
| `com.rustegon:rustegon-bom` | BOM aligning the two |

Runtime dependencies: `grpc-api`, `grpc-stub`, `grpc-protobuf`, `grpc-netty-shaded` (Netty is relocated
inside it), `protobuf-java`, `guava` (needed by gRPC), `slf4j-api`. No gRPC or protobuf type is part of
the public API. There is no additional shaded (`-all`) artifact in R1 (PD-120).

```kotlin
dependencies {
    implementation(platform("com.rustegon:rustegon-bom:0.1.0"))
    implementation("com.rustegon:rustegon-driver")
    annotationProcessor("com.rustegon:rustegon-processor")   // optional: generated codecs
}
```

## Quick start

The code below is [`samples/.../Quickstart.java`](samples/src/main/java/io/rustegon/samples/Quickstart.java),
compiled by `./gradlew check` (AC-DRV-002).

A single node started with its defaults speaks plain text (ADR-034), so
`RustegonClient.create("rustegon://admin:<password>@localhost:7700/<database>")` is enough. A node
with `security.tls = true` (every cluster node) needs its CA:
`rustegon://admin:<password>@localhost:7700/<database>?tls=true&tlsCaFile=ca.crt`, or in code:

```java
RustegonClientSettings settings = RustegonClientSettings.builder()
        .endpoints("127.0.0.1:7700")
        .credential(RustegonCredential.scram("app_user", password))      // char[]
        .tls(TlsSettings.builder().caCertificate(Path.of("ca.crt")).build())  // omit: plain text
        .defaultDatabase("shop")
        .build();
try (RustegonClient client = RustegonClient.create(settings)) {
    RustegonCollection<Order> orders = client.database("shop").collection("orders", Order.class);
    orders.insertOne(new Order("o-1", null, "paid", new BigDecimal("120.00"), Instant.now()));
    try (Cursor<Order> c = orders.find(Filters.eq(Order_.status, "paid"))
            .sort(Sorts.desc(Order_.createdAt)).limit(50).cursor()) {
        for (Order o : c) { … }
    }
    long updated = client.withTransaction(txn -> txn.collection("shop.orders", Order.class)
            .updateOne(Filters.id("o-1"), Updates.set(Order_.status, "shipped")).modifiedCount());
}
```

## JPMS

The driver is a named module; gRPC, protobuf and guava are automatic modules. A mapped type's package
must be exported to `io.rustegon.driver` (generated codecs) or opened to it (run-time `MethodHandles`
mapper), PD-113:

```java
module com.example.app {
    requires io.rustegon.driver;
    exports com.example.app.model to io.rustegon.driver;
}
```

`grpc-netty-shaded` is resolved on the module path without `--add-modules`. On JDK 24 and later Netty
loads a native library: run with `--enable-native-access=io.grpc.netty.shaded` (module path) or
`--enable-native-access=ALL-UNNAMED` (class path) to silence the JDK warning. The module setup is
checked by `samples` (`jpmsSmoke`, `jpmsSmokeJdk25`; TC-DRV-JAVA-026).

## Robustness notes

- A node that goes away is reported as `UnavailableException` (RGN-3002, retryable); the same client
  reconnects and logs in again when the node is back (TC-DRV-JAVA-030).
- A `commit()` that fails in transport after it was sent has an unknown outcome: it throws
  `CommitOutcomeUnknownException` (RGN-2006), never a plain retryable error, and `withTransaction` resolves
  it with `Status` instead of re-running the callback (PD-122). A node that restarted no longer knows the
  transaction: `resolve()` then fails with RGN-1030 (PD-121).

## Build, test, publish

```bash
cd drivers/java
./gradlew clean check                 # JDK 21 `test`, JDK 25 `testJdk25`, javadoc -Xdoclint:all, samples + JPMS smoke
./gradlew validateCentralBundle       # publish into build/repo and check it against Maven Central's rules (TC-DRV-JAVA-027)
scripts/verify-reproducible.sh        # two clean -Preproducible builds, byte-identical jars (TC-DRV-JAVA-028)
```

Integration tests start `rustegond` from `RUSTEGON_BIN_DIR` (default `<repo>/target/debug`, PD-072;
`cargo build -p rustegond -p rustegon-cli`); see [`TESTS.md`](TESTS.md).

Publishing uses the core `maven-publish` and `signing` plugins. Artifacts are signed only when a key is
configured, never otherwise:

| Key source | Properties |
|---|---|
| in memory (CI) | `ORG_GRADLE_PROJECT_signingKey` (ASCII-armoured secret key), `ORG_GRADLE_PROJECT_signingKeyId`, `ORG_GRADLE_PROJECT_signingPassword` |
| gpg agent | `-Psigning.gnupg.keyName=<key id>` (and `signing.gnupg.executable` if not `gpg`) |
| keyring file | `-Psigning.keyId=… -Psigning.password=… -Psigning.secretKeyRingFile=…` |

`./gradlew -Prustegon.release validateCentralBundle` additionally requires signatures and a non-SNAPSHOT
version, as Central does. The upload to Central (Central Portal bundle) is not automated yet.
