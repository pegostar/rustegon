// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * The official Java driver of Rustegon (java-driver.md, FR-DRV-002).
 *
 * <p>Entry point: {@link io.rustegon.driver.RustegonClient}. Documents and values use the RDoc
 * codec of {@link io.rustegon.driver.rdoc}. The gRPC stubs and transport helpers live in
 * non-exported packages.
 */
module io.rustegon.driver {
    requires io.grpc;
    requires io.grpc.protobuf;
    requires io.grpc.stub;
    requires com.google.protobuf;
    requires com.google.common;
    requires org.slf4j;

    exports io.rustegon.driver;
    // The error catalog (generated, PD-075): code constants for comparing RustegonException.code().
    exports io.rustegon.driver.errors;
    exports io.rustegon.driver.rdoc;
    // Object mapping (annotations, codecs used by generated code, the MethodHandles mapper).
    exports io.rustegon.driver.mapping;
}
