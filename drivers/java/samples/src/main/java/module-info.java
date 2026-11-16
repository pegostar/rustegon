// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Samples of the Java driver and its JPMS smoke test (TC-DRV-JAVA-026). The model package is
 * exported to the driver so that it can load the generated codecs (PD-113).
 */
module io.rustegon.samples {
    requires io.rustegon.driver;

    exports io.rustegon.samples.model to io.rustegon.driver;
}
