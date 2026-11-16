// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// Java driver build (java-driver.md §1, DEC-020: baseline JDK 21, tested on 21 and 25).
plugins {
    // Provisions the JDK 21 / 25 toolchains when they are not installed locally.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "rustegon-java"

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

// Artifacts: `driver` = com.rustegon:rustegon-driver, `processor` = com.rustegon:rustegon-processor
// (annotation processor, java-driver.md §5), `bom` = com.rustegon:rustegon-bom; `samples`
// (README samples and the JPMS smoke test, not published).
include("driver", "processor", "bom", "samples")
