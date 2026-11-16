// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// io.rustegon:rustegon-bom (java-driver.md §1). Placeholder until the optional modules
// (Jackson, reactive, OpenTelemetry) exist; it already pins the core driver.
plugins {
    `java-platform`
    `maven-publish`
}

description = "Bill of materials aligning the versions of the Rustegon Java artifacts."

dependencies {
    constraints {
        api(project(":driver"))
        api(project(":processor"))
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "rustegon-bom"
            from(components["javaPlatform"])
            pom {
                name = "Rustegon Java BOM"
                description = project.description
            }
        }
    }
}
