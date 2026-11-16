// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// io.rustegon:rustegon-processor: the @RustegonDocument annotation processor (java-driver.md §5,
// TC-DRV-JAVA-021). Used through `annotationProcessor`, never at run time: it depends on the JDK
// only and leaves the driver's runtime dependencies unchanged. Its tests live in the driver
// (driver/src/test, TC-DRV-JAVA-021…025), which compiles its test model with this processor.
plugins {
    `java-library`
    `maven-publish`
}

base.archivesName = "rustegon-processor"
description = "Annotation processor generating Rustegon codecs and metamodels for records and POJOs."

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "rustegon-processor"
            from(components["java"])
            pom {
                name = "Rustegon annotation processor"
                description = project.description
            }
        }
    }
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror", "-Xdoclint:all/protected"))
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        addBooleanOption("Xdoclint:all", true)
        addBooleanOption("Werror", true)
    }
}

tasks.named("check") {
    dependsOn(tasks.named("javadoc"))
}
