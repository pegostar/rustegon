// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// com.rustegon:rustegon-driver (java-driver.md, FR-DRV-002, AC-DRV-002).
plugins {
    `java-library`
    `java-test-fixtures`
    alias(libs.plugins.protobuf)
    `maven-publish`
}

base.archivesName = "rustegon-driver"
description = "The official Java driver of the Rustegon document database."

val protobufVersion: String = libs.versions.protobuf.get()
val grpcVersion: String = libs.versions.grpc.get()

/** Repository root (drivers/java/..): protos, error catalog, RDoc fixtures, Rust binaries. */
val repoRoot: File = rootProject.projectDir.parentFile.parentFile

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    // No gRPC or protobuf type appears in the public API: everything is an implementation
    // detail (the stubs live in a non-exported package).
    implementation(libs.grpc.api)
    // Selected at run time by Grpc.newChannelBuilderForAddress (see ChannelPool).
    runtimeOnly(libs.grpc.netty.shaded)
    implementation(libs.grpc.protobuf)
    implementation(libs.grpc.stub)
    implementation(libs.protobuf.java)
    implementation(libs.slf4j.api)
    implementation(libs.guava)

    testFixturesApi(platform(libs.junit.bom))
    testFixturesApi(libs.junit.jupiter)

    // The mapping tests (TC-DRV-JAVA-021…025) compile their model with the annotation processor
    // and run it in-process through javax.tools; nothing of it reaches the runtime classpath.
    testAnnotationProcessor(project(":processor"))
    testImplementation(project(":processor"))

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jqwik)
    testImplementation(libs.zero.allocation.hashing)
    testImplementation(libs.snakeyaml.engine)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.slf4j.simple)
}

// --- Protobuf stubs -------------------------------------------------------------------------
// The protos under <repo>/proto carry no Java options and must not be edited for one driver,
// so they are copied with Java options injected: the generated classes then live in the
// driver's non-exported package io.rustegon.driver.internal.proto, one class per message, and
// each file's outer class is `<File>Proto` (a message may share the file's name, e.g. Document).
val protoSrc = layout.buildDirectory.dir("proto-src")
val prepareProtos = tasks.register<Copy>("prepareProtos") {
    from(repoRoot.resolve("proto")) {
        include("rustegon/v1/*.proto")
    }
    into(protoSrc)
    eachFile {
        val outer = name.removeSuffix(".proto").split('_')
            .joinToString("") { part -> part.replaceFirstChar { it.uppercaseChar() } } + "Proto"
        filter { line ->
            if (line.trim() == "package rustegon.v1;") {
                line + "\n\noption java_package = \"io.rustegon.driver.internal.proto\";" +
                    "\noption java_multiple_files = true;" +
                    "\noption java_outer_classname = \"$outer\";"
            } else {
                line
            }
        }
    }
}

// --- Error table (PD-075) ---------------------------------------------------------------------
// The driver compiles drivers/conformance/generated/ErrorCodes.java (written by the Rust test
// crates/rustegon-common/tests/driver_tables.rs) as is; there is no hand-kept copy, so the
// Java table can never drift from the Rust catalog. The suite lives at <repo>/drivers/conformance; -Prustegon.conformanceDir (or the environment
// variable RUSTEGON_CONFORMANCE_DIR) points the build and the tests at another checkout of it.
val conformanceDir: File = (providers.gradleProperty("rustegon.conformanceDir").orNull
    ?: System.getenv("RUSTEGON_CONFORMANCE_DIR"))?.let { File(it) }
    ?: repoRoot.resolve("drivers/conformance")
val generatedErrorCodes: File = conformanceDir.resolve("generated/ErrorCodes.java")
val errorTableDir = layout.buildDirectory.dir("generated/sources/errors/java")
val prepareErrorCodes = tasks.register<Copy>("prepareErrorCodes") {
    doFirst {
        if (!generatedErrorCodes.isFile) {
            throw GradleException(
                "$generatedErrorCodes not found: the driver compiles the generated error table " +
                    "(PD-075); set -Prustegon.conformanceDir or RUSTEGON_CONFORMANCE_DIR",
            )
        }
    }
    from(generatedErrorCodes)
    into(errorTableDir.map { it.dir("io/rustegon/driver/errors") })
}

sourceSets {
    main {
        proto {
            srcDir(protoSrc)
        }
        java {
            srcDir(files(errorTableDir).builtBy(prepareErrorCodes))
        }
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:$protobufVersion"
    }
    plugins {
        create("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:$grpcVersion"
        }
    }
    generateProtoTasks {
        all().configureEach {
            dependsOn(prepareProtos)
            plugins {
                create("grpc") {
                    // No @javax.annotation.Generated: it needs an extra dependency.
                    option("@generated=omit")
                }
            }
        }
    }
}

tasks.matching { it.name.startsWith("extract") && it.name.endsWith("Proto") }.configureEach {
    dependsOn(prepareProtos)
}
tasks.named("sourcesJar") { dependsOn("generateProto", prepareErrorCodes) }

tasks.named<Jar>("jar") {
    // The protobuf plugin copies the (option-injected) .proto sources into the resources; they
    // are not part of the driver's API and would clash with other jars shipping the protos.
    exclude("**/*.proto")
    manifest {
        attributes("Implementation-Title" to "rustegon-driver", "Implementation-Version" to project.version)
    }
}

// --- Publication (root build.gradle.kts adds the Central POM metadata and signing) -----------
// The test fixtures (the rustegond process fixture) are for this build only: not published.
(components["java"] as AdhocComponentWithVariants).apply {
    withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
    withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
}
publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "rustegon-driver"
            from(components["java"])
            // The POM lists the versions Gradle resolved, not only the declared ones.
            versionMapping { allVariants { fromResolutionResult() } }
            pom {
                name = "Rustegon Java driver"
                description = project.description
            }
        }
    }
}

// --- Compilation and javadoc -----------------------------------------------------------------
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
}

tasks.named<JavaCompile>("compileJava") {
    // Lint and doclint are errors for hand-written code; the generated stubs are exempt.
    options.compilerArgs.addAll(
        listOf(
            // gRPC and protobuf are automatic modules: requiring them is unavoidable.
            "-Xlint:all,-processing,-serial,-requires-automatic",
            "-Werror",
            "-Xdoclint:all/protected",
            "-Xdoclint/package:-io.rustegon.driver.internal.proto",
        ),
    )
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        addBooleanOption("Xdoclint:all", true)
        // Only the exported API is documented; the hand-written internal classes are
        // doclint-checked by javac (-Xdoclint:all/protected), the generated stubs not at all.
        addBooleanOption("Xdoclint/package:-io.rustegon.driver.internal.*", true)
        addBooleanOption("Werror", true)
    }
    // Only the exported packages are documented. The non-exported sources (hand-written
    // internals and generated stubs) are resolved through the source path instead of being
    // passed as files, because javadoc documents every file it is given.
    exclude("io/rustegon/driver/internal/**")
    val sourceDirs = sourceSets.main.get().java.srcDirs
    (options as StandardJavadocDocletOptions).addStringOption(
        "sourcepath", sourceDirs.joinToString(File.pathSeparator) { it.absolutePath })
}

// --- Tests: JDK 21 (default toolchain) and JDK 25 (AC-DRV-002) --------------------------------
fun Test.configureDriverTests() {
    useJUnitPlatform {
        includeEngines("junit-jupiter", "jqwik")
    }
    systemProperty("rustegon.repoRoot", repoRoot.absolutePath)
    systemProperty("rustegon.conformanceDir", conformanceDir.absolutePath)
    // The integration tests start one rustegond per test JVM; keep one JVM per task.
    maxParallelForks = 1
    // The limit tests build 16 MiB documents.
    maxHeapSize = "1g"
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = false
    }
    // The Rust binaries are an input outside Gradle's knowledge: never reuse a cached result.
    outputs.upToDateWhen { false }
}

// AC-DRV-003: each JDK writes its own conformance-results file (README §6), compared with the
// .NET one and with each other by crates/rustegon-common/tests/driver_results.rs.
tasks.named<Test>("test") {
    configureDriverTests()
    systemProperty("rustegon.conformanceResults",
        layout.buildDirectory.file("conformance-results-jdk21.json").get().asFile.absolutePath)
}

val testJdk25 = tasks.register<Test>("testJdk25") {
    description = "Runs the driver tests on a JDK 25 launcher (DEC-020, AC-DRV-002)."
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    javaLauncher = javaToolchains.launcherFor {
        languageVersion = JavaLanguageVersion.of(25)
    }
    configureDriverTests()
    systemProperty("rustegon.conformanceResults",
        layout.buildDirectory.file("conformance-results-jdk25.json").get().asFile.absolutePath)
    shouldRunAfter(tasks.named("test"))
}

// AC-DRV-002: javadoc with -Xdoclint:all and no warnings is part of the gate.
tasks.named("check") {
    dependsOn(testJdk25, tasks.named("javadoc"))
}
