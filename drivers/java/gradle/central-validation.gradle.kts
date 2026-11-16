// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// TC-DRV-JAVA-027 (AC-DRV-002, java-driver.md §1): the published artifact set, checked in
// build/repo against the rules of the Maven Central publisher validation (POM metadata,
// sources and javadoc jars, checksums, signatures, resolvable dependency versions, no SNAPSHOT
// in a release) plus the shading contract of the driver: its jar holds only Rustegon classes
// and its runtime dependencies are exactly the allowed set (Netty only through
// grpc-netty-shaded). Applied from the root build script.
//
// Signatures: checked whenever signing is enabled; required with -Prustegon.release (as is a
// non-SNAPSHOT version). Without a key the report says so: nothing is faked.

import java.security.MessageDigest
import java.util.zip.ZipFile
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

/** Published modules and their packaging. */
val expectedModules = mapOf(
    "rustegon-driver" to "jar",
    "rustegon-processor" to "jar",
    "rustegon-bom" to "pom",
)

/** The driver's runtime dependencies (java-driver.md §1; gRPC needs guava and its own API jars). */
val allowedDriverDependencies = setOf(
    "io.grpc:grpc-api", "io.grpc:grpc-netty-shaded", "io.grpc:grpc-protobuf", "io.grpc:grpc-stub",
    "com.google.protobuf:protobuf-java", "org.slf4j:slf4j-api", "com.google.guava:guava",
)

val repoDir = layout.buildDirectory.dir("repo")
val releaseBuild = providers.gradleProperty("rustegon.release").isPresent
val signed = extra["signingEnabled"] as Boolean

tasks.register("validateCentralBundle") {
    description = "Publishes into build/repo and checks the bundle against Maven Central's rules (TC-DRV-JAVA-027)."
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    dependsOn("publishToLocalRepo")
    val repo = repoDir
    val version = project.version.toString()
    val release = releaseBuild
    val signingOn = signed
    val modules = expectedModules
    val allowed = allowedDriverDependencies
    doLast {
        val problems = mutableListOf<String>()
        val notes = mutableListOf<String>()
        if (version.endsWith("-SNAPSHOT")) {
            if (release) problems += "version $version is a SNAPSHOT: Central accepts releases only"
            else notes += "version $version is a SNAPSHOT (release rule enforced with -Prustegon.release)"
        }
        if (!signingOn) {
            if (release) problems += "no signing key configured: Central requires a .asc for every file"
            else notes += "not signed: no signing key configured (required with -Prustegon.release)"
        }
        for ((artifact, packaging) in modules) {
            val dir = repo.get().dir("io/rustegon/$artifact/$version").asFile
            val poms = dir.listFiles { f -> f.name.endsWith(".pom") }.orEmpty()
            if (poms.size != 1) {
                problems += "$artifact: expected one POM in $dir, found ${poms.size}"
                continue
            }
            val base = poms[0].name.removeSuffix(".pom")
            val pom = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(poms[0])
                .documentElement
            fun text(parent: Element, tag: String): String? =
                (0 until parent.childNodes.length).map { parent.childNodes.item(it) }
                    .filterIsInstance<Element>().firstOrNull { it.tagName == tag }
                    ?.textContent?.trim()?.takeIf { it.isNotEmpty() }
            fun child(parent: Element, vararg path: String): Element? = path.fold(parent as Element?) { e, tag ->
                e?.let { p -> (0 until p.childNodes.length).map { p.childNodes.item(it) }
                    .filterIsInstance<Element>().firstOrNull { it.tagName == tag } }
            }
            // Coordinates and the metadata Central requires.
            if (text(pom, "groupId") != "io.rustegon") problems += "$artifact: groupId is not io.rustegon"
            if (text(pom, "artifactId") != artifact) problems += "$artifact: artifactId is ${text(pom, "artifactId")}"
            if (text(pom, "version") != version) problems += "$artifact: version is ${text(pom, "version")}"
            if ((text(pom, "packaging") ?: "jar") != packaging) problems += "$artifact: packaging is not $packaging"
            for (tag in listOf("name", "description", "url")) {
                if (text(pom, tag) == null) problems += "$artifact: <$tag> missing"
            }
            val license = child(pom, "licenses", "license")
            if (license == null || text(license, "name") == null || text(license, "url") == null) {
                problems += "$artifact: <licenses><license> with name and url missing"
            }
            val developer = child(pom, "developers", "developer")
            if (developer == null || text(developer, "name") == null) {
                problems += "$artifact: <developers><developer> with a name missing"
            }
            val scm = child(pom, "scm")
            if (scm == null || text(scm, "url") == null || text(scm, "connection") == null) {
                problems += "$artifact: <scm> with url and connection missing"
            }
            // Every dependency must be resolvable from Central: explicit version, no system scope.
            val deps = pom.getElementsByTagName("dependency")
            val runtimeDeps = mutableSetOf<String>()
            for (i in 0 until deps.length) {
                val d = deps.item(i) as Element
                val coords = "${text(d, "groupId")}:${text(d, "artifactId")}"
                val v = text(d, "version")
                if (v == null || v.contains("\${")) problems += "$artifact: dependency $coords has no concrete version"
                if (text(d, "scope") == "system") problems += "$artifact: dependency $coords has system scope"
                if (v != null && v.endsWith("-SNAPSHOT") && !coords.startsWith("io.rustegon:")) {
                    problems += "$artifact: dependency $coords is a SNAPSHOT"
                }
                // Direct dependencies (not dependencyManagement): what a consumer resolves.
                if ((d.parentNode.parentNode as Element).tagName == "project" && text(d, "scope") != "test") {
                    runtimeDeps += coords
                }
            }
            // Files: main artifact, sources and javadoc (jar packaging), each with checksums
            // (and signatures when signing is on).
            val required = mutableListOf("$base.pom")
            if (packaging == "jar") required += listOf("$base.jar", "$base-sources.jar", "$base-javadoc.jar")
            val artifacts = dir.listFiles().orEmpty().filter { f ->
                listOf(".md5", ".sha1", ".sha256", ".sha512", ".asc").none { f.name.endsWith(it) } &&
                    !f.name.startsWith("maven-metadata")
            }
            for (name in required) {
                if (artifacts.none { it.name == name }) problems += "$artifact: $name missing"
            }
            for (f in artifacts) {
                for ((ext, algorithm) in listOf("md5" to "MD5", "sha1" to "SHA-1")) {
                    val sum = File(f.path + ".$ext")
                    val expected = MessageDigest.getInstance(algorithm).digest(f.readBytes())
                        .joinToString("") { "%02x".format(it) }
                    if (!sum.isFile) problems += "$artifact: ${sum.name} missing"
                    else if (sum.readText().trim().substringBefore(' ') != expected) problems += "$artifact: ${sum.name} does not match"
                }
                if (signingOn && !File(f.path + ".asc").isFile) problems += "$artifact: ${f.name}.asc missing"
            }
            // Gradle module metadata must not expose the build-only test fixtures.
            artifacts.filter { it.name.endsWith(".module") }.forEach {
                if (it.readText().contains("testFixtures", ignoreCase = true)) {
                    problems += "$artifact: ${it.name} publishes test fixtures"
                }
            }
            if (packaging == "jar") {
                fun entries(name: String): List<String> = File(dir, name).takeIf { it.isFile }
                    ?.let { f -> ZipFile(f).use { z -> z.entries().toList().map { it.name } } }.orEmpty()
                if (entries("$base-sources.jar").none { it.endsWith(".java") }) problems += "$artifact: sources jar has no .java file"
                if ("index.html" !in entries("$base-javadoc.jar")) problems += "$artifact: javadoc jar has no index.html"
                val classes = entries("$base.jar")
                if (classes.none { it.endsWith(".class") }) problems += "$artifact: jar has no classes"
                if (artifact == "rustegon-driver") {
                    // Shading contract (TC-DRV-JAVA-027): no bundled third-party classes, Netty
                    // only inside grpc-netty-shaded, a JPMS descriptor (io.rustegon.driver).
                    if ("module-info.class" !in classes) problems += "$artifact: module-info.class missing"
                    classes.filter { !it.endsWith("/") && !it.startsWith("io/rustegon/") && !it.startsWith("META-INF/") && it != "module-info.class" }
                        .forEach { problems += "$artifact: foreign entry $it in the jar" }
                    if (runtimeDeps != allowed) {
                        problems += "$artifact: runtime dependencies $runtimeDeps differ from the allowed set $allowed"
                    }
                }
            }
            logger.lifecycle("validateCentralBundle: $artifact ($packaging) ${artifacts.size} files checked in ${dir.relativeTo(repo.get().asFile)}")
        }
        notes.forEach { logger.lifecycle("validateCentralBundle: note: $it") }
        if (problems.isNotEmpty()) {
            throw GradleException("Maven Central validation failed:\n  " + problems.joinToString("\n  "))
        }
        logger.lifecycle("validateCentralBundle: OK (${modules.size} modules)")
    }
}
