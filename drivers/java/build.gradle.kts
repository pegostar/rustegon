// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// Shared coordinates; the projects configure themselves (driver/, processor/, bom/, samples/).
allprojects {
    group = "com.rustegon"
    version = "0.1.0"
}

// --- Publishing (java-driver.md §1, AC-DRV-002) ---------------------------------------------
// Core plugins only (`maven-publish`, `signing`). Each published project applies
// `maven-publish` and declares its publication with its POM name and description; the rest of
// the POM metadata Maven Central requires, the local verification repository and the optional
// signing are added here. `./gradlew validateCentralBundle` publishes into build/repo and
// checks the result against Central's rules (TC-DRV-JAVA-027).
val localRepo: Provider<Directory> = layout.buildDirectory.dir("repo")

// Signing is wired but optional: artifacts are signed only when a key is configured, in memory
// (ORG_GRADLE_PROJECT_signingKey [+ signingKeyId, signingPassword], for CI), through the gpg
// agent (-Psigning.gnupg.keyName=…) or from a keyring file (-Psigning.keyId=… with
// signing.secretKeyRingFile/signing.password). Without a key nothing is signed.
val signingKey: String? = providers.gradleProperty("signingKey").orNull
val gpgKeyName: String? = providers.gradleProperty("signing.gnupg.keyName").orNull
val signingEnabled: Boolean = signingKey != null || gpgKeyName != null ||
    providers.gradleProperty("signing.keyId").isPresent
extra["signingEnabled"] = signingEnabled

subprojects {
    plugins.withId("maven-publish") {
        apply(plugin = "signing")
        configure<PublishingExtension> {
            repositories {
                maven {
                    name = "local"
                    url = uri(localRepo)
                }
            }
            publications.withType<MavenPublication>().configureEach {
                pom {
                    url = "https://github.com/pegostar/rustegon"
                    inceptionYear = "2026"
                    licenses {
                        license {
                            name = "Apache-2.0"
                            url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                            distribution = "repo"
                        }
                    }
                    developers {
                        developer {
                            id = "pegostar"
                            name = "Davide Pegoraro"
                            url = "https://github.com/pegostar"
                        }
                    }
                    scm {
                        url = "https://github.com/pegostar/rustegon"
                        connection = "scm:git:https://github.com/pegostar/rustegon.git"
                        developerConnection = "scm:git:ssh://git@github.com/pegostar/rustegon.git"
                    }
                }
            }
        }
        configure<SigningExtension> {
            when {
                signingKey != null -> useInMemoryPgpKeys(
                    providers.gradleProperty("signingKeyId").orNull, signingKey,
                    providers.gradleProperty("signingPassword").orNull,
                )
                gpgKeyName != null -> useGpgCmd()
            }
            if (signingEnabled) {
                sign(the<PublishingExtension>().publications)
            }
        }
    }

    // Reproducible archives (java-driver.md §1, `-Preproducible`, TC-DRV-JAVA-028): no file
    // timestamps, a fixed entry order and fixed permissions in every jar, no generation date in
    // the javadoc pages. The manifests hold fixed attributes only (no build time, JDK or user).
    // scripts/verify-reproducible.sh builds twice from clean and compares the jars.
    if (providers.gradleProperty("reproducible").isPresent) {
        tasks.withType<AbstractArchiveTask>().configureEach {
            isPreserveFileTimestamps = false
            isReproducibleFileOrder = true
            filePermissions { unix("rw-r--r--") }
            dirPermissions { unix("rwxr-xr-x") }
        }
        tasks.withType<Javadoc>().configureEach {
            (options as StandardJavadocDocletOptions).noTimestamp(true)
        }
    }
}

// Publishes into an emptied build/repo, so that each module directory holds exactly one set of
// files (snapshot file names carry a timestamp).
val cleanLocalRepo = tasks.register<Delete>("cleanLocalRepo") {
    delete(localRepo)
}
val publishToLocalRepo = tasks.register("publishToLocalRepo") {
    description = "Publishes every artifact into an emptied build/repo."
    group = PublishingPlugin.PUBLISH_TASK_GROUP
    dependsOn(cleanLocalRepo)
}
subprojects {
    plugins.withId("maven-publish") {
        val publish = tasks.named("publishAllPublicationsToLocalRepository")
        publish.configure { mustRunAfter(cleanLocalRepo) }
        publishToLocalRepo.configure { dependsOn(publish) }
    }
}

apply(from = "gradle/central-validation.gradle.kts")
