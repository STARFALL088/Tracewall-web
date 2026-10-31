// Tracewall Desktop root build.
//
// Pure JVM: no Android SDK, no Android Gradle Plugin. Gradle itself runs on
// JDK 17 (pinned in gradle.properties) and compiles with a Java 17 toolchain,
// matching the engine module it was copied from.
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "tracewall-desktop"
