plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Pure-JVM module so the protocol logic is unit-tested on CI with the desktop libsignal build.
// The Android app will depend on this module but swap libsignal-client for libsignal-android
// (the AAR with Android native libraries) -- wired up when the app integrates messaging.
kotlin { jvmToolchain(17) }

dependencies {
    api(libs.libsignal.client)
    testImplementation(libs.junit)
}
