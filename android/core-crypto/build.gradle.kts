plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Pure-JVM module so the protocol logic is unit-tested on CI with the desktop libsignal build.
// The Android app will depend on this module but swap libsignal-client for libsignal-android
// (the AAR with Android native libraries) -- wired up when the app integrates messaging.
kotlin { jvmToolchain(21) }

dependencies {
    api(libs.libsignal.client)
    implementation(libs.gson)
    // org.json ships with Android; on the JVM it is needed only for tests.
    compileOnly(libs.org.json)
    testImplementation(libs.org.json)
    testImplementation(libs.junit)
}
