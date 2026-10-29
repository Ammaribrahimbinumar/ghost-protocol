import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

android {
    namespace = "com.ghostprotocol.app"
    // CI can run the non-UI instrumented tests against the minified release build: -PghostTestBuildType=release
    testBuildType = providers.gradleProperty("ghostTestBuildType").getOrElse("debug")
    compileSdk = 35

    defaultConfig {
        applicationId = "com.ghostprotocol.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-phase1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Optional: -PghostAbis=arm64-v8a builds a much smaller APK for real phones.
        providers.gradleProperty("ghostAbis").orNull?.let { abis ->
            ndk { abiFilters += abis.split(",").map { it.trim() }.filter { it.isNotEmpty() } }
        }
    }

    // Signing material is supplied from the environment / a local, untracked
    // gradle.properties. Nothing secret is stored in this repository.
    signingConfigs {
        create("release") {
            val ks = providers.gradleProperty("GHOST_KEYSTORE").orNull
            if (ks != null) {
                storeFile = file(ks)
                storePassword = providers.gradleProperty("GHOST_KEYSTORE_PASSWORD").orNull
                keyAlias = providers.gradleProperty("GHOST_KEY_ALIAS").orNull
                keyPassword = providers.gradleProperty("GHOST_KEY_PASSWORD").orNull
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (providers.gradleProperty("ghostTestBuildType").orNull == "release") proguardFile("proguard-test-keep.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true }

    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.kotlinx.coroutines.android)

    // Protocol core. libsignal-client (desktop JVM natives) is excluded; libsignal-android carries the
    // Android native libraries instead. AGPL-3.0, see docs/ARCHITECTURE.md.
    implementation(project(":core-crypto")) { exclude(group = "org.signal", module = "libsignal-client") }
    implementation(libs.libsignal.android)
    coreLibraryDesugaring(libs.desugar)
    // Phase 4 (not yet integrated): net.zetetic:sqlcipher-android + androidx.room

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
