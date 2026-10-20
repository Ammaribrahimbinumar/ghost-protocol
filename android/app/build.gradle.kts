plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.ghostprotocol.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.ghostprotocol.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-phase1"
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
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
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

    // Phase 2 (not yet integrated): org.signal:libsignal-android  (AGPL-3.0, see docs/ARCHITECTURE.md)
    // Phase 4 (not yet integrated): net.zetetic:sqlcipher-android + androidx.room

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
