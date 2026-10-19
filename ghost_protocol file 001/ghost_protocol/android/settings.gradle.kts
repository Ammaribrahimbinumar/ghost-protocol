pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // libsignal-android is published to Signal's own repository; Maven Central only
        // carries older builds. Enable and pin after verifying the current version:
        // maven { url = uri("https://build-artifacts.signal.org/libraries/maven/") }
    }
}
rootProject.name = "GhostProtocol"
include(":app")
