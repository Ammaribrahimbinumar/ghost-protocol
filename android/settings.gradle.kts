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
        // libsignal is published to Signal's own repository (Maven Central has only old builds).
        // Restricted to the org.signal group so no other dependency can be served from it.
        maven {
            url = uri("https://build-artifacts.signal.org/libraries/maven/")
            content { includeGroup("org.signal") }
        }
    }
}
rootProject.name = "GhostProtocol"
include(":app")
include(":core-crypto")
