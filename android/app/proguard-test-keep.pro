# Used ONLY when CI runs instrumented tests against the minified build (-PghostTestBuildType=release).
# The tests call app classes that production code never references, so R8 would otherwise strip them.
# Libraries (libsignal, gson, kotlin, androidx) are still shrunk exactly as in a real release.
-keep class com.ghostprotocol.app.** { *; }
-keep class androidx.tracing.** { *; }
-keep class androidx.test.** { *; }
-dontwarn androidx.test.**
