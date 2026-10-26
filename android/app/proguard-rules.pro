# Release builds strip logging calls so nothing sensitive can reach logcat.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}
-keep class com.ghostprotocol.crypto.** { *; }
# libsignal's native (Rust) code calls back into Java classes and methods BY NAME over JNI. Renaming or removing
# them breaks every session operation at runtime ("JNI error Method not found: loadSession"), which debug builds
# do not show. Found by running the crypto device tests against the minified build in CI.
-keep class org.signal.libsignal.** { *; }
-keepclasseswithmembernames class * { native <methods>; }
