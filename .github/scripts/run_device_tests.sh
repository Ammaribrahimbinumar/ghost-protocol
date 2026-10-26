#!/bin/sh
adb reverse tcp:8443 tcp:8443
cd android || exit 1
LOG="${RUNNER_TEMP:-/tmp}/device.log"
gradle --no-daemon :app:connectedDebugAndroidTest "-Pandroid.testInstrumentationRunnerArguments.adminToken=$GHOST_ADMIN_TOKEN" --stacktrace > "$LOG" 2>&1
code=$?
echo "debug gradle exit code: $code"
if [ $code -ne 0 ]; then python3 "$GITHUB_WORKSPACE/.github/scripts/explain_failure.py" "$LOG"; exit $code; fi

# Second pass: the minified (R8) release build, signed with a THROWAWAY key made just now. Non-UI tests only
# (Compose test hooks and the loopback exception exist in debug builds only). Proves R8 did not break libsignal,
# Keystore use or the JSON/gson code paths.
KS="${RUNNER_TEMP:-/tmp}/throwaway.jks"
keytool -genkeypair -keystore "$KS" -storepass throwaway-ci -keypass throwaway-ci -alias ci -keyalg RSA -keysize 2048 -validity 2 -dname "CN=ci-throwaway" >/dev/null 2>&1
gradle --no-daemon :app:connectedReleaseAndroidTest -PghostTestBuildType=release \
  "-PGHOST_KEYSTORE=$KS" -PGHOST_KEYSTORE_PASSWORD=throwaway-ci -PGHOST_KEY_ALIAS=ci -PGHOST_KEY_PASSWORD=throwaway-ci \
  "-Pandroid.testInstrumentationRunnerArguments.class=com.ghostprotocol.app.DeviceTest,com.ghostprotocol.app.DeviceVaultTest" \
  --stacktrace > "$LOG.release" 2>&1
code=$?
echo "release gradle exit code: $code"
if [ $code -ne 0 ]; then python3 "$GITHUB_WORKSPACE/.github/scripts/explain_failure.py" "$LOG.release"; fi
exit $code
