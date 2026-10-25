#!/bin/sh
adb reverse tcp:8443 tcp:8443
cd android || exit 1
gradle --no-daemon :app:connectedDebugAndroidTest "-Pandroid.testInstrumentationRunnerArguments.adminToken=$GHOST_ADMIN_TOKEN" --stacktrace > "${RUNNER_TEMP:-/tmp}/device.log" 2>&1
code=$?
echo "gradle exit code: $code"
if [ $code -ne 0 ]; then python3 "$GITHUB_WORKSPACE/.github/scripts/explain_failure.py" "${RUNNER_TEMP:-/tmp}/device.log"; fi
exit $code
