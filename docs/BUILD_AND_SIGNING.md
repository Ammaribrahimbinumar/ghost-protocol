# Build, test, sign, install

**None of the Android steps below have been executed.** They are written for a machine with network access.

## Prerequisites
JDK 17, Android SDK (platform 35, build-tools), Gradle 8.9+ or Android Studio, network access to Google Maven and Maven Central.

## 0. Before first build
1. Update every version in `android/gradle/libs.versions.toml` to the current stable release; read changelogs and security advisories; record them in `DEPENDENCIES.md`.
2. Generate the wrapper: `cd android && gradle wrapper --gradle-version <version compatible with your AGP>`.

## 1. Unit tests (no device needed)
```
cd android
./gradlew testDebugUnitTest
```
Expect the evaluator, unlock-verifier, controller, input-buffer and risk-check tests to run. Record real results in `FEATURE_REPORT.md`; if any fail, fix the code, not the test.

## 2. Create a signing key (once, keep offline)
```
keytool -genkeypair -v -keystore ghost-release.jks -alias ghost \
  -keyalg RSA -keysize 4096 -validity 10000
```
Store the keystore and passwords outside the repository, with a backup: losing the key means invited users must uninstall and reinstall (and lose local data) to receive updates.

## 3. Build a signed release APK
Put secrets in `~/.gradle/gradle.properties` (never in the repo):
```
GHOST_KEYSTORE=/secure/path/ghost-release.jks
GHOST_KEYSTORE_PASSWORD=...
GHOST_KEY_ALIAS=ghost
GHOST_KEY_PASSWORD=...
```
```
./gradlew assembleRelease
apksigner verify --verbose --print-certs app/build/outputs/apk/release/app-release.apk
sha256sum app/build/outputs/apk/release/app-release.apk
```
Send the APK and publish its SHA-256 and the signing-certificate fingerprint through a **different channel** than the APK itself, so invitees can detect a swapped file.

## 4. Install
Enable "install unknown apps" for the file manager or browser used, then `adb install app-release.apk` or open the file. Because the app is sideloaded, Android shows no store provenance; invitees must check the hash.

## 5. Relay
```
cd relay
go vet ./... && go test -race -count=1 ./...
go build -o ghost-relay .
export GHOST_ADMIN_TOKEN="$(head -c 32 /dev/urandom | base64)"   # >= 32 chars
./ghost-relay -addr :8443 -tls-cert fullchain.pem -tls-key privkey.pem -data /var/lib/ghost/accounts.json
```
Create an invite:
```
curl -X POST https://relay.example/v1/admin/invites -H "Authorization: Bearer $GHOST_ADMIN_TOKEN"
```
Deployment notes: run as an unprivileged user; put the data directory on an encrypted volume; if a reverse proxy sits in front, **turn its access logs off** (they would record client IPs and request paths containing usernames and mailbox IDs) and make sure it forwards no client IP header the relay would trust (the relay uses the socket address); use a certificate from a public CA; monitor disk and memory; keep the OS patched. `-insecure-dev` is for loopback development only.
