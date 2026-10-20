# Dependency and licensing inventory

Status (updated): versions below the first table resolved and built in CI; libsignal 0.105.1 verified as the latest in Signal's repository by a CI discovery run. Resolving is NOT a security review: advisories and changelogs still need reading before release. Original note: versions were unverified. The authoring environment could not reach Maven Central or Google Maven, so none of the Android versions were resolved or checked for advisories. Fill in the "Verified version / date / advisories checked" columns on a networked machine before building.

## Relay (Go)
| Dependency | License | Notes |
|---|---|---|
| Go standard library only (Go 1.24) | BSD-3-Clause | No third-party modules. `go.mod` has no `require` lines |

## Android — in the project today (placeholders)
| Dependency | Placeholder version | License | Verified version / advisories |
|---|---|---|---|
| Android Gradle Plugin | 8.7.3 | Apache-2.0 | TODO |
| Kotlin (+ Compose compiler plugin) | 2.2.20 (required: libsignal metadata is Kotlin 2.2) | Apache-2.0 | TODO |
| Compose BOM / UI / Foundation / Material3 | 2024.12.01 | Apache-2.0 | TODO |
| androidx.activity:activity-compose | 1.9.3 | Apache-2.0 | TODO |
| androidx.lifecycle:lifecycle-runtime-compose | 2.8.7 | Apache-2.0 | TODO |
| kotlinx-coroutines (android, test) | 1.9.0 | Apache-2.0 | TODO |
| JUnit | 4.13.2 | EPL-1.0 | TODO |

## Android — planned, not yet integrated
| Dependency | License | What was checked this session |
|---|---|---|
| `org.signal:libsignal-client` (JVM, used by `core-crypto`) and `libsignal-android` (planned for the app) | **AGPL-3.0** | **Pinned 0.105.1** (latest in `build-artifacts.signal.org/libraries/maven/` per CI run 39323710575; Maven Central's 0.86.5 is stale). Requires JDK 21 for the JVM artifact. README: "Use outside of Signal is unsupported". Project decision: release Ghost_Protocol under AGPL-3.0 with public source |
| `net.zetetic:sqlcipher-android` | BSD-style (Community Edition) | SQLCipher 4.18.0 release notes (Aug 2026) mention Room 3 support. The Android package version to pin: NOT determined |
| AndroidX Room | Apache-2.0 | Not yet chosen |

Licensing consequence: linking an AGPL-3.0 library means Ghost_Protocol must be offered to its users under AGPL-3.0-compatible terms, including source. Decide this before distributing the first APK.

Sources: https://github.com/SignalApp/libsignal-client · https://central.sonatype.com/artifact/org.signal/libsignal-android · https://www.zetetic.net/blog/2026/08/18/sqlcipher-4.18.0-release/
