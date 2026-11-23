# iOS integrity detection

MobShield integrity detection (`MobShieldDetectIntegrity`) validates the code signature and Team ID, bundle identity, provisioning metadata, distribution channel, binary encryption, anchored resources, and the App Store app transaction. Signals map to `APP_INTEGRITY` threat events.

## Signals

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|--------------------|
| `ios.integrity.sec_code` | Certificates in `embedded.mobileprovision` vs anchor | 90 | 95 |
| `ios.integrity.team_id` | Team ID and `application-identifier` from the executable's code signature | 90 | 95 |
| `ios.integrity.distribution` | Distribution channel derived from the build vs `allowedDistributions` | 80 | 90 |
| `ios.integrity.encryption` | `LC_ENCRYPTION_INFO_64` of the main executable in store builds | 80 | 85 |
| `ios.integrity.bundle_id` | `Bundle` identifier vs anchor | 85 | 90 |
| `ios.integrity.provisioning` | `embedded.mobileprovision` plist parse | 70 | 80 |
| `ios.integrity.resource` | SHA-256 of anchored bundle files | 80 | 85 |
| `ios.integrity.receipt` | StoreKit 2 `AppTransaction` (iOS 16+), else `appStoreReceiptURL` shape | 55 | 65 |
| `ios.integrity.check_unavailable` | A configured check timed out or could not read its input | 30 | 40 |

`ios.integrity.check_unavailable` scores LOW on its own. One signal is emitted per scan, and its
`checks` evidence lists each `check:reason` pair (for example `resource:timeout`).

App Store and TestFlight builds do not contain `embedded.mobileprovision`. In those builds the
certificate and provisioning checks have nothing to compare and emit no signal; use
`expectedTeamId` and `allowedDistributions`, which cover store builds.

## Re-signing attack model

A repackaged IPA typically changes one or more of:

1. **Code signature** (new certificate digest, team ID, or ad-hoc sign)
2. **Bundle identifier** (different `CFBundleIdentifier`)
3. **Provisioning profile** (enterprise or development profile swapped in)
4. **Resources** (`Info.plist`, storyboards, assets tampered)
5. **App Store receipt** (missing, truncated, or non-PKCS#7 payload on sideload builds)

MobShield compares live runtime values to anchors you set in `MobShieldConfig`.

Attackers who re-sign with their own developer certificate are caught when `expectedSigners` and `expectedPackageId` do not match.

## Configuration

```swift
let config = try MobShieldConfig.make(
    expectedPackageId: "com.example.app",
    expectedResourceHashes: [
        "Info.plist": "<sha256>",
        "Main.storyboardc/Info.plist": "<sha256>",
    ],
    expectedTeamId: "ABCDE12345",
    allowedDistributions: AppDistribution.store
)
await IntegrityDetectionRegistrar.register(config: config)
```

- `expectedTeamId`: Your 10-character Team ID. Enables `ios.integrity.team_id`. Recommended for every build.
- `allowedDistributions`: Channels this build may run from (`appStore`, `testFlight`, `adHoc`, `enterprise`, `development`). Empty skips `ios.integrity.distribution` and `ios.integrity.encryption`. Use `AppDistribution.store` for an App Store release and add `.development` for builds you run from Xcode.
- `expectedSigners`: SHA-256 digests of signing certificates (64 hex chars), for development, ad hoc and enterprise builds. Empty skips `ios.integrity.sec_code`.
- `expectedPackageId`: Optional; when set enables bundle ID and provisioning checks, and the `application-identifier` comparison of the Team ID check.
- `expectedResourceHashes`: Relative paths inside the `.app` bundle. Empty skips resource hashing.

## Checks

### Code signature

Uses Security.framework certificate APIs. On iOS, `SecCodeCopySelf` is not exposed in the mobile SDK, so MobShield reads `DeveloperCertificates` from `embedded.mobileprovision` and computes SHA-256 digests with `SecCertificateCreateWithData`. Any expected digest match is treated as success. Skipped when the build has no embedded profile. A profile that cannot be read is reported as `sec_code:sec_code_unavailable` through `ios.integrity.check_unavailable`.

### Team ID

Reads the code signature of the main executable as loaded in memory (`LC_CODE_SIGNATURE` in
`__LINKEDIT`), and compares the CodeDirectory Team ID to `expectedTeamId`. App Store builds keep the
developer's Team ID after Apple re-signs them. Reasons: `team_id_mismatch`, `team_id_missing`
(ad hoc signature), `signature_missing`, and `app_id_mismatch` when the signed
`application-identifier` does not end in `expectedPackageId`. Skipped on the Simulator.

### Distribution

Derives the channel: a build with an embedded profile is `enterprise` (`ProvisionsAllDevices`),
`development` (`get-task-allow`) or `adHoc`; a build without one is `testFlight` (sandbox receipt)
or `appStore`. Reports `distribution_not_allowed` when the channel is not in
`allowedDistributions`, and `get_task_allow` when the signed entitlements allow debugging but
`.development` is not allowed. Skipped on the Simulator.

### Binary encryption

When `allowedDistributions` contains only store channels and the build has no embedded profile,
checks that `LC_ENCRYPTION_INFO_64` of the main executable is present with a non-zero `cryptid`.
Skipped on the Simulator and for iOS apps running on a Mac.

### Bundle identifier

Compares `Bundle.main.bundleIdentifier` to `expectedPackageId`.

### Embedded provisioning profile

Reads `embedded.mobileprovision`, extracts the XML plist, and compares `application-identifier` to `TEAMID.expectedPackageId`. A missing profile emits no signal: App Store and TestFlight builds, and Simulator builds, do not have one. A profile that cannot be read or parsed is reported through `ios.integrity.check_unavailable`.

### Resource integrity

Hashes files at anchored paths with SHA-256 (CryptoKit). A file that cannot be read is reported through `ios.integrity.check_unavailable`; a missing file is reported as `ios.integrity.resource`. Record digests for `Info.plist` and the main storyboard (`UIMainStoryboardFile`) for your build and pass them in `MobShieldConfig`; the personalize build phase does not record them.

### App Store verification

Runs only for builds without an embedded profile, outside the Simulator. On iOS 16+ it reads
StoreKit 2 `AppTransaction.shared` and reports `app_transaction_unverified` when StoreKit cannot
verify its signature, or `app_transaction_bundle_mismatch` when its bundle ID differs from the
app's. When StoreKit cannot provide the transaction, for example offline, the check is reported
through `ios.integrity.check_unavailable`. Before iOS 16 it checks the shape of the receipt at
`appStoreReceiptURL`: readability, minimum size, and ASN.1 SEQUENCE prefix (`0x30`).

## Timeouts

Each check runs off the calling task with a timeout: `scanTimeoutMs` (default 500 ms) for most
checks and `digestTimeoutMs` (default 5 s) for resource hashing and App Store verification. A check that does not finish in
time is reported as `check:timeout` through `ios.integrity.check_unavailable`, and the scan does not
wait for it.

## Bypass notes

| Check | Limitation |
|-------|------------|
| `ios.integrity.sec_code` | Attacker with a stolen enterprise cert matching allowlist |
| `ios.integrity.resource` | Runtime file patching after launch without changing on-disk hash before scan |
| `ios.integrity.receipt` | Verifies on device; does not replace server-side verification of the transaction |
| All client checks | Skilled attackers can patch MobShield itself |

## Registration

```swift
await IntegrityDetectionRegistrar.register(config: mobShieldConfig)
```

Module name: `integrity`. Module criticality: `100`.
