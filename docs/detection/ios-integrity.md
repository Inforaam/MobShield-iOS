# iOS integrity detection

MobShield integrity detection (`MobShieldDetectIntegrity`) validates code signature, bundle identity, provisioning metadata, anchored resources, and App Store receipts. Signals map to `APP_INTEGRITY` threat events.

## Signals

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|--------------------|
| `ios.integrity.sec_code` | Certificates in `embedded.mobileprovision` vs anchor | 90 | 95 |
| `ios.integrity.bundle_id` | `Bundle` identifier vs anchor | 85 | 90 |
| `ios.integrity.provisioning` | `embedded.mobileprovision` plist parse | 70 | 80 |
| `ios.integrity.resource` | SHA-256 of anchored bundle files | 80 | 85 |
| `ios.integrity.receipt` | `appStoreReceiptURL` basic PKCS#7 shape | 55 | 65 |
| `ios.integrity.check_unavailable` | A configured check timed out or could not read its input | 30 | 40 |

`ios.integrity.check_unavailable` scores LOW on its own. One signal is emitted per scan, and its
`checks` evidence lists each `check:reason` pair (for example `resource:timeout`).

App Store and TestFlight builds do not contain `embedded.mobileprovision`. In those builds the code
signature and provisioning checks have nothing to compare and emit no signal.

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
    expectedSigners: ["<sha256-of-signing-cert>"],
    expectedPackageId: "com.example.app",
    expectedResourceHashes: [
        "Info.plist": "<sha256>",
        "Main.storyboardc/Info.plist": "<sha256>",
    ]
)
await IntegrityDetectionRegistrar.register(config: config)
```

- `expectedSigners`: SHA-256 digests of signing certificates (64 hex chars). Empty skips `ios.integrity.sec_code`.
- `expectedPackageId`: Optional; when set enables bundle ID and provisioning checks.
- `expectedResourceHashes`: Relative paths inside the `.app` bundle. Empty skips resource hashing.

## Checks

### Code signature

Uses Security.framework certificate APIs. On iOS, `SecCodeCopySelf` is not exposed in the mobile SDK, so MobShield reads `DeveloperCertificates` from `embedded.mobileprovision` and computes SHA-256 digests with `SecCertificateCreateWithData`. Any expected digest match is treated as success. Skipped when the build has no embedded profile. A profile that cannot be read is reported as `sec_code:sec_code_unavailable` through `ios.integrity.check_unavailable`.

### Bundle identifier

Compares `Bundle.main.bundleIdentifier` to `expectedPackageId`.

### Embedded provisioning profile

Reads `embedded.mobileprovision`, extracts the XML plist, and compares `application-identifier` to `TEAMID.expectedPackageId`. A missing profile emits no signal: App Store and TestFlight builds, and Simulator builds, do not have one. A profile that cannot be read or parsed is reported through `ios.integrity.check_unavailable`.

### Resource integrity

Hashes files at anchored paths with SHA-256 (CryptoKit). A file that cannot be read is reported through `ios.integrity.check_unavailable`; a missing file is reported as `ios.integrity.resource`. Record digests for `Info.plist` and the main storyboard (`UIMainStoryboardFile`) for your build and pass them in `MobShieldConfig`; the personalize build phase does not record them.

### App Store receipt

When `appStoreReceiptURL` is present, verifies readability, minimum size, and ASN.1 SEQUENCE prefix (`div 0x30`). Absent receipts on Simulator or developer builds do not emit a signal.

## Timeouts

Each check runs off the calling task with a timeout: `scanTimeoutMs` (default 500 ms) for most
checks and `digestTimeoutMs` (default 5 s) for resource hashing. A check that does not finish in
time is reported as `check:timeout` through `ios.integrity.check_unavailable`, and the scan does not
wait for it.

## Bypass notes

| Check | Limitation |
|-------|------------|
| `ios.integrity.sec_code` | Attacker with a stolen enterprise cert matching allowlist |
| `ios.integrity.resource` | Runtime file patching after launch without changing on-disk hash before scan |
| `ios.integrity.receipt` | Does not call Apple's online receipt verification |
| All client checks | Skilled attackers can patch MobShield itself |

## Registration

```swift
await IntegrityDetectionRegistrar.register(config: mobShieldConfig)
```

Module name: `integrity`. Module criticality: `100`.
