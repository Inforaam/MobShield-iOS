# Verifying reports on your server

MobShield's report tells your backend what the app saw on the device. This page covers how to make
that report something a server can check, what the server must verify, and what a verified report
still cannot tell you.

## Why the HMAC-signed report is deprecated

`MobShield.shared.currentSignedReport(key:)` signs the report with HMAC-SHA256 under a key the app
supplies. That key has to ship inside the app, so anyone who can unpack or hook the app has it and can
sign a clean report for any device. The report also had no server challenge, and its timestamp comes
from the client, so a clean report captured once could be sent again forever. The signature only
showed that the report was not changed in transit.

`currentSignedReport(key:)` and `MobShieldReporter.sign(_:key:)` still work but are deprecated. Use
App Attest as described below.

## The flow

**Challenges.** For every request below, your server issues a challenge: 16 to 128 random bytes (32
is a good size) from a secure random generator, stored server-side with a short expiry (a minute or
two) and bound to the session or user that asked for it. A challenge is accepted **once**: delete it
as soon as it is answered, and reject anything that answers a challenge that is unknown, expired,
already used, or issued to a different session. Ignore the report's `generatedAtMs` for freshness:
the client sets it.

**Once per install: register an App Attest key.**

```swift
let attester = MobShieldAppAttest()
guard attester.isSupported else { /* Simulator or unsupported device: see below */ return }

if !(await attester.hasAttestedKey) {
    let challenge = try await api.fetchChallenge()
    let attestation = try await attester.attestKey(challenge: challenge)
    try await api.registerKey(attestation.keyId, attestation.attestationObject)
}
```

**Each report: send an assertion.**

```swift
let challenge = try await api.fetchChallenge()
let report = try await MobShield.shared.currentAttestedReport(challenge: challenge, attester: attester)
try await api.sendReport(report.json, report.keyId, report.assertion)
```

`MobShieldAppAttest` keeps the key identifier in the Keychain (this device only). If App Attest
returns `DCError.invalidKey`, or your server no longer recognises the key, call `resetKey()` and
register again. App Attest is not available in the Simulator or in some app extensions; there
`isSupported` is false and the calls throw `MobShieldReportError.unsupported`. Decide on the server
how to treat clients that cannot attest, rather than trusting an unattested report.

## What the server verifies

Follow Apple's
[Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).
In MobShield's terms:

**Registering a key** (`keyId`, `attestationObject`, both Base64):

1. Verify the attestation object's certificate chain up to Apple's App Attestation root CA.
2. Compute `clientDataHash = SHA256(challenge)` from the challenge you issued, then
   `nonce = SHA256(authData || clientDataHash)`, and check that it equals the nonce in the credential
   certificate's extension `1.2.840.113635.100.8.2`.
3. Check that the SHA-256 of the credential certificate's public key equals `keyId`, that the
   authenticator data's RP ID hash is `SHA256("<TeamID>.<bundle ID>")`, that its counter is 0, that
   its AAGUID is `appattest` (production) or `appattestdevelop` (development) as you expect, and that
   its credential ID equals `keyId`.
4. Store the public key and the counter for `keyId`, and mark the challenge used.

**Each report** (`json`, `keyId`, `assertion`):

1. Look up the public key and counter stored for `keyId`; reject unknown keys.
2. Compute `clientDataHash = SHA256(json)` over the exact bytes received, then
   `nonce = SHA256(authenticatorData || clientDataHash)`, and verify the assertion's signature for
   `nonce` with the stored public key.
3. Check the RP ID hash as above, and that the assertion's counter is greater than the stored counter;
   store the new counter.
4. Check that the `challenge` in `json` (Base64) is one you issued, unexpired and unused, then mark it
   used.

Only after all of this, read the report's `threats` and `riskLevel`.

## What a verified report proves, and what it does not

A verified report proves that it was produced **for your challenge**, **once**, by a genuine copy of
**your app** on a genuine Apple device holding the key you registered, and that it was not changed
afterwards.

It does not prove that the report's **contents** are true. The app builds the report, and on a device
where an attacker can hook the app, the attacker can hand a clean report to App Attest, which will
sign it. App Attest does not detect jailbreaks by itself either. No client-side signing scheme can
prevent that. Therefore:

- Base decisions on what App Attest proves (your genuine app, a registered key, a fresh challenge) and
  on your own server-side signals, such as how many keys one account registers and Apple's optional
  fraud-risk metric for attestation receipts.
- Treat MobShield's `threats` as additional context: a report of a hook is strong evidence, but the
  absence of one is not proof that there is none.

## Changes in this version

- New `MobShieldAppAttest` (with the `AppAttestService` and `AppAttestKeyStore` protocols and their
  default implementations), `MobShield.currentAttestedReport(challenge:attester:)`,
  `MobShield.currentReport(challenge:)`, `MobShieldReporter.makeReport(state:events:buildId:challenge:schemaVersion:)`,
  `MobShieldReporter.clientDataHash(_:)`, `AttestedThreatReport`, `AppAttestKeyAttestation` and
  `MobShieldReportError`.
- Reports gain an optional `challenge` field; the schema version is now `report-2`. Reports built
  without a challenge are unchanged apart from the version.
- `currentSignedReport(key:)`, `MobShieldReporter.sign(_:key:)` and HMAC signing are deprecated.
