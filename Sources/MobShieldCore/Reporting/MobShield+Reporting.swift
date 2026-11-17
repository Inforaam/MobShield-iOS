/*
 * Copyright 2025 MobShield Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation

public extension MobShield {
    /// A snapshot report of the latest scan wave's posture, suitable for sending to a backend.
    func currentReport(schemaVersion: String = ThreatReport.currentSchemaVersion) -> ThreatReport {
        MobShieldReporter.makeReport(
            state: getState(),
            events: getLastEvents(),
            buildId: MobShield.getBuildId(),
            schemaVersion: schemaVersion
        )
    }

    /// The current report, answering the server-issued `challenge`.
    func currentReport(challenge: Data) throws -> ThreatReport {
        try MobShieldReporter.makeReport(
            state: getState(),
            events: getLastEvents(),
            buildId: MobShield.getBuildId(),
            challenge: challenge
        )
    }

    /// The current report, answering the server-issued `challenge`, with an App Attest assertion
    /// from `attester`'s key. Attest the key once with ``MobShieldAppAttest/attestKey(challenge:)``
    /// first. Verify the result on your backend as described in `docs/report-attestation.md`.
    func currentAttestedReport(challenge: Data, attester: MobShieldAppAttest) async throws -> AttestedThreatReport {
        try await attester.attest(currentReport(challenge: challenge))
    }

    /// The current report as canonical JSON plus an HMAC-SHA256 signature under `key`.
    ///
    /// The key ships inside the app, so anyone who can read or hook the app can sign a clean report
    /// with it, and the report can be replayed. Use ``currentAttestedReport(challenge:attester:)``.
    @available(
        *,
        deprecated,
        message: "An HMAC key shipped in the app cannot prove where a report came from. Use currentAttestedReport; see docs/report-attestation.md."
    )
    func currentSignedReport(key: Data) throws -> SignedThreatReport {
        try MobShieldReporter.sign(currentReport(), key: key)
    }
}
