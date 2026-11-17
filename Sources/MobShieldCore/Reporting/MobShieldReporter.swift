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

import CryptoKit
import Foundation

/// Builds and signs ``ThreatReport``s. It never performs networking: the host app fetches
/// challenges from, and sends reports to, its own backend. See `docs/report-attestation.md`.
public enum MobShieldReporter {
    /// Shortest server challenge accepted, in bytes.
    public static let minChallengeBytes = 16
    /// Longest server challenge accepted, in bytes (matches the Android limit).
    public static let maxChallengeBytes = 128

    /// Builds a report from a posture snapshot and the events of the last scan wave.
    public static func makeReport(
        state: MobShieldState,
        events: [ThreatEvent],
        buildId: String,
        schemaVersion: String = ThreatReport.currentSchemaVersion
    ) -> ThreatReport {
        let entries = events
            .sorted { $0.score > $1.score }
            .map { event in
                ThreatReport.Entry(
                    type: event.type,
                    severity: event.severity,
                    score: event.score,
                    signals: event.signals
                )
            }
        return ThreatReport(
            schemaVersion: schemaVersion,
            signalSetVersion: state.signalSetVersion,
            buildId: buildId,
            generatedAtMs: state.lastScanMs,
            riskLevel: state.riskLevel,
            threats: entries
        )
    }

    /// Builds a report that answers a server-issued challenge of ``minChallengeBytes`` to
    /// ``maxChallengeBytes`` random bytes. Without a challenge, a captured report can be replayed.
    public static func makeReport(
        state: MobShieldState,
        events: [ThreatEvent],
        buildId: String,
        challenge: Data,
        schemaVersion: String = ThreatReport.currentSchemaVersion
    ) throws -> ThreatReport {
        try requireValidChallenge(challenge)
        let report = makeReport(state: state, events: events, buildId: buildId, schemaVersion: schemaVersion)
        return ThreatReport(
            schemaVersion: report.schemaVersion,
            signalSetVersion: report.signalSetVersion,
            buildId: report.buildId,
            generatedAtMs: report.generatedAtMs,
            riskLevel: report.riskLevel,
            threats: report.threats,
            challenge: challenge.base64EncodedString()
        )
    }

    /// SHA-256 of `data`: the App Attest client data hash for a report's canonical JSON, or for a
    /// challenge when attesting a key.
    public static func clientDataHash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func requireValidChallenge(_ challenge: Data) throws {
        guard (minChallengeBytes...maxChallengeBytes).contains(challenge.count) else {
            throw MobShieldReportError.invalidChallenge(length: challenge.count)
        }
    }

    /// Encodes a report to canonical (deterministic, sorted-key) JSON so a backend can recompute
    /// the signature over identical bytes.
    public static func canonicalJSON(_ report: ThreatReport) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(report)
    }

    /// Produces the canonical JSON and its HMAC-SHA256 signature under `key`.
    ///
    /// The key ships inside the app, so anyone who can read or hook the app can sign a clean report
    /// with it, and a report without a challenge can be replayed. The signature shows only that the
    /// report was not changed in transit.
    @available(
        *,
        deprecated,
        message: "An HMAC key shipped in the app cannot prove where a report came from. Use MobShieldAppAttest; see docs/report-attestation.md."
    )
    public static func sign(_ report: ThreatReport, key: Data) throws -> SignedThreatReport {
        let json = try canonicalJSON(report)
        let code = HMAC<SHA256>.authenticationCode(for: json, using: SymmetricKey(data: key))
        let hex = code.map { String(format: "%02x", $0) }.joined()
        return SignedThreatReport(json: json, signatureHex: hex)
    }
}
