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

/// A serializable snapshot of the current posture, intended to be sent to a backend for
/// server-side decisioning. Client-side termination is bypassable, so the authoritative decision
/// belongs on a server that receives and verifies this report. See `docs/report-attestation.md`.
public struct ThreatReport: Codable, Sendable, Equatable {
    /// `report-2` adds the optional `challenge` field to `report-1`.
    public static let currentSchemaVersion = "report-2"

    public let schemaVersion: String
    public let signalSetVersion: String
    public let buildId: String
    /// Client clock at the last scan. Informational only: the client controls it.
    public let generatedAtMs: Int64
    public let riskLevel: RiskLevel
    public let threats: [Entry]
    /// The server-issued challenge this report answers, Base64 (RFC 4648, padded). A server accepts
    /// a report only for a challenge it issued, has not seen answered before, and has not expired.
    /// `nil` for reports that were not requested with a challenge; such reports can be replayed.
    public let challenge: String?

    public struct Entry: Codable, Sendable, Equatable {
        public let type: ThreatType
        public let severity: Severity
        public let score: Int
        public let signals: [String]

        public init(type: ThreatType, severity: Severity, score: Int, signals: [String]) {
            self.type = type
            self.severity = severity
            self.score = score
            self.signals = signals
        }
    }

    public init(
        schemaVersion: String,
        signalSetVersion: String,
        buildId: String,
        generatedAtMs: Int64,
        riskLevel: RiskLevel,
        threats: [Entry],
        challenge: String? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.signalSetVersion = signalSetVersion
        self.buildId = buildId
        self.generatedAtMs = generatedAtMs
        self.riskLevel = riskLevel
        self.threats = threats
        self.challenge = challenge
    }
}

/// A ``ThreatReport`` serialized to canonical JSON together with an HMAC-SHA256 signature over
/// exactly those bytes.
///
/// The HMAC key has to ship inside the app, so anyone who can read or hook the app can sign any
/// report with it. This proves only that the report was not changed in transit; it does not prove
/// which app or device produced it. Use ``AttestedThreatReport`` instead.
public struct SignedThreatReport: Sendable, Equatable {
    /// Canonical JSON of the report — the exact bytes the signature covers.
    public let json: Data
    /// Lowercase hex HMAC-SHA256 of `json`.
    public let signatureHex: String

    public init(json: Data, signatureHex: String) {
        self.json = json
        self.signatureHex = signatureHex
    }
}

/// A ``ThreatReport`` that answers a server challenge, with an App Attest assertion over its
/// canonical JSON.
///
/// Send all three fields to your backend. The backend looks up the public key it stored when it
/// verified the attestation for `keyId`, verifies `assertion` against `SHA256(json)`, checks that the
/// assertion's counter increased, and checks the challenge in `json`. See `docs/report-attestation.md`.
public struct AttestedThreatReport: Sendable, Equatable {
    /// Canonical JSON of the report: the exact bytes whose SHA-256 is the assertion's client data hash.
    public let json: Data
    /// The App Attest key identifier, as returned by `DCAppAttestService.generateKey()`.
    public let keyId: String
    /// The App Attest assertion (CBOR), Base64.
    public let assertion: String

    public init(json: Data, keyId: String, assertion: String) {
        self.json = json
        self.keyId = keyId
        self.assertion = assertion
    }
}

/// The one-time attestation of a new App Attest key, to send to your backend before the first
/// attested report. The backend verifies it against Apple's App Attestation root and stores the key.
public struct AppAttestKeyAttestation: Sendable, Equatable {
    /// The App Attest key identifier.
    public let keyId: String
    /// The attestation object (CBOR), Base64. Its client data hash is `SHA256(challenge)`.
    public let attestationObject: String

    public init(keyId: String, attestationObject: String) {
        self.keyId = keyId
        self.attestationObject = attestationObject
    }
}
