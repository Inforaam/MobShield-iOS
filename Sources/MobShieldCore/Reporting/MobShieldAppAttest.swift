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

import DeviceCheck
import Foundation
import Security

/// Errors from building or attesting a report.
public enum MobShieldReportError: Error, Equatable {
    /// The challenge is shorter than ``MobShieldReporter/minChallengeBytes`` or longer than
    /// ``MobShieldReporter/maxChallengeBytes``.
    case invalidChallenge(length: Int)
    /// The report carries no challenge. Build it with ``MobShield/currentReport(challenge:)``.
    case missingChallenge
    /// App Attest is not available: the Simulator, an unsupported device, or an app extension
    /// that cannot use it.
    case unsupported
    /// No attested key is stored. Call ``MobShieldAppAttest/attestKey(challenge:)`` first.
    case keyNotAttested
    /// The Keychain refused to store the key identifier.
    case keychain(status: OSStatus)
}

/// The App Attest operations MobShield uses. ``DeviceCheckAppAttestService`` is the implementation
/// for apps; the protocol exists so the reporting path can be tested where App Attest is unavailable.
public protocol AppAttestService: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// `DCAppAttestService.shared`.
public struct DeviceCheckAppAttestService: AppAttestService {
    public init() {}

    public var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    public func generateKey() async throws -> String {
        try await DCAppAttestService.shared.generateKey()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
    }
}

/// Where ``MobShieldAppAttest`` keeps the identifier of its attested key.
public protocol AppAttestKeyStore: Sendable {
    func load() -> String?
    func save(_ keyId: String) throws
    func clear()
}

/// Keeps the key identifier in the Keychain, readable after first unlock and never migrated to
/// another device: App Attest keys do not move between devices, so a restored identifier would be
/// useless there.
public struct KeychainAppAttestKeyStore: AppAttestKeyStore {
    private let service: String
    private let account = "keyId"

    public init(service: String = "io.mobshield.appattest") {
        self.service = service
    }

    public func load() -> String? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func save(_ keyId: String) throws {
        clear()
        var item = baseQuery
        item[kSecValueData as String] = Data(keyId.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw MobShieldReportError.keychain(status: status) }
    }

    public func clear() {
        SecItemDelete(baseQuery as CFDictionary)
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

/// Signs reports with an App Attest key, so a backend can check that a report came from your genuine
/// app on a genuine Apple device and answers a challenge it issued.
///
/// 1. Once per install, fetch a challenge from your backend, call ``attestKey(challenge:)`` and send
///    the result to the backend, which verifies it and stores the key's public key and counter.
/// 2. For each report, fetch a new challenge and call ``MobShield/currentAttestedReport(challenge:attester:)``
///    (or ``attest(_:)``), and send the result to the backend.
///
/// If the backend no longer recognises the key, or App Attest reports `DCError.invalidKey` (for
/// example after the app is restored onto another device), call ``resetKey()`` and attest again.
/// App Attest is not available in the Simulator. See `docs/report-attestation.md`.
public actor MobShieldAppAttest {
    private let service: AppAttestService
    private let keyStore: AppAttestKeyStore

    public init(
        service: AppAttestService = DeviceCheckAppAttestService(),
        keyStore: AppAttestKeyStore = KeychainAppAttestKeyStore()
    ) {
        self.service = service
        self.keyStore = keyStore
    }

    /// Whether App Attest can be used on this device.
    public nonisolated var isSupported: Bool {
        service.isSupported
    }

    /// Whether a key has been attested and stored.
    public var hasAttestedKey: Bool {
        keyStore.load() != nil
    }

    /// Creates a new App Attest key, attests it for the server-issued `challenge`, and stores it for
    /// later reports, replacing any earlier key. The attestation's client data hash is
    /// `SHA256(challenge)`. Send the result to your backend to register the key.
    public func attestKey(challenge: Data) async throws -> AppAttestKeyAttestation {
        try MobShieldReporter.requireValidChallenge(challenge)
        guard service.isSupported else { throw MobShieldReportError.unsupported }
        let keyId = try await service.generateKey()
        let attestation = try await service.attestKey(
            keyId,
            clientDataHash: MobShieldReporter.clientDataHash(challenge)
        )
        try keyStore.save(keyId)
        return AppAttestKeyAttestation(keyId: keyId, attestationObject: attestation.base64EncodedString())
    }

    /// Generates an App Attest assertion over `report`, which must carry a challenge. The assertion's
    /// client data hash is `SHA256(json)`.
    public func attest(_ report: ThreatReport) async throws -> AttestedThreatReport {
        guard report.challenge != nil else { throw MobShieldReportError.missingChallenge }
        guard service.isSupported else { throw MobShieldReportError.unsupported }
        guard let keyId = keyStore.load() else { throw MobShieldReportError.keyNotAttested }
        let json = try MobShieldReporter.canonicalJSON(report)
        let assertion = try await service.generateAssertion(
            keyId,
            clientDataHash: MobShieldReporter.clientDataHash(json)
        )
        return AttestedThreatReport(json: json, keyId: keyId, assertion: assertion.base64EncodedString())
    }

    /// Forgets the stored key, so the next report needs ``attestKey(challenge:)`` again.
    public func resetKey() {
        keyStore.clear()
    }
}
