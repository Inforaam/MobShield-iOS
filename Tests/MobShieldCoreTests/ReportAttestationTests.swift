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
import XCTest
@testable import MobShieldCore

/// Reports answer a server challenge and carry an App Attest assertion over their canonical JSON.
/// App Attest is unavailable in tests, so a fake service records what it is asked to sign; what
/// these tests check is that the client data hashes are the ones a server recomputes.
/// See `docs/report-attestation.md`.
/// What ``ReportAttestationTests``' fake App Attest service was asked to sign.
private struct RecordedAttestCalls {
    var attestHash: Data?
    var assertionHash: Data?
    var assertionKeyId: String?
}

final class ReportAttestationTests: XCTestCase {
    private let challenge = Data((0..<32).map { UInt8($0) })
    private let otherChallenge = Data((0..<32).map { UInt8($0 + 1) })

    func testMakeReport_carriesTheChallenge_inTheJSON() throws {
        let report = try makeReport(challenge)
        let json = try String(bytes: MobShieldReporter.canonicalJSON(report), encoding: .utf8) ?? ""

        XCTAssertEqual(challenge.base64EncodedString(), report.challenge)
        XCTAssertTrue(json.contains("\"challenge\":\"\(challenge.base64EncodedString())\""))
        let buildId = try XCTUnwrap(json.range(of: "\"buildId\""))
        let challengeKey = try XCTUnwrap(json.range(of: "\"challenge\""))
        let generatedAt = try XCTUnwrap(json.range(of: "\"generatedAtMs\""))
        XCTAssertTrue(buildId.lowerBound < challengeKey.lowerBound)
        XCTAssertTrue(challengeKey.lowerBound < generatedAt.lowerBound)
    }

    func testReportWithoutChallenge_omitsTheKey() throws {
        let report = MobShieldReporter.makeReport(state: state(), events: [], buildId: "b")
        let json = try String(bytes: MobShieldReporter.canonicalJSON(report), encoding: .utf8) ?? ""

        XCTAssertNil(report.challenge)
        XCTAssertFalse(json.contains("challenge"))
    }

    func testReportsForDifferentChallenges_differ() throws {
        let a = try MobShieldReporter.canonicalJSON(makeReport(challenge))
        let b = try MobShieldReporter.canonicalJSON(makeReport(otherChallenge))

        XCTAssertNotEqual(a, b)
    }

    func testMakeReport_rejectsChallengesOutsideTheAllowedLength() throws {
        XCTAssertThrowsError(try makeReport(Data(count: 15))) {
            XCTAssertEqual(MobShieldReportError.invalidChallenge(length: 15), $0 as? MobShieldReportError)
        }
        XCTAssertThrowsError(try makeReport(Data(count: 129)))
        XCTAssertNoThrow(try makeReport(Data(count: MobShieldReporter.minChallengeBytes)))
        XCTAssertNoThrow(try makeReport(Data(count: MobShieldReporter.maxChallengeBytes)))
    }

    func testReportWithChallenge_roundTripsThroughCodable() throws {
        let report = try makeReport(challenge)
        let decoded = try JSONDecoder().decode(ThreatReport.self, from: MobShieldReporter.canonicalJSON(report))

        XCTAssertEqual(report, decoded)
    }

    func testAttestKey_usesTheHashOfTheChallenge_andStoresTheKey() async throws {
        let service = FakeAppAttestService()
        let store = InMemoryKeyStore()
        let attester = MobShieldAppAttest(service: service, keyStore: store)

        let attestation = try await attester.attestKey(challenge: challenge)

        XCTAssertEqual("key-1", attestation.keyId)
        XCTAssertEqual(Data("attestation".utf8).base64EncodedString(), attestation.attestationObject)
        XCTAssertEqual(Data(SHA256.hash(data: challenge)), service.recorded.attestHash)
        XCTAssertEqual("key-1", store.load())
        let hasKey = await attester.hasAttestedKey
        XCTAssertTrue(hasKey)
    }

    func testAttest_assertsOverTheHashOfTheCanonicalJSON() async throws {
        let service = FakeAppAttestService()
        let attester = MobShieldAppAttest(service: service, keyStore: InMemoryKeyStore())
        _ = try await attester.attestKey(challenge: challenge)
        let report = try makeReport(challenge)

        let attested = try await attester.attest(report)

        XCTAssertEqual(try MobShieldReporter.canonicalJSON(report), attested.json)
        XCTAssertEqual(Data(SHA256.hash(data: attested.json)), service.recorded.assertionHash)
        XCTAssertEqual("key-1", service.recorded.assertionKeyId)
        XCTAssertEqual("key-1", attested.keyId)
        XCTAssertEqual(Data("assertion".utf8).base64EncodedString(), attested.assertion)
    }

    func testAttest_requiresAChallenge() async throws {
        let attester = MobShieldAppAttest(service: FakeAppAttestService(), keyStore: InMemoryKeyStore())
        _ = try await attester.attestKey(challenge: challenge)
        let report = MobShieldReporter.makeReport(state: state(), events: [], buildId: "b")

        await assertThrows(.missingChallenge) { _ = try await attester.attest(report) }
    }

    func testAttest_requiresAnAttestedKey() async throws {
        let service = FakeAppAttestService()
        let attester = MobShieldAppAttest(service: service, keyStore: InMemoryKeyStore())
        let report = try makeReport(challenge)

        await assertThrows(.keyNotAttested) { _ = try await attester.attest(report) }
        XCTAssertNil(service.recorded.assertionHash)
    }

    func testUnsupportedDevice_attestsNothing() async throws {
        let service = FakeAppAttestService(isSupported: false)
        let attester = MobShieldAppAttest(service: service, keyStore: InMemoryKeyStore())

        XCTAssertFalse(attester.isSupported)
        await assertThrows(.unsupported) { _ = try await attester.attestKey(challenge: self.challenge) }
        XCTAssertNil(service.recorded.attestHash)
    }

    func testAttestKey_rejectsAShortChallenge() async {
        let attester = MobShieldAppAttest(service: FakeAppAttestService(), keyStore: InMemoryKeyStore())

        await assertThrows(.invalidChallenge(length: 8)) { _ = try await attester.attestKey(challenge: Data(count: 8)) }
    }

    func testResetKey_requiresANewAttestation() async throws {
        let attester = MobShieldAppAttest(service: FakeAppAttestService(), keyStore: InMemoryKeyStore())
        _ = try await attester.attestKey(challenge: challenge)

        await attester.resetKey()

        let hasKey = await attester.hasAttestedKey
        XCTAssertFalse(hasKey)
        let report = try makeReport(challenge)
        await assertThrows(.keyNotAttested) { _ = try await attester.attest(report) }
    }

    func testClientDataHash_isSHA256() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        let hash = MobShieldReporter.clientDataHash(Data("abc".utf8))

        XCTAssertEqual(expected, hash.map { String(format: "%02x", $0) }.joined())
    }

    // MARK: - Helpers

    private func makeReport(_ challenge: Data) throws -> ThreatReport {
        try MobShieldReporter.makeReport(
            state: state(),
            events: [
                ThreatEvent.create(
                    type: .hookFramework,
                    severity: .high,
                    signals: ["ios.hook.frida_port"],
                    score: 60,
                    timestampMs: 0
                ),
            ],
            buildId: "b",
            challenge: challenge
        )
    }

    private func state() -> MobShieldState {
        MobShieldState(
            riskLevel: .high,
            activeThreats: [],
            lastScanMs: 1,
            signalSetVersion: MobShield.signalSetVersion,
            running: true
        )
    }

    private func assertThrows(
        _ expected: MobShieldReportError,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("Expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(expected, error as? MobShieldReportError, file: file, line: line)
        }
    }

    private final class FakeAppAttestService: AppAttestService, @unchecked Sendable {
        let isSupported: Bool
        private let lock = NSLock()
        private var state = RecordedAttestCalls()
        private var keys = 0

        init(isSupported: Bool = true) {
            self.isSupported = isSupported
        }

        var recorded: RecordedAttestCalls {
            lock.lock()
            defer { lock.unlock() }
            return state
        }

        func generateKey() async throws -> String {
            nextKeyId()
        }

        func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
            record { $0.attestHash = clientDataHash }
            return Data("attestation".utf8)
        }

        func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
            record {
                $0.assertionHash = clientDataHash
                $0.assertionKeyId = keyId
            }
            return Data("assertion".utf8)
        }

        // NSLock cannot be used directly in async functions, so the async methods call these.
        private func nextKeyId() -> String {
            lock.lock()
            defer { lock.unlock() }
            keys += 1
            return "key-\(keys)"
        }

        private func record(_ update: (inout RecordedAttestCalls) -> Void) {
            lock.lock()
            defer { lock.unlock() }
            update(&state)
        }
    }

    private final class InMemoryKeyStore: AppAttestKeyStore, @unchecked Sendable {
        private let lock = NSLock()
        private var keyId: String?

        func load() -> String? {
            lock.lock()
            defer { lock.unlock() }
            return keyId
        }

        func save(_ keyId: String) throws {
            lock.lock()
            defer { lock.unlock() }
            self.keyId = keyId
        }

        func clear() {
            lock.lock()
            defer { lock.unlock() }
            keyId = nil
        }
    }
}
