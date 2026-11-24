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
import MobShieldCore
@testable import MobShieldDetectIntegrity
import XCTest

final class IntegrityAvailabilityTests: XCTestCase {
    private let bundleURL = URL(fileURLWithPath: "/App.app")
    private var profilePath: String { bundleURL.appendingPathComponent("embedded.mobileprovision").path }
    private let digest = String(repeating: "a", count: 64)

    private func profile(applicationIdentifier: String) -> Data {
        let plist: [String: Any] = [
            "Entitlements": ["application-identifier": applicationIdentifier],
            "TeamIdentifier": ["TEAM"],
        ]
        let xml = try! PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        return Data("signature-prefix".utf8) + xml + Data("signature-suffix".utf8)
    }

    func testProvisioning_noEmbeddedProfile_noHit() {
        let bundle = MockIntegrityBundle(bundleIdentifier: "com.example.app", bundleURL: bundleURL)
        XCTAssertNil(EmbeddedProvisioningProfileCheck(expectedPackageId: "com.example.app", bundle: bundle).scan())
    }

    func testProvisioning_appIdMismatch_emitsHit() {
        let bundle = MockIntegrityBundle(
            bundleURL: bundleURL,
            files: [profilePath: profile(applicationIdentifier: "TEAM.com.other.app")]
        )
        let hit = EmbeddedProvisioningProfileCheck(expectedPackageId: "com.example.app", bundle: bundle).scan()
        XCTAssertEqual("provisioning_app_id_mismatch", hit?.reason)
        XCTAssertEqual(false, hit?.isUnavailable)
    }

    func testProvisioning_matchingAppId_noHit() {
        let bundle = MockIntegrityBundle(
            bundleURL: bundleURL,
            files: [profilePath: profile(applicationIdentifier: "TEAM.com.example.app")]
        )
        XCTAssertNil(EmbeddedProvisioningProfileCheck(expectedPackageId: "com.example.app", bundle: bundle).scan())
    }

    func testProvisioning_unparseableProfile_isUnavailable() {
        let bundle = MockIntegrityBundle(bundleURL: bundleURL, files: [profilePath: Data("garbage".utf8)])
        let hit = EmbeddedProvisioningProfileCheck(expectedPackageId: "com.example.app", bundle: bundle).scan()
        XCTAssertEqual("provisioning_profile_parse_failed", hit?.reason)
        XCTAssertEqual(true, hit?.isUnavailable)
    }

    func testLiveSecCode_noEmbeddedProfile_throwsNoEmbeddedProfile() {
        let provider = LiveSecCodeProvider(bundle: MockIntegrityBundle(bundleURL: bundleURL))
        XCTAssertThrowsError(try provider.copySigningInfo()) { error in
            guard case IntegritySecCodeError.noEmbeddedProfile = error else {
                return XCTFail("Unexpected error \(error)")
            }
        }
    }

    func testCodeSignature_noEmbeddedProfile_noHit() {
        let check = CodeSignatureCheck(
            expectedSigners: [digest],
            secCode: MockSecCodeProvider(
                signingInfo: IntegritySigningInfo(certificateDigests: [], teamIdentifier: nil, bundleIdentifier: nil),
                error: IntegritySecCodeError.noEmbeddedProfile
            )
        )
        XCTAssertNil(check.scan())
    }

    func testCodeSignature_unreadableSigningInfo_isUnavailable() {
        let check = CodeSignatureCheck(
            expectedSigners: [digest],
            secCode: MockSecCodeProvider(
                signingInfo: IntegritySigningInfo(certificateDigests: [], teamIdentifier: nil, bundleIdentifier: nil),
                error: IntegritySecCodeError.missingSigningInfo
            )
        )
        let hit = check.scan()
        XCTAssertEqual("sec_code_unavailable", hit?.reason)
        XCTAssertEqual(true, hit?.isUnavailable)
    }

    func testRunner_fastWork_returnsItsResult() async {
        let hit = IntegrityScanHit(reason: "r")
        let result = await IntegrityCheckRunner.run(timeoutNs: 1_000_000_000) { hit }
        XCTAssertEqual(.finished(hit), result)
    }

    func testRunner_slowWork_timesOutWithoutWaitingForIt() async {
        let start = Date()
        let result = await IntegrityCheckRunner.run(timeoutNs: 50_000_000) {
            Thread.sleep(forTimeInterval: 3)
            return nil
        }
        XCTAssertEqual(.timedOut, result)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }

    func testRunner_busyGlobalQueue_stillTimesOut() async {
        let blockers = ProcessInfo.processInfo.activeProcessorCount * 4
        for _ in 0..<blockers {
            DispatchQueue.global(qos: .utility).async { Thread.sleep(forTimeInterval: 1.5) }
        }
        let start = Date()
        let result = await IntegrityCheckRunner.run(timeoutNs: 50_000_000) {
            Thread.sleep(forTimeInterval: 2)
            return nil
        }
        XCTAssertEqual(.timedOut, result)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
    }

    func testModule_storeBuildWithoutProfile_emitsNothing() async throws {
        let config = try MobShieldConfig.make(expectedSigners: [digest], expectedPackageId: "com.example.app")
        let bundle = MockIntegrityBundle(bundleIdentifier: "com.example.app", bundleURL: bundleURL)
        let module = IntegrityDetectionModule(
            config: config,
            bundle: bundle,
            secCode: LiveSecCodeProvider(bundle: bundle)
        )
        let signals = await module.scan()
        XCTAssertEqual([], signals.map(\.name))
    }

    func testModule_unavailableChecks_reportedAsOneLowSignal() async throws {
        let config = try MobShieldConfig.make(
            expectedSigners: [digest],
            expectedResourceHashes: ["Info.plist": digest]
        )
        let module = IntegrityDetectionModule(
            config: config,
            bundle: MockIntegrityBundle(),
            secCode: MockSecCodeProvider(
                signingInfo: IntegritySigningInfo(certificateDigests: [], teamIdentifier: nil, bundleIdentifier: nil),
                error: IntegritySecCodeError.missingSigningInfo
            )
        )
        let signals = await module.scan()
        XCTAssertEqual([IntegritySignalDefaults.checkUnavailable], signals.map(\.name))
        XCTAssertEqual(
            "provisioning:bundle_url_missing,resource:bundle_url_missing,sec_code:sec_code_unavailable",
            signals.first?.evidence["checks"]
        )
        let events = SignalAggregator(config: config).aggregate(signals: signals)
        XCTAssertEqual(.low, events.first?.severity)
    }

    func testModule_slowCheck_reportedAsTimeout() async throws {
        let config = try MobShieldConfig.make(expectedSigners: [digest])
        let module = IntegrityDetectionModule(
            config: config,
            scanTimeoutMs: 50,
            bundle: MockIntegrityBundle(bundleURL: bundleURL),
            secCode: SlowSecCodeProvider()
        )
        let signals = await module.scan()
        XCTAssertEqual("sec_code:timeout", signals.first { $0.name == IntegritySignalDefaults.checkUnavailable }?
            .evidence["checks"])
    }
}

private struct SlowSecCodeProvider: IntegritySecCodeProviding {
    func copySigningInfo() throws -> IntegritySigningInfo {
        Thread.sleep(forTimeInterval: 2)
        throw IntegritySecCodeError.missingSigningInfo
    }
}
