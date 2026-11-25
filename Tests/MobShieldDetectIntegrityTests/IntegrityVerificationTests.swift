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

final class IntegrityVerificationTests: XCTestCase {
    private let bundleURL = URL(fileURLWithPath: "/App.app")
    private var profilePath: String { bundleURL.appendingPathComponent("embedded.mobileprovision").path }
    private let team = "ABCDE12345"

    // MARK: - Helpers

    private func be32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24 & 0xFF), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
    }

    private func codeDirectory(identifier: String, team: String?, flags: UInt32) -> [UInt8] {
        let headerSize = 88
        let identBytes: [UInt8] = Array(identifier.utf8) + [0]
        let teamBytes: [UInt8] = team.map { Array($0.utf8) + [0] } ?? []
        var header = [UInt8](repeating: 0, count: headerSize)
        func put(_ value: UInt32, at offset: Int) {
            header.replaceSubrange(offset..<(offset + 4), with: be32(value))
        }
        let length = UInt32(headerSize + identBytes.count + teamBytes.count)
        put(CodeSignatureParser.codeDirectoryMagic, at: 0)
        put(length, at: 4)
        put(0x20400, at: 8)
        put(flags, at: 12)
        put(UInt32(headerSize), at: 20)
        put(team == nil ? 0 : UInt32(headerSize + identBytes.count), at: 48)
        return header + identBytes + teamBytes
    }

    private func entitlementsBlob(_ entitlements: [String: Any]) -> [UInt8] {
        let xml = try! PropertyListSerialization.data(fromPropertyList: entitlements, format: .xml, options: 0)
        return be32(CodeSignatureParser.entitlementsMagic) + be32(UInt32(8 + xml.count)) + [UInt8](xml)
    }

    private func superBlob(_ blobs: [(UInt32, [UInt8])]) -> Data {
        let indexSize = 12 + blobs.count * 8
        var offset = indexSize
        var index: [UInt8] = []
        var body: [UInt8] = []
        for (type, blob) in blobs {
            index += be32(type) + be32(UInt32(offset))
            body += blob
            offset += blob.count
        }
        return Data(be32(CodeSignatureParser.superBlobMagic) + be32(UInt32(offset)) + be32(UInt32(blobs.count)) + index + body)
    }

    private func profile(_ plist: [String: Any]) -> Data {
        let xml = try! PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        return Data("prefix".utf8) + xml + Data("suffix".utf8)
    }

    private func info(
        team: String? = "ABCDE12345",
        appId: String? = "ABCDE12345.com.example.app",
        getTaskAllow: Bool = false,
        encrypted: Bool? = true
    ) -> MockExecutableProvider {
        MockExecutableProvider(info: IntegrityExecutableInfo(
            hasCodeSignature: true,
            signingIdentifier: "com.example.app",
            teamIdentifier: team,
            applicationIdentifier: appId,
            getTaskAllow: getTaskAllow,
            isEncrypted: encrypted
        ))
    }

    // MARK: - Code signature parsing

    func testParser_readsIdentifierTeamAndEntitlements() throws {
        let data = superBlob([
            (CodeSignatureParser.codeDirectorySlot, codeDirectory(identifier: "com.example.app", team: team, flags: 0)),
            (CodeSignatureParser.entitlementsSlot, entitlementsBlob([
                "application-identifier": "\(team).com.example.app",
                "get-task-allow": true,
            ])),
        ])
        let parsed = try XCTUnwrap(CodeSignatureParser.parse(data))
        XCTAssertEqual("com.example.app", parsed.identifier)
        XCTAssertEqual(team, parsed.teamIdentifier)
        XCTAssertFalse(parsed.isAdHoc)
        XCTAssertEqual("\(team).com.example.app", parsed.entitlements["application-identifier"] as? String)
        XCTAssertEqual(true, parsed.entitlements["get-task-allow"] as? Bool)
    }

    func testParser_adHocWithoutTeam() throws {
        let data = superBlob([
            (CodeSignatureParser.codeDirectorySlot, codeDirectory(identifier: "a.out", team: nil, flags: 0x2)),
        ])
        let parsed = try XCTUnwrap(CodeSignatureParser.parse(data))
        XCTAssertNil(parsed.teamIdentifier)
        XCTAssertTrue(parsed.isAdHoc)
    }

    func testParser_rejectsMalformedInput() {
        XCTAssertNil(CodeSignatureParser.parse(Data([1, 2, 3])))
        var data = [UInt8](superBlob([
            (CodeSignatureParser.codeDirectorySlot, codeDirectory(identifier: "x", team: team, flags: 0)),
        ]))
        data.removeLast(20)
        XCTAssertNil(CodeSignatureParser.parse(Data(data)))
        XCTAssertNil(CodeSignatureParser.parse(superBlob([])))
    }

    func testLiveExecutable_readsTheRunningProcessSignature() throws {
        let info = try XCTUnwrap(LiveExecutableProvider().executableInfo())
        XCTAssertTrue(info.hasCodeSignature)
        XCTAssertNotNil(info.signingIdentifier)
    }

    // MARK: - Team ID

    private func teamCheck(_ executable: MockExecutableProvider, simulator: Bool = false) -> TeamIdentifierCheck {
        TeamIdentifierCheck(
            expectedTeamId: team,
            expectedPackageId: "com.example.app",
            executable: executable,
            isSimulator: simulator
        )
    }

    func testTeamId_matching_noHit() {
        XCTAssertNil(teamCheck(info()).scan())
    }

    func testTeamId_legacyAppIdPrefix_noHit() {
        XCTAssertNil(teamCheck(info(appId: "XYZ9876543.com.example.app")).scan())
    }

    func testTeamId_mismatch() {
        let hit = teamCheck(info(team: "ZZZZZ99999")).scan()
        XCTAssertEqual("team_id_mismatch", hit?.reason)
        XCTAssertEqual("ZZZZZ99999", hit?.evidence["actual"])
    }

    func testTeamId_missingTeam() {
        XCTAssertEqual("team_id_missing", teamCheck(info(team: nil)).scan()?.reason)
    }

    func testTeamId_noSignature() {
        let hit = teamCheck(MockExecutableProvider(info: IntegrityExecutableInfo(hasCodeSignature: false))).scan()
        XCTAssertEqual("signature_missing", hit?.reason)
    }

    func testTeamId_appIdMismatch() {
        XCTAssertEqual("app_id_mismatch", teamCheck(info(appId: "\(team).com.other.app")).scan()?.reason)
    }

    func testTeamId_unreadableExecutable_isUnavailable() {
        XCTAssertEqual(true, teamCheck(MockExecutableProvider(info: nil)).scan()?.isUnavailable)
    }

    func testTeamId_simulator_isSkipped() {
        XCTAssertNil(teamCheck(info(team: nil), simulator: true).scan())
    }

    // MARK: - Distribution

    private func distribution(
        _ allowed: Set<AppDistribution>,
        profile plist: [String: Any]? = nil,
        receipt: String? = nil,
        executable: MockExecutableProvider? = nil,
        simulator: Bool = false
    ) -> IntegrityScanHit? {
        var files: [String: Data] = [:]
        if let plist {
            files[profilePath] = profile(plist)
        }
        let bundle = MockIntegrityBundle(
            bundleURL: bundleURL,
            appStoreReceiptURL: receipt.map { bundleURL.appendingPathComponent("StoreKit/\($0)") },
            files: files
        )
        return DistributionCheck(
            allowed: allowed,
            bundle: bundle,
            executable: executable ?? info(),
            isSimulator: simulator
        ).scan()
    }

    func testDistribution_storeBuilds() {
        XCTAssertNil(distribution(AppDistribution.store, receipt: "receipt"))
        XCTAssertNil(distribution([.testFlight], receipt: "sandboxReceipt"))
        XCTAssertEqual("testFlight", distribution([.appStore], receipt: "sandboxReceipt")?.evidence["actual"])
    }

    func testDistribution_profileTypes() {
        XCTAssertEqual("enterprise", distribution(AppDistribution.store, profile: ["ProvisionsAllDevices": true])?
            .evidence["actual"])
        XCTAssertEqual("development", distribution(
            AppDistribution.store,
            profile: ["Entitlements": ["get-task-allow": true], "ProvisionedDevices": ["x"]]
        )?.evidence["actual"])
        XCTAssertEqual("adHoc", distribution(AppDistribution.store, profile: ["ProvisionedDevices": ["x"]])?
            .evidence["actual"])
        XCTAssertNil(distribution([.adHoc], profile: ["ProvisionedDevices": ["x"]]))
    }

    func testDistribution_getTaskAllowOutsideDevelopment() {
        let hit = distribution(AppDistribution.store, executable: info(getTaskAllow: true))
        XCTAssertEqual("get_task_allow", hit?.reason)
        XCTAssertNil(distribution([.appStore, .development], executable: info(getTaskAllow: true)))
    }

    func testDistribution_notConfiguredOrSimulator_isSkipped() {
        XCTAssertNil(distribution([], profile: ["ProvisionsAllDevices": true]))
        XCTAssertNil(distribution(AppDistribution.store, profile: ["ProvisionsAllDevices": true], simulator: true))
    }

    // MARK: - Encryption

    private func encryption(
        _ allowed: Set<AppDistribution> = AppDistribution.store,
        encrypted: Bool?,
        withProfile: Bool = false,
        onMac: Bool = false
    ) -> IntegrityScanHit? {
        let files = withProfile ? [profilePath: profile(["ProvisionedDevices": ["x"]])] : [:]
        return BinaryEncryptionCheck(
            allowed: allowed,
            bundle: MockIntegrityBundle(bundleURL: bundleURL, files: files),
            executable: info(encrypted: encrypted),
            isSimulator: false,
            isiOSAppOnMac: onMac
        ).scan()
    }

    func testEncryption() {
        XCTAssertNil(encryption(encrypted: true))
        XCTAssertEqual("binary_not_encrypted", encryption(encrypted: false)?.reason)
        XCTAssertEqual("encryption_info_missing", encryption(encrypted: nil)?.reason)
    }

    func testEncryption_onlyForStoreOnlyConfigWithoutProfile() {
        XCTAssertNil(encryption([.appStore, .adHoc], encrypted: false))
        XCTAssertNil(encryption(encrypted: false, withProfile: true))
        XCTAssertNil(encryption(encrypted: false, onMac: true))
        XCTAssertNil(encryption([], encrypted: false))
    }

    // MARK: - App Store verification

    private func appStore(
        _ result: IntegrityAppTransactionResult,
        withProfile: Bool = false
    ) async -> IntegrityScanHit? {
        let files = withProfile ? [profilePath: profile(["ProvisionedDevices": ["x"]])] : [:]
        return await AppStoreVerificationCheck(
            bundle: MockIntegrityBundle(bundleIdentifier: "com.example.app", bundleURL: bundleURL, files: files),
            transactions: MockAppTransactionProvider(result: result),
            isSimulator: false
        ).scan()
    }

    func testAppStore_verification() async {
        let verified = await appStore(.verified(bundleId: "com.example.app"))
        XCTAssertNil(verified)
        let mismatch = await appStore(.verified(bundleId: "com.other.app"))
        XCTAssertEqual("app_transaction_bundle_mismatch", mismatch?.reason)
        let unverified = await appStore(.unverified)
        XCTAssertEqual("app_transaction_unverified", unverified?.reason)
        let unavailable = await appStore(.unavailable)
        XCTAssertEqual(true, unavailable?.isUnavailable)
        let unsupported = await appStore(.unsupported)
        XCTAssertNil(unsupported)
    }

    func testAppStore_buildWithProfile_isSkipped() async {
        let hit = await appStore(.unverified, withProfile: true)
        XCTAssertNil(hit)
    }

    // MARK: - Runner and module

    func testRunAsync_timesOut() async {
        let result = await IntegrityCheckRunner.runAsync(timeoutNs: 50_000_000) {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            return nil
        }
        XCTAssertEqual(.timedOut, result)
    }

    func testModule_storeBuildWithAllAnchors_emitsNothing() async throws {
        let config = try MobShieldConfig.make(
            expectedPackageId: "com.example.app",
            expectedTeamId: team,
            allowedDistributions: AppDistribution.store
        )
        let module = IntegrityDetectionModule(
            config: config,
            bundle: MockIntegrityBundle(bundleIdentifier: "com.example.app", bundleURL: bundleURL),
            executable: info(),
            appTransactions: MockAppTransactionProvider(result: .verified(bundleId: "com.example.app")),
            isSimulator: false,
            isiOSAppOnMac: false
        )
        let signals = await module.scan()
        XCTAssertEqual([], signals.map(\.name))
    }

    func testModule_resignedAdHocCopy_isReported() async throws {
        let config = try MobShieldConfig.make(
            expectedPackageId: "com.example.app",
            expectedTeamId: team,
            allowedDistributions: AppDistribution.store
        )
        let module = IntegrityDetectionModule(
            config: config,
            bundle: MockIntegrityBundle(
                bundleIdentifier: "com.example.app",
                bundleURL: bundleURL,
                files: [profilePath: profile(["ProvisionedDevices": ["x"]])]
            ),
            executable: info(team: "ZZZZZ99999", appId: "ZZZZZ99999.com.example.app", encrypted: false),
            appTransactions: MockAppTransactionProvider(result: .unavailable),
            isSimulator: false,
            isiOSAppOnMac: false
        )
        let names = await Set(module.scan().map(\.name))
        XCTAssertEqual([IntegritySignalDefaults.teamId, IntegritySignalDefaults.distribution], names)
    }

    // MARK: - Config

    func testConfig_teamIdValidation() throws {
        XCTAssertEqual(team, try MobShieldConfig.make(expectedTeamId: team).expectedTeamId)
        XCTAssertThrowsError(try MobShieldConfig.make(expectedTeamId: "abc"))
        XCTAssertThrowsError(try MobShieldConfig.make(expectedTeamId: "abcde12345"))
        let built = try MobShieldConfig.builder()
            .expectedTeamId(team)
            .allowedDistributions([.appStore])
            .build()
        XCTAssertEqual([.appStore], built.allowedDistributions)
    }
}
