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

final class IntegrityAnchorsTests: XCTestCase {
    private let team = "ABCDE12345"

    private func appBundle(profile: [String: Any]? = nil) throws -> (MockIntegrityBundle, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".app")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        try Data("plist".utf8).write(to: dir.appendingPathComponent("Info.plist"))
        var files: [String: Data] = [:]
        if let profile {
            let xml = try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
            files[dir.appendingPathComponent("embedded.mobileprovision").path] = xml
        }
        return (MockIntegrityBundle(bundleIdentifier: "com.example.app", bundleURL: dir, files: files), dir)
    }

    private var executable: MockExecutableProvider {
        MockExecutableProvider(info: IntegrityExecutableInfo(hasCodeSignature: true, teamIdentifier: team))
    }

    func testCurrent_storeBuild() throws {
        let (bundle, _) = try appBundle()
        let anchors = IntegrityAnchors.current(bundle: bundle, executable: executable, isSimulator: false)
        XCTAssertEqual("com.example.app", anchors.bundleIdentifier)
        XCTAssertEqual(team, anchors.teamIdentifier)
        XCTAssertEqual(.appStore, anchors.distribution)
        XCTAssertEqual([], anchors.signerCertificateDigests)
        XCTAssertEqual(SHA256Digest.hex(for: Data("plist".utf8)), anchors.resourceHashes["Info.plist"])
    }

    func testCurrent_adHocBuild() throws {
        let (bundle, _) = try appBundle(profile: ["ProvisionedDevices": ["x"]])
        XCTAssertEqual(.adHoc, IntegrityAnchors.current(bundle: bundle, executable: executable, isSimulator: false).distribution)
    }

    func testCurrent_simulatorHasNoDistribution() throws {
        let (bundle, _) = try appBundle()
        XCTAssertNil(IntegrityAnchors.current(bundle: bundle, executable: executable, isSimulator: true).distribution)
    }

    func testConfigSnippet() {
        let digest = String(repeating: "a", count: 64)
        let anchors = IntegrityAnchors(
            bundleIdentifier: "com.example.app",
            teamIdentifier: team,
            distribution: .appStore,
            signerCertificateDigests: [],
            resourceHashes: ["Info.plist": digest]
        )
        XCTAssertEqual(
            """
            MobShieldConfig.builder()
                .expectedPackageId("com.example.app")
                .expectedTeamId("\(team)")
                .allowedDistributions([.appStore])
                .expectedResourceHashes([
                    "Info.plist": "\(digest)",
                ])
                .build()
            """,
            anchors.configSnippet
        )
        XCTAssertNoThrow(try MobShieldConfig.builder()
            .expectedPackageId("com.example.app")
            .expectedTeamId(team)
            .allowedDistributions([.appStore])
            .expectedResourceHashes(["Info.plist": digest])
            .build())
    }
}
