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

/// Compares the Team ID in the main executable's code signature to `MobShieldConfig.expectedTeamId`.
/// Works for App Store builds, which keep the developer's Team ID after Apple re-signs them.
public struct TeamIdentifierCheck: Sendable {
    private let expectedTeamId: String
    private let expectedPackageId: String?
    private let executable: IntegrityExecutableProviding
    private let isSimulator: Bool

    public init(expectedTeamId: String, expectedPackageId: String?, executable: IntegrityExecutableProviding) {
        self.init(
            expectedTeamId: expectedTeamId,
            expectedPackageId: expectedPackageId,
            executable: executable,
            isSimulator: IntegrityPlatform.isSimulator
        )
    }

    init(
        expectedTeamId: String,
        expectedPackageId: String?,
        executable: IntegrityExecutableProviding,
        isSimulator: Bool
    ) {
        self.expectedTeamId = expectedTeamId
        self.expectedPackageId = expectedPackageId
        self.executable = executable
        self.isSimulator = isSimulator
    }

    public func scan() -> IntegrityScanHit? {
        guard !isSimulator else {
            return nil
        }
        guard let info = executable.executableInfo() else {
            return IntegrityScanHit(reason: "executable_unreadable", isUnavailable: true)
        }
        guard info.hasCodeSignature else {
            return IntegrityScanHit(reason: "signature_missing")
        }
        guard let teamIdentifier = info.teamIdentifier else {
            return IntegrityScanHit(
                reason: "team_id_missing",
                evidence: ["expected": expectedTeamId, "adHoc": String(info.isAdHocSigned)]
            )
        }
        if teamIdentifier != expectedTeamId {
            return IntegrityScanHit(
                reason: "team_id_mismatch",
                evidence: ["expected": expectedTeamId, "actual": teamIdentifier]
            )
        }
        if let expectedPackageId, let appId = info.applicationIdentifier,
           appId != expectedPackageId, !appId.hasSuffix("." + expectedPackageId) {
            return IntegrityScanHit(
                reason: "app_id_mismatch",
                evidence: ["expected": expectedPackageId, "applicationIdentifier": appId]
            )
        }
        return nil
    }
}
