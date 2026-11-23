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
#if canImport(MobShieldCore)
import MobShieldCore
#endif

/// Derives how the build was distributed and compares it to `MobShieldConfig.allowedDistributions`.
///
/// A build with an embedded profile is enterprise (`ProvisionsAllDevices`), development
/// (`get-task-allow`) or ad hoc. A build without one is TestFlight (sandbox receipt) or App Store.
public struct DistributionCheck: Sendable {
    private let allowed: Set<AppDistribution>
    private let bundle: IntegrityBundleProviding
    private let executable: IntegrityExecutableProviding
    private let isSimulator: Bool

    public init(
        allowed: Set<AppDistribution>,
        bundle: IntegrityBundleProviding,
        executable: IntegrityExecutableProviding
    ) {
        self.init(allowed: allowed, bundle: bundle, executable: executable, isSimulator: IntegrityPlatform.isSimulator)
    }

    init(
        allowed: Set<AppDistribution>,
        bundle: IntegrityBundleProviding,
        executable: IntegrityExecutableProviding,
        isSimulator: Bool
    ) {
        self.allowed = allowed
        self.bundle = bundle
        self.executable = executable
        self.isSimulator = isSimulator
    }

    public func scan() -> IntegrityScanHit? {
        guard !allowed.isEmpty, !isSimulator else {
            return nil
        }
        let actual: AppDistribution
        switch EmbeddedProfile.lookup(in: bundle) {
        case nil:
            return IntegrityScanHit(reason: "bundle_url_missing", isUnavailable: true)
        case .unreadable:
            return IntegrityScanHit(reason: "provisioning_profile_unreadable", isUnavailable: true)
        case .absent:
            actual = bundle.appStoreReceiptURL?.lastPathComponent == "sandboxReceipt" ? .testFlight : .appStore
        case let .present(plist):
            if ProvisioningProfileParser.provisionsAllDevices(plist) {
                actual = .enterprise
            } else if ProvisioningProfileParser.getTaskAllow(plist) {
                actual = .development
            } else {
                actual = .adHoc
            }
        }
        let allowedList = allowed.map(\.rawValue).sorted().joined(separator: ",")
        if !allowed.contains(actual) {
            return IntegrityScanHit(
                reason: "distribution_not_allowed",
                evidence: ["actual": actual.rawValue, "allowed": allowedList]
            )
        }
        if !allowed.contains(.development), executable.executableInfo()?.getTaskAllow == true {
            return IntegrityScanHit(
                reason: "get_task_allow",
                evidence: ["actual": actual.rawValue, "allowed": allowedList]
            )
        }
        return nil
    }
}
