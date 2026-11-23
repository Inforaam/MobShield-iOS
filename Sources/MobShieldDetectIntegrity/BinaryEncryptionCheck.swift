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

/// Checks that the main executable is still encrypted when the build presents itself as an App Store
/// or TestFlight build (no embedded profile) and only those channels are allowed.
public struct BinaryEncryptionCheck: Sendable {
    private let allowed: Set<AppDistribution>
    private let bundle: IntegrityBundleProviding
    private let executable: IntegrityExecutableProviding
    private let isSimulator: Bool
    private let isiOSAppOnMac: Bool

    public init(
        allowed: Set<AppDistribution>,
        bundle: IntegrityBundleProviding,
        executable: IntegrityExecutableProviding
    ) {
        self.init(
            allowed: allowed,
            bundle: bundle,
            executable: executable,
            isSimulator: IntegrityPlatform.isSimulator,
            isiOSAppOnMac: IntegrityPlatform.isiOSAppOnMac
        )
    }

    init(
        allowed: Set<AppDistribution>,
        bundle: IntegrityBundleProviding,
        executable: IntegrityExecutableProviding,
        isSimulator: Bool,
        isiOSAppOnMac: Bool
    ) {
        self.allowed = allowed
        self.bundle = bundle
        self.executable = executable
        self.isSimulator = isSimulator
        self.isiOSAppOnMac = isiOSAppOnMac
    }

    public func scan() -> IntegrityScanHit? {
        guard !allowed.isEmpty, allowed.isSubset(of: AppDistribution.store), !isSimulator, !isiOSAppOnMac else {
            return nil
        }
        guard case .absent = EmbeddedProfile.lookup(in: bundle) else {
            return nil
        }
        guard let info = executable.executableInfo() else {
            return IntegrityScanHit(reason: "executable_unreadable", isUnavailable: true)
        }
        switch info.isEncrypted {
        case true?:
            return nil
        case false?:
            return IntegrityScanHit(reason: "binary_not_encrypted")
        case nil:
            return IntegrityScanHit(reason: "encryption_info_missing")
        }
    }
}
