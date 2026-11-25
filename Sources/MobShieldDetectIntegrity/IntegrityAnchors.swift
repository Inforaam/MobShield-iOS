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

/// The integrity values of the running app, for filling in `MobShieldConfig`.
///
/// Read them from a build installed the way users get it, for example from TestFlight. App Store and
/// TestFlight builds keep your Team ID and bundle ID, but have no embedded profile, so
/// `signerCertificateDigests` is empty for them.
public struct IntegrityAnchors: Sendable, Equatable {
    public let bundleIdentifier: String?
    public let teamIdentifier: String?
    /// Nil in the Simulator or when the embedded profile cannot be read.
    public let distribution: AppDistribution?
    /// SHA-256 of the certificates in `embedded.mobileprovision`, for `expectedSigners`.
    public let signerCertificateDigests: [String]
    /// SHA-256 of `Info.plist` and the main storyboard's `Info.plist`, for `expectedResourceHashes`.
    public let resourceHashes: [String: String]

    public init(
        bundleIdentifier: String?,
        teamIdentifier: String?,
        distribution: AppDistribution?,
        signerCertificateDigests: [String],
        resourceHashes: [String: String]
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.distribution = distribution
        self.signerCertificateDigests = signerCertificateDigests
        self.resourceHashes = resourceHashes
    }

    public static func current(
        bundle: IntegrityBundleProviding = LiveIntegrityBundleProvider(),
        executable: IntegrityExecutableProviding = LiveExecutableProvider()
    ) -> IntegrityAnchors {
        current(bundle: bundle, executable: executable, isSimulator: IntegrityPlatform.isSimulator)
    }

    static func current(
        bundle: IntegrityBundleProviding,
        executable: IntegrityExecutableProviding,
        isSimulator: Bool
    ) -> IntegrityAnchors {
        var resourceHashes: [String: String] = [:]
        if let bundleURL = bundle.bundleURL {
            for path in ResourceIntegrityCheck.curatedResourcePaths(bundle: bundle) {
                if let digest = SHA256Digest.hex(forFileAt: bundleURL.appendingPathComponent(path)) {
                    resourceHashes[path] = digest
                }
            }
        }
        var distribution: AppDistribution?
        if !isSimulator, case let .success(resolved) = DistributionCheck.resolve(bundle: bundle) {
            distribution = resolved
        }
        let signers = (try? LiveSecCodeProvider(bundle: bundle).copySigningInfo().certificateDigests) ?? []
        return IntegrityAnchors(
            bundleIdentifier: bundle.bundleIdentifier,
            teamIdentifier: executable.executableInfo()?.teamIdentifier,
            distribution: distribution,
            signerCertificateDigests: signers,
            resourceHashes: resourceHashes
        )
    }

    /// A `MobShieldConfig.builder()` snippet with these values.
    public var configSnippet: String {
        var lines = ["MobShieldConfig.builder()"]
        if let bundleIdentifier {
            lines.append("    .expectedPackageId(\"\(bundleIdentifier)\")")
        }
        if let teamIdentifier {
            lines.append("    .expectedTeamId(\"\(teamIdentifier)\")")
        }
        if let distribution {
            lines.append("    .allowedDistributions([.\(distribution.rawValue)])")
        }
        if !signerCertificateDigests.isEmpty {
            let list = signerCertificateDigests.map { "\"\($0)\"" }.joined(separator: ", ")
            lines.append("    .expectedSigners([\(list)])")
        }
        if !resourceHashes.isEmpty {
            lines.append("    .expectedResourceHashes([")
            for (path, digest) in resourceHashes.sorted(by: { $0.key < $1.key }) {
                lines.append("        \"\(path)\": \"\(digest)\",")
            }
            lines.append("    ])")
        }
        lines.append("    .build()")
        return lines.joined(separator: "\n")
    }
}
