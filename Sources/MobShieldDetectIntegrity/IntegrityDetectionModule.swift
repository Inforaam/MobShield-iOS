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

/// App signature, Team ID, bundle ID, provisioning, distribution, encryption, resource, and App Store
/// integrity checks.
public struct IntegrityDetectionModule: DetectionModule {
    private struct Check: Sendable {
        let name: String
        let signalName: String
        let run: @Sendable () async -> IntegrityCheckResult

        init(name: String, signalName: String, timeoutNs: UInt64, scan: @escaping @Sendable () -> IntegrityScanHit?) {
            self.name = name
            self.signalName = signalName
            run = { await IntegrityCheckRunner.run(timeoutNs: timeoutNs, scan) }
        }

        init(
            name: String,
            signalName: String,
            timeoutNs: UInt64,
            asyncScan: @escaping @Sendable () async -> IntegrityScanHit?
        ) {
            self.name = name
            self.signalName = signalName
            run = { await IntegrityCheckRunner.runAsync(timeoutNs: timeoutNs, asyncScan) }
        }
    }

    private let detectionTuning: [String: SignalTuning]
    private let checks: [Check]

    public let name = "integrity"
    public let criticality = 100

    public init(
        config: MobShieldConfig = MobShieldConfig(),
        detectionTuning: [String: SignalTuning]? = nil,
        scanTimeoutMs: Int = 500,
        digestTimeoutMs: Int = 5_000,
        bundle: IntegrityBundleProviding = LiveIntegrityBundleProvider(),
        secCode: IntegritySecCodeProviding = LiveSecCodeProvider(),
        executable: IntegrityExecutableProviding = LiveExecutableProvider(),
        appTransactions: IntegrityAppTransactionProviding = LiveAppTransactionProvider()
    ) {
        self.init(
            config: config,
            detectionTuning: detectionTuning,
            scanTimeoutMs: scanTimeoutMs,
            digestTimeoutMs: digestTimeoutMs,
            bundle: bundle,
            secCode: secCode,
            executable: executable,
            appTransactions: appTransactions,
            isSimulator: IntegrityPlatform.isSimulator,
            isiOSAppOnMac: IntegrityPlatform.isiOSAppOnMac
        )
    }

    init(
        config: MobShieldConfig,
        detectionTuning: [String: SignalTuning]? = nil,
        scanTimeoutMs: Int = 500,
        digestTimeoutMs: Int = 5_000,
        bundle: IntegrityBundleProviding,
        secCode: IntegritySecCodeProviding = LiveSecCodeProvider(),
        executable: IntegrityExecutableProviding = LiveExecutableProvider(),
        appTransactions: IntegrityAppTransactionProviding = LiveAppTransactionProvider(),
        isSimulator: Bool,
        isiOSAppOnMac: Bool
    ) {
        self.detectionTuning = detectionTuning ?? config.detectionTuning
        let scanTimeoutNs = UInt64(max(scanTimeoutMs, 0)) * 1_000_000
        let digestTimeoutNs = UInt64(max(digestTimeoutMs, 0)) * 1_000_000

        var checks: [Check] = []
        if !config.expectedSigners.isEmpty {
            let check = CodeSignatureCheck(expectedSigners: config.expectedSigners, secCode: secCode)
            checks.append(Check(
                name: "sec_code",
                signalName: IntegritySignalDefaults.secCode,
                timeoutNs: scanTimeoutNs,
                scan: { check.scan() }
            ))
        }
        checks += Self.codeSignatureChecks(
            config: config,
            bundle: bundle,
            executable: executable,
            timeoutNs: scanTimeoutNs,
            platform: (isSimulator: isSimulator, isiOSAppOnMac: isiOSAppOnMac)
        )
        if let expectedPackageId = config.expectedPackageId {
            let check = BundleIdentifierCheck(expectedPackageId: expectedPackageId, bundle: bundle)
            checks.append(Check(
                name: "bundle_id",
                signalName: IntegritySignalDefaults.bundleId,
                timeoutNs: scanTimeoutNs,
                scan: { check.scan() }
            ))
        }
        let provisioningCheck = EmbeddedProvisioningProfileCheck(
            expectedPackageId: config.expectedPackageId,
            bundle: bundle
        )
        checks.append(Check(
            name: "provisioning",
            signalName: IntegritySignalDefaults.provisioning,
            timeoutNs: scanTimeoutNs,
            scan: { provisioningCheck.scan() }
        ))
        if !config.expectedResourceHashes.isEmpty {
            let check = ResourceIntegrityCheck(expectedHashes: config.expectedResourceHashes, bundle: bundle)
            checks.append(Check(
                name: "resource",
                signalName: IntegritySignalDefaults.resource,
                timeoutNs: digestTimeoutNs,
                scan: { check.scan() }
            ))
        }
        let appStoreCheck = AppStoreVerificationCheck(
            bundle: bundle,
            transactions: appTransactions,
            isSimulator: isSimulator
        )
        checks.append(Check(
            name: "receipt",
            signalName: IntegritySignalDefaults.receipt,
            timeoutNs: digestTimeoutNs,
            asyncScan: { await appStoreCheck.scan() }
        ))
        self.checks = checks
    }

    /// Team ID, distribution and encryption checks, which read the executable's code signature.
    private static func codeSignatureChecks(
        config: MobShieldConfig,
        bundle: IntegrityBundleProviding,
        executable: IntegrityExecutableProviding,
        timeoutNs: UInt64,
        platform: (isSimulator: Bool, isiOSAppOnMac: Bool)
    ) -> [Check] {
        var checks: [Check] = []
        if let expectedTeamId = config.expectedTeamId {
            let check = TeamIdentifierCheck(
                expectedTeamId: expectedTeamId,
                expectedPackageId: config.expectedPackageId,
                executable: executable,
                isSimulator: platform.isSimulator
            )
            checks.append(Check(
                name: "team_id",
                signalName: IntegritySignalDefaults.teamId,
                timeoutNs: timeoutNs,
                scan: { check.scan() }
            ))
        }
        if !config.allowedDistributions.isEmpty {
            let distributionCheck = DistributionCheck(
                allowed: config.allowedDistributions,
                bundle: bundle,
                executable: executable,
                isSimulator: platform.isSimulator
            )
            checks.append(Check(
                name: "distribution",
                signalName: IntegritySignalDefaults.distribution,
                timeoutNs: timeoutNs,
                scan: { distributionCheck.scan() }
            ))
            let encryptionCheck = BinaryEncryptionCheck(
                allowed: config.allowedDistributions,
                bundle: bundle,
                executable: executable,
                isSimulator: platform.isSimulator,
                isiOSAppOnMac: platform.isiOSAppOnMac
            )
            checks.append(Check(
                name: "encryption",
                signalName: IntegritySignalDefaults.encryption,
                timeoutNs: timeoutNs,
                scan: { encryptionCheck.scan() }
            ))
        }
        return checks
    }

    public func scan() async -> [Signal] {
        let results = await withTaskGroup(of: (Check, IntegrityCheckResult).self) { group in
            for check in checks {
                group.addTask { (check, await check.run()) }
            }
            var results: [(Check, IntegrityCheckResult)] = []
            for await result in group {
                results.append(result)
            }
            return results
        }

        var signals: [Signal] = []
        var unavailable: [String] = []
        for (check, result) in results {
            switch result {
            case .timedOut:
                unavailable.append("\(check.name):timeout")
            case .finished(nil):
                continue
            case let .finished(hit?) where hit.isUnavailable:
                unavailable.append("\(check.name):\(hit.reason)")
            case let .finished(hit?):
                var evidence = hit.evidence
                evidence["reason"] = hit.reason
                signals.append(IntegritySignalDefaults.buildSignal(
                    name: check.signalName,
                    evidence: evidence,
                    tuning: detectionTuning
                ))
            }
        }
        if !unavailable.isEmpty {
            signals.append(IntegritySignalDefaults.buildSignal(
                name: IntegritySignalDefaults.checkUnavailable,
                evidence: ["checks": unavailable.sorted().joined(separator: ",")],
                tuning: detectionTuning
            ))
        }
        return signals
    }
}
