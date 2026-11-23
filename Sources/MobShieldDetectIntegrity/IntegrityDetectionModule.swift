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

/// App signature, bundle ID, provisioning, resource, and receipt integrity checks.
public struct IntegrityDetectionModule: DetectionModule {
    private struct Check: Sendable {
        let name: String
        let signalName: String
        let timeoutNs: UInt64
        let scan: @Sendable () -> IntegrityScanHit?
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
        secCode: IntegritySecCodeProviding = LiveSecCodeProvider()
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
                scan: check.scan
            ))
        }
        if let expectedPackageId = config.expectedPackageId {
            let check = BundleIdentifierCheck(expectedPackageId: expectedPackageId, bundle: bundle)
            checks.append(Check(
                name: "bundle_id",
                signalName: IntegritySignalDefaults.bundleId,
                timeoutNs: scanTimeoutNs,
                scan: check.scan
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
            scan: provisioningCheck.scan
        ))
        if !config.expectedResourceHashes.isEmpty {
            let check = ResourceIntegrityCheck(expectedHashes: config.expectedResourceHashes, bundle: bundle)
            checks.append(Check(
                name: "resource",
                signalName: IntegritySignalDefaults.resource,
                timeoutNs: digestTimeoutNs,
                scan: check.scan
            ))
        }
        let receiptCheck = AppStoreReceiptCheck(bundle: bundle)
        checks.append(Check(
            name: "receipt",
            signalName: IntegritySignalDefaults.receipt,
            timeoutNs: scanTimeoutNs,
            scan: receiptCheck.scan
        ))
        self.checks = checks
    }

    public func scan() async -> [Signal] {
        let results = await withTaskGroup(of: (Check, IntegrityCheckResult).self) { group in
            for check in checks {
                group.addTask { (check, await IntegrityCheckRunner.run(timeoutNs: check.timeoutNs, check.scan)) }
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
