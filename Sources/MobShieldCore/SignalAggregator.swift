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

/// Stateless pure aggregator: maps weighted ``Signal`` values to ``ThreatEvent`` list.
///
/// Score formula per threat type T:
/// `score(T) = min(100, sum(weight * confidence / 100))` for signals mapped to T.
public struct SignalAggregator: Sendable {
    private let config: MobShieldConfig

    public init(config: MobShieldConfig) {
        self.config = config
    }

    public func aggregate(signals: [Signal]) -> [ThreatEvent] {
        guard !signals.isEmpty else {
            return []
        }

        var grouped: [ThreatType: [Signal]] = [:]
        for signal in signals {
            guard let type = Self.resolveThreatType(signalName: signal.name) else {
                continue
            }
            if !config.allowDeveloperSignals,
               type == .developerMode || type == .adbEnabled {
                continue
            }
            grouped[type, default: []].append(signal)
        }

        let now = Int64(Date().timeIntervalSince1970 * 1000)
        var events: [ThreatEvent] = []
        for (type, typeSignals) in grouped {
            let score = computeScore(signals: typeSignals)
            if score <= 0 {
                continue
            }
            let threshold = config.thresholds[type] ?? DefaultThreatThresholds.map[type]!
            let severity = mapSeverity(type: type, score: score, threshold: threshold)
            if severity == .info, score < threshold.warning / 2 {
                continue
            }
            let names = typeSignals.map(\.name)
            let metadata = mergeEvidence(signals: typeSignals)
            events.append(
                ThreatEvent.create(
                    type: type,
                    severity: severity,
                    signals: names,
                    score: score,
                    timestampMs: now,
                    metadata: metadata
                )
            )
        }
        return events.sorted { $0.score > $1.score }
    }

    /// Threat types for which at least one of `signals`, scored as the only signal of its type,
    /// reaches `.high`. Termination requires this, so that several weak hints that only add up to
    /// HIGH or CRITICAL report a threat but never end the process. See `docs/termination.md`.
    func typesWithStrongSignal(signals: [Signal]) -> Set<ThreatType> {
        var types = Set<ThreatType>()
        for signal in signals where aggregate(signals: [signal]).contains(where: { $0.severity >= .high }) {
            if let type = Self.resolveThreatType(signalName: signal.name) {
                types.insert(type)
            }
        }
        return types
    }

    private func computeScore(signals: [Signal]) -> Int {
        Self.scoreOf(signals: signals, groups: config.signalGroups)
    }

    /// Full scale (100 points) in hundredths of a point.
    private static let fullScale = 10_000
    private static let hundredthsPerPoint = 100
    private static let maxScore = 100

    /// Scores signals that already belong to one threat type.
    ///
    /// Each signal contributes `weight * confidence / 100` points. Signals that share a correlation
    /// group are combined with noisy-OR, `100 * (1 - prod(1 - c / 100))`, so one artifact seen by
    /// several checks is not counted several times; a group is never below its strongest member nor
    /// above their sum. Groups and ungrouped signals are added, capped at 100 and truncated.
    /// Arithmetic is in integer hundredths of a point, so results are exact and match Android.
    public static func scoreOf(signals: [Signal], groups: [String: String]) -> Int {
        var hundredths = 0
        var grouped: [String: [Int]] = [:]
        for signal in signals {
            let contribution = signal.weight * signal.confidence
            if let group = groups[signal.name] {
                grouped[group, default: []].append(contribution)
            } else {
                hundredths += contribution
            }
        }
        for contributions in grouped.values {
            hundredths += combineCorrelated(contributions)
        }
        return min(maxScore, max(0, hundredths / hundredthsPerPoint))
    }

    /// Noisy-OR of contributions given in hundredths of a point (0...10 000). The running complement
    /// is rounded up at each step, so the combined value is never overstated, and a single
    /// contribution is returned unchanged.
    static func combineCorrelated(_ contributions: [Int]) -> Int {
        var complement = fullScale
        for contribution in contributions.sorted(by: >) {
            let remaining = fullScale - min(fullScale, max(0, contribution))
            complement = ceilDiv(complement * remaining, fullScale)
        }
        return fullScale - complement
    }

    private static func ceilDiv(_ numerator: Int, _ denominator: Int) -> Int {
        (numerator + denominator - 1) / denominator
    }

    private func mapSeverity(type: ThreatType, score: Int, threshold: ThreatThreshold) -> Severity {
        let criticalCap = threshold.critical == nil
        if criticalCap, Self.informationalTypes.contains(type) {
            if score < threshold.warning {
                return .info
            }
            return .high
        }

        if let critical = threshold.critical, score >= critical {
            return .critical
        }
        if score >= threshold.warning {
            return .high
        }
        if score >= threshold.warning / 2 {
            return .medium
        }
        if score >= threshold.warning / 4 {
            return .low
        }
        return .info
    }

    private func mergeEvidence(signals: [Signal]) -> [String: String] {
        var merged: [String: String] = [:]
        for signal in signals {
            for (key, value) in signal.evidence {
                merged["\(signal.name).\(key)"] = value
            }
        }
        return merged
    }

    private static let informationalTypes: Set<ThreatType> = [.developerMode, .adbEnabled]

    public static func resolveThreatType(signalName: String) -> ThreatType? {
        let name = signalName.lowercased()
        if name.hasPrefix("android.root.") || name.hasPrefix("ios.jb.") {
            return .privilegedAccess
        }
        if name.contains(".hook.") || name.hasPrefix("common.hook.") {
            return .hookFramework
        }
        if name.hasPrefix("android.debug.") || name.hasPrefix("ios.debug.") {
            return .debugger
        }
        if name.hasPrefix("android.env.") || name.hasPrefix("ios.env.") {
            return .emulator
        }
        if name.hasPrefix("android.automation.") || name.hasPrefix("ios.automation.") {
            return .automation
        }
        if name.hasPrefix("android.integrity.") || name.hasPrefix("ios.integrity.") {
            return .appIntegrity
        }
        if name.hasPrefix("android.store.") || name.hasPrefix("ios.store.") {
            return .unofficialStore
        }
        if name.hasPrefix("android.dev.") || name.hasSuffix(".developer_mode") {
            return .developerMode
        }
        if name.hasPrefix("android.adb.") || name.hasSuffix(".adb_enabled") {
            return .adbEnabled
        }
        return nil
    }
}
