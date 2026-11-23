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
import XCTest
@testable import MobShieldCore

final class UnknownSignalWarningTests: XCTestCase {
    func testUnknownSignalNames_keepsOnlyNamesWithoutThreatType() {
        let names = ["ios.jb.cydia", "custom.jb.check", "com.example.hook.x", "custom.jb.check"]
        XCTAssertEqual(["custom.jb.check"], MobShieldEngine.unknownSignalNames(names))
    }

    func testUnknownSignal_isWarnedOnceAcrossScans() async {
        let warnings = WarningRecorder()
        let engine = makeEngine(
            config: MobShieldConfig(),
            signals: [Signal(name: "custom.jb.check", weight: 90, confidence: 100)],
            warnings: warnings,
            intervalNanos: 50_000_000
        )

        engine.start()
        try? await Task.sleep(nanoseconds: 300_000_000)
        engine.stop()

        XCTAssertEqual(1, warnings.messages.count)
        XCTAssertTrue(warnings.messages.first?.contains("\"custom.jb.check\"") ?? false)
    }

    func testKnownSignal_isNotWarned() async {
        let warnings = WarningRecorder()
        let engine = makeEngine(
            config: MobShieldConfig(),
            signals: [Signal(name: "ios.jb.custom", weight: 90, confidence: 100)],
            warnings: warnings
        )

        engine.start()
        try? await Task.sleep(nanoseconds: 200_000_000)
        engine.stop()

        XCTAssertTrue(warnings.messages.isEmpty)
    }

    func testUnknownConfigKeys_areWarnedAtStart() {
        let warnings = WarningRecorder()
        let config = MobShieldConfig(
            detectionTuning: ["ios.jailbreak.cydia": SignalTuning(weight: 5, confidence: 5)],
            signalGroups: ["custom.jb.check": "custom"]
        )
        let engine = makeEngine(config: config, signals: [], warnings: warnings)

        engine.start()
        engine.stop()

        let messages = warnings.messages
        XCTAssertEqual(2, messages.count)
        XCTAssertTrue(messages.first?.hasPrefix("detectionTuning") ?? false)
        XCTAssertTrue(messages.first?.contains("\"ios.jailbreak.cydia\"") ?? false)
        XCTAssertTrue(messages.last?.hasPrefix("signalGroups") ?? false)
    }

    func testDefaultThresholds_areUnchanged() throws {
        XCTAssertEqual(try ThreatThreshold(warning: 40, critical: 70), DefaultThreatThresholds.map[.privilegedAccess])
        XCTAssertEqual(try ThreatThreshold(warning: 15, critical: nil), DefaultThreatThresholds.map[.adbEnabled])
        XCTAssertEqual(ThreatType.allCases.count, DefaultThreatThresholds.map.count)
    }

    private func makeEngine(
        config: MobShieldConfig,
        signals: [Signal],
        warnings: WarningRecorder,
        intervalNanos: UInt64? = nil
    ) -> MobShieldEngine {
        let module = FixedSignalsModule(signals: signals)
        return MobShieldEngine(
            config: config,
            listener: SilentListener(),
            resolveModules: { [module] },
            signalSetVersion: MobShield.signalSetVersion,
            periodicIntervalOverrideNanos: intervalNanos,
            selfCheck: { 1 },
            warn: { warnings.record($0) }
        )
    }

    private struct FixedSignalsModule: DetectionModule {
        let signals: [Signal]
        let name = "custom"
        let criticality = 10

        func scan() async -> [Signal] {
            signals
        }
    }

    private final class SilentListener: MobShieldListener, @unchecked Sendable {
        func onThreat(_ event: ThreatEvent) {}
        func onAllChecksFinished(_ events: [ThreatEvent]) {}
    }

    private final class WarningRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: [String] = []

        var messages: [String] {
            lock.lock(); defer { lock.unlock() }
            return stored
        }

        func record(_ message: String) {
            lock.lock(); defer { lock.unlock() }
            stored.append(message)
        }
    }
}
