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

import XCTest
@testable import MobShieldCore

/// Termination needs corroboration: an event ends the process only if one of its signals reaches
/// HIGH on its own, and only if its type is in `MobShieldConfig.terminateOn`. Mirrors the Android
/// `TerminationTest` with the same signals, so both platforms are held to the same rule.
/// See `docs/termination.md`.
final class TerminationTests: XCTestCase {
    // Three weak root hints: 38 + 8 + 6 = 53, which is HIGH, but none is HIGH on its own.
    private let packages = Signal(name: "android.root.dangerous_packages", weight: 55, confidence: 70)
    private let pathProbe = Signal(name: "android.root.path_probe", weight: 25, confidence: 35)
    private let props = Signal(name: "android.root.props", weight: 20, confidence: 30)

    // Strong root signals: each is HIGH on its own (63 and 56); together they are CRITICAL.
    private let mountNamespace = Signal(name: "android.root.mount_namespace", weight: 75, confidence: 85)
    private let magiskSocket = Signal(name: "android.root.magisk_uds", weight: 70, confidence: 80)

    // CRITICAL on its own (72).
    private let prologue = Signal(name: "common.hook.prologue", weight: 80, confidence: 90)

    private let bypass = MobShieldConfig(detectOnly: false, terminationPolicy: .exitOnBypass)
    private let critical = MobShieldConfig(detectOnly: false, terminationPolicy: .exitOnCritical)

    private var allButRoot: Set<ThreatType> {
        var types = Set(ThreatType.allCases)
        types.remove(.privilegedAccess)
        return types
    }

    func testWeakRootHints_reachHigh_butDoNotTerminate() async {
        let run = await scan(bypass, [packages, pathProbe, props])

        XCTAssertEqual(0, run.terminated)
        XCTAssertEqual(1, run.listener.events.count)
        XCTAssertEqual(.privilegedAccess, run.listener.events.first?.type)
        XCTAssertEqual(53, run.listener.events.first?.score)
        XCTAssertEqual(.high, run.listener.events.first?.severity)
    }

    func testWeakHints_reachCritical_butDoNotTerminate() async {
        let weak = (1...4).map { Signal(name: "android.root.weak_\($0)", weight: 20, confidence: 100) }
        let run = await scan(critical, weak)

        XCTAssertEqual(0, run.terminated)
        XCTAssertEqual(.critical, run.listener.events.first?.severity)
    }

    func testWeakHints_plusOneStrongSignal_terminate() async {
        let run = await scan(bypass, [packages, pathProbe, props, mountNamespace])

        XCTAssertEqual(1, run.terminated)
    }

    func testTwoStrongRootSignals_terminateOnCritical() async {
        let run = await scan(critical, [mountNamespace, magiskSocket])

        XCTAssertEqual(1, run.terminated)
        XCTAssertEqual(.critical, run.listener.events.first?.severity)
    }

    func testStrongSignalOfAnotherType_doesNotCorroborate() async {
        let config = MobShieldConfig(
            detectOnly: false,
            terminationPolicy: .exitOnBypass,
            terminateOn: [.privilegedAccess]
        )
        let run = await scan(config, [packages, pathProbe, props, prologue])

        // The hook is strong but not allowed to terminate; the root event has no strong signal.
        XCTAssertEqual(0, run.terminated)
        XCTAssertEqual(2, run.listener.events.count)
    }

    func testTypeLeftOutOfTerminateOn_isReportedButNeverTerminates() async {
        let config = MobShieldConfig(detectOnly: false, terminationPolicy: .exitOnCritical, terminateOn: allButRoot)
        let run = await scan(config, [mountNamespace, magiskSocket])

        XCTAssertEqual(0, run.terminated)
        XCTAssertEqual(.critical, run.listener.events.first?.severity)
    }

    func testHookTerminatesWhenRootIsExcluded() async {
        let config = MobShieldConfig(detectOnly: false, terminationPolicy: .exitOnCritical, terminateOn: allButRoot)
        let run = await scan(config, [mountNamespace, magiskSocket, prologue])

        XCTAssertEqual(1, run.terminated)
    }

    func testNativeSelfCheckFailure_terminatesOnCritical() async {
        let run = await scan(critical, [], selfCheck: { 0 })

        XCTAssertEqual(1, run.terminated)
        XCTAssertEqual(.appIntegrity, run.listener.events.first?.type)
    }

    func testTerminateOn_defaultsToEveryType() throws {
        XCTAssertEqual(Set(ThreatType.allCases), MobShieldConfig().terminateOn)
        XCTAssertEqual(Set(ThreatType.allCases), try MobShieldConfig.make().terminateOn)
        XCTAssertEqual(Set(ThreatType.allCases), try MobShieldConfig.builder().build().terminateOn)
    }

    func testBuilder_setsTerminateOnAndSignalGroups() throws {
        let built = try MobShieldConfig.builder()
            .terminateOn([.hookFramework])
            .signalGroups([:])
            .build()

        XCTAssertEqual([.hookFramework], built.terminateOn)
        XCTAssertTrue(built.signalGroups.isEmpty)
    }

    func testTypesWithStrongSignal_usesEachSignalAlone() {
        let aggregator = SignalAggregator(config: MobShieldConfig())

        XCTAssertTrue(aggregator.typesWithStrongSignal(signals: [packages, pathProbe, props]).isEmpty)
        XCTAssertEqual(
            [.privilegedAccess, .hookFramework],
            aggregator.typesWithStrongSignal(signals: [packages, mountNamespace, prologue])
        )
    }

    // MARK: - Helpers

    private struct FixedModule: DetectionModule {
        let name = "fixed-signals"
        let criticality = 10
        let signals: [Signal]

        func scan() async -> [Signal] {
            signals
        }
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0

        var value: Int {
            lock.lock()
            defer { lock.unlock() }
            return count
        }

        func increment() {
            lock.lock()
            count += 1
            lock.unlock()
        }
    }

    private final class RecordingListener: MobShieldListener, @unchecked Sendable {
        private let lock = NSLock()
        private var received: [ThreatEvent] = []
        private var finishedWaves = 0

        var events: [ThreatEvent] {
            lock.lock()
            defer { lock.unlock() }
            return received
        }

        var finishedCount: Int {
            lock.lock()
            defer { lock.unlock() }
            return finishedWaves
        }

        func onThreat(_ event: ThreatEvent) {
            lock.lock()
            received.append(event)
            lock.unlock()
        }

        func onAllChecksFinished(_ events: [ThreatEvent]) {
            lock.lock()
            finishedWaves += 1
            lock.unlock()
        }
    }

    private func scan(
        _ config: MobShieldConfig,
        _ signals: [Signal],
        selfCheck: @escaping @Sendable () -> Int = { 1 }
    ) async -> (listener: RecordingListener, terminated: Int) {
        let listener = RecordingListener()
        let counter = Counter()
        let module = FixedModule(signals: signals)
        let engine = MobShieldEngine(
            config: config,
            listener: listener,
            resolveModules: { [module] },
            signalSetVersion: MobShield.signalSetVersion,
            terminate: { counter.increment() },
            selfCheck: selfCheck
        )
        engine.start()
        // The termination decision follows onAllChecksFinished in the same task; wait for the wave,
        // then give that task time to finish.
        for _ in 0..<100 where listener.finishedCount == 0 {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        try? await Task.sleep(nanoseconds: 100_000_000)
        engine.stop()
        return (listener, counter.value)
    }
}
