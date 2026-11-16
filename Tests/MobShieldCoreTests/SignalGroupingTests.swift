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

final class SignalGroupingTests: XCTestCase {
    private let grouped = MobShieldConfig()
    private let ungrouped = MobShieldConfig(signalGroups: [:])

    private func signal(_ name: String, _ weight: Int, _ confidence: Int) -> Signal {
        Signal(name: name, weight: weight, confidence: confidence, timestampMs: 1)
    }

    private func score(_ config: MobShieldConfig, _ signals: [Signal]) -> Int? {
        let events = SignalAggregator(config: config).aggregate(signals: signals)
        XCTAssertEqual(1, events.count)
        return events.first?.score
    }

    func testSingleSignal_scoreUnchangedByGrouping() {
        let port = signal("android.hook.frida_port", 85, 95)
        XCTAssertEqual(80, score(grouped, [port]))
        XCTAssertEqual(80, score(ungrouped, [port]))
    }

    func testFridaMapsAndThreads_combineWithDiminishingReturns() {
        let signals = [signal("common.hook.frida_maps", 75, 85), signal("android.hook.thread_name", 70, 80)]
        XCTAssertEqual(100, score(ungrouped, signals))
        XCTAssertEqual(84, score(grouped, signals))
    }

    func testSameMapsFileReadTwice_isNotCountedTwice() {
        let signals = [signal("common.hook.frida_maps", 75, 85), signal("android.hook.suspicious_library", 55, 65)]
        XCTAssertEqual(99, score(ungrouped, signals))
        XCTAssertEqual(76, score(grouped, signals))
    }

    func testDifferentGroups_stillAdd() {
        let signals = [signal("common.hook.frida_maps", 75, 85), signal("android.hook.xposed", 70, 80)]
        XCTAssertEqual(100, score(grouped, signals))
    }

    func testUngroupedSignals_addAsBefore() {
        let events = SignalAggregator(config: grouped).aggregate(signals: [
            signal("android.root.path_probe", 25, 35),
            signal("android.root.props", 20, 30),
            signal("android.root.dangerous_packages", 55, 70),
        ])
        XCTAssertEqual(53, events.first?.score)
        XCTAssertEqual(.high, events.first?.severity)
    }

    func testRootMountPair_staysCritical() {
        let events = SignalAggregator(config: grouped).aggregate(signals: [
            signal("android.root.mount_namespace", 75, 85),
            signal("android.root.overlayfs", 65, 75),
        ])
        XCTAssertEqual(81, events.first?.score)
        XCTAssertEqual(.critical, events.first?.severity)
    }

    func testTracerPair_combined() {
        let signals = [signal("android.debug.tracerpid", 85, 90), signal("android.debug.ptrace", 80, 85)]
        XCTAssertEqual(92, score(grouped, signals))
    }

    func testIosDyldImagePair_combined() {
        let signals = [signal("ios.jb.dyld_image", 80, 85), signal("ios.jb.dyld_header", 75, 85)]
        XCTAssertEqual(100, score(ungrouped, signals))
        XCTAssertEqual(88, score(grouped, signals))
    }

    func testIosFridaThreeChecks_combined() {
        let signals = [
            signal("ios.hook.frida_thread", 80, 90),
            signal("ios.hook.frida_symbols", 80, 90),
            signal("common.hook.frida_maps", 75, 85),
        ]
        XCTAssertEqual(97, score(grouped, signals))
    }

    func testGroupIsBetweenStrongestMemberAndSum() {
        let cases: [[(Int, Int)]] = [
            [(10, 100), (10, 100)],
            [(50, 100), (50, 100)],
            [(75, 85), (70, 80), (55, 65)],
            [(25, 35), (60, 70)],
            [(100, 100), (30, 30)],
        ]
        for testCase in cases {
            let signals = testCase.enumerated().map { index, pair in
                signal(index == 0 ? "common.hook.frida_maps" : "android.hook.thread_name", pair.0, pair.1)
            }
            let strongest = testCase.map { $0.0 * $0.1 / 100 }.max() ?? 0
            let sum = min(100, testCase.map { $0.0 * $0.1 }.reduce(0, +) / 100)
            let combined = SignalAggregator.scoreOf(signals: signals, groups: DefaultSignalGroups.map)
            XCTAssertGreaterThanOrEqual(combined, strongest, "\(testCase)")
            XCTAssertLessThanOrEqual(combined, sum, "\(testCase)")
        }
    }

    func testSignalOrder_doesNotChangeScore() {
        let signals = [
            signal("common.hook.frida_maps", 75, 85),
            signal("common.hook.prologue", 80, 90),
            signal("android.hook.frida_port", 85, 95),
            signal("android.hook.thread_name", 70, 80),
            signal("android.hook.suspicious_library", 55, 65),
        ]
        let forward = SignalAggregator.scoreOf(signals: signals, groups: DefaultSignalGroups.map)
        let backward = SignalAggregator.scoreOf(signals: signals.reversed(), groups: DefaultSignalGroups.map)
        XCTAssertEqual(99, forward)
        XCTAssertEqual(forward, backward)
    }

    func testIntegerArithmetic_isExactAtThresholds() {
        // 50 x 60 / 100 = 30 exactly; floating point could produce 29.999... and truncate to 29.
        XCTAssertEqual(30, SignalAggregator.scoreOf(signals: [signal("ios.debug.timing", 50, 60)], groups: [:]))
        XCTAssertEqual(
            40,
            SignalAggregator.scoreOf(signals: [signal("common.hook.frida_maps", 40, 100)], groups: DefaultSignalGroups.map)
        )
    }

    func testCustomGroups_override() {
        let config = MobShieldConfig(signalGroups: ["android.root.props": "mine", "android.root.path_probe": "mine"])
        let signals = [signal("android.root.path_probe", 50, 100), signal("android.root.props", 50, 100)]
        XCTAssertEqual(75, score(config, signals))
    }

    func testDefaultConfig_usesDefaultGroups() {
        XCTAssertEqual(DefaultSignalGroups.map, MobShieldConfig().signalGroups)
        XCTAssertTrue(try MobShieldConfig.make(signalGroups: [:]).signalGroups.isEmpty)
    }

    func testDefaultGroups_matchAndroidTable() {
        // The same table ships in the Android library; keep the two in sync.
        XCTAssertEqual(19, DefaultSignalGroups.map.count)
        XCTAssertEqual(Set(["hook.frida", "hook.xposed", "root.mounts", "root.su_paths", "debug.tracer", "jb.dyld_images"]),
                       Set(DefaultSignalGroups.map.values))
    }
}
