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

import MobShieldCore
@testable import MobShieldDetectIntegrity
import XCTest

private struct Expectation {
    let name: String
    let score: Int
    let severity: Severity
}

/// Locks the documented single-signal outcomes in `docs/scoring.md`: what each default signal
/// scores, and which severity it reaches, when it is the only signal of its threat type.
final class SingleSignalSeverityTests: XCTestCase {
    private let table: [Expectation] = [
        Expectation(name: IntegritySignalDefaults.secCode, score: 85, severity: .critical),
        Expectation(name: IntegritySignalDefaults.bundleId, score: 76, severity: .high),
        Expectation(name: IntegritySignalDefaults.provisioning, score: 56, severity: .high),
        Expectation(name: IntegritySignalDefaults.resource, score: 68, severity: .high),
        Expectation(name: IntegritySignalDefaults.receipt, score: 35, severity: .medium),
        Expectation(name: IntegritySignalDefaults.checkUnavailable, score: 12, severity: .low),
    ]

    func testEachDefaultSignal_aloneMatchesDocumentedSeverity() {
        let aggregator = SignalAggregator(config: MobShieldConfig())
        for expected in table {
            let signal = IntegritySignalDefaults.buildSignal(name: expected.name, evidence: [:], tuning: [:])
            let events = aggregator.aggregate(signals: [signal])
            XCTAssertEqual(1, events.count, expected.name)
            XCTAssertEqual(expected.score, events.first?.score, expected.name)
            XCTAssertEqual(expected.severity, events.first?.severity, expected.name)
        }
    }
}
