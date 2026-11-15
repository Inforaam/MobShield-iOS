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

/// Locks the documented single-signal outcomes in `docs/scoring.md`: what each default signal
/// scores, and which severity it reaches, when it is the only signal of its threat type.
final class SingleSignalSeverityTests: XCTestCase {
    private let table: [(String, Int, Severity)] = [
        (IntegritySignalDefaults.secCode, 85, .critical),
        (IntegritySignalDefaults.bundleId, 76, .high),
        (IntegritySignalDefaults.provisioning, 56, .high),
        (IntegritySignalDefaults.resource, 68, .high),
        (IntegritySignalDefaults.receipt, 35, .medium),
    ]

    func testEachDefaultSignal_aloneMatchesDocumentedSeverity() {
        let aggregator = SignalAggregator(config: MobShieldConfig())
        for (name, expectedScore, expectedSeverity) in table {
            let signal = IntegritySignalDefaults.buildSignal(name: name, evidence: [:], tuning: [:])
            let events = aggregator.aggregate(signals: [signal])
            XCTAssertEqual(1, events.count, name)
            XCTAssertEqual(expectedScore, events.first?.score, name)
            XCTAssertEqual(expectedSeverity, events.first?.severity, name)
        }
    }
}
