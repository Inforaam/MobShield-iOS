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

enum IntegrityCheckResult: Sendable, Equatable {
    case finished(IntegrityScanHit?)
    case timedOut
}

enum IntegrityCheckRunner {
    /// Timeouts fire on their own serial queue, which gets a thread even when every thread of the
    /// shared pool is blocked.
    private static let timerQueue = DispatchQueue(label: "io.mobshield.integrity.timeout", qos: .utility)

    /// Runs `work` off the caller and returns `.timedOut` once `timeoutNs` passes, without waiting
    /// for `work` to return.
    static func run(
        timeoutNs: UInt64,
        queue: DispatchQueue = .global(qos: .utility),
        _ work: @escaping @Sendable () -> IntegrityScanHit?
    ) async -> IntegrityCheckResult {
        await withCheckedContinuation { continuation in
            let once = ResumeOnce(continuation)
            queue.async { once.resume(.finished(work())) }
            timerQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(clamping: timeoutNs))) {
                once.resume(.timedOut)
            }
        }
    }

    /// Async variant of `run(timeoutNs:queue:_:)`.
    static func runAsync(
        timeoutNs: UInt64,
        _ work: @escaping @Sendable () async -> IntegrityScanHit?
    ) async -> IntegrityCheckResult {
        await withCheckedContinuation { continuation in
            let once = ResumeOnce(continuation)
            Task { once.resume(.finished(await work())) }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .nanoseconds(Int(clamping: timeoutNs))) {
                once.resume(.timedOut)
            }
        }
    }
}

private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<IntegrityCheckResult, Never>?

    init(_ continuation: CheckedContinuation<IntegrityCheckResult, Never>) {
        self.continuation = continuation
    }

    func resume(_ result: IntegrityCheckResult) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: result)
    }
}
