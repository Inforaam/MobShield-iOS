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
import StoreKit

public enum IntegrityAppTransactionResult: Sendable, Equatable {
    /// StoreKit verified the app transaction's signature.
    case verified(bundleId: String)
    case unverified
    /// StoreKit could not provide an app transaction, for example without a network connection.
    case unavailable
    /// The OS has no `AppTransaction` (before iOS 16).
    case unsupported
}

public protocol IntegrityAppTransactionProviding: Sendable {
    func appTransaction() async -> IntegrityAppTransactionResult
}

public struct LiveAppTransactionProvider: IntegrityAppTransactionProviding {
    public init() {}

    public func appTransaction() async -> IntegrityAppTransactionResult {
        guard #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) else {
            return .unsupported
        }
        do {
            switch try await AppTransaction.shared {
            case let .verified(transaction):
                return .verified(bundleId: transaction.bundleID)
            case .unverified:
                return .unverified
            }
        } catch {
            return .unavailable
        }
    }
}

/// For builds without an embedded profile, verifies the StoreKit 2 app transaction and its bundle
/// ID. Before iOS 16 it falls back to `AppStoreReceiptCheck`. Builds with a profile are skipped.
public struct AppStoreVerificationCheck: Sendable {
    private let bundle: IntegrityBundleProviding
    private let transactions: IntegrityAppTransactionProviding
    private let isSimulator: Bool

    public init(bundle: IntegrityBundleProviding, transactions: IntegrityAppTransactionProviding) {
        self.init(bundle: bundle, transactions: transactions, isSimulator: IntegrityPlatform.isSimulator)
    }

    init(bundle: IntegrityBundleProviding, transactions: IntegrityAppTransactionProviding, isSimulator: Bool) {
        self.bundle = bundle
        self.transactions = transactions
        self.isSimulator = isSimulator
    }

    public func scan() async -> IntegrityScanHit? {
        guard !isSimulator else {
            return nil
        }
        switch EmbeddedProfile.lookup(in: bundle) {
        case nil:
            return IntegrityScanHit(reason: "bundle_url_missing", isUnavailable: true)
        case .present, .unreadable:
            return nil
        case .absent:
            break
        }
        switch await transactions.appTransaction() {
        case let .verified(bundleId):
            guard bundleId != bundle.bundleIdentifier else {
                return nil
            }
            return IntegrityScanHit(
                reason: "app_transaction_bundle_mismatch",
                evidence: ["expected": bundle.bundleIdentifier ?? "", "actual": bundleId]
            )
        case .unverified:
            return IntegrityScanHit(reason: "app_transaction_unverified")
        case .unavailable:
            return IntegrityScanHit(reason: "app_transaction_unavailable", isUnavailable: true)
        case .unsupported:
            return AppStoreReceiptCheck(bundle: bundle).scan()
        }
    }
}
