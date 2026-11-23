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

/// How an iOS build was distributed, as derived from its signature and embedded profile.
public enum AppDistribution: String, CaseIterable, Sendable {
    case appStore
    case testFlight
    case adHoc
    case enterprise
    case development

    /// App Store and TestFlight builds, which carry no embedded provisioning profile.
    public static let store: Set<AppDistribution> = [.appStore, .testFlight]
}
