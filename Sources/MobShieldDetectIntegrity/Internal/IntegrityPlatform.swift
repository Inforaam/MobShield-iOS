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

enum IntegrityPlatform {
    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    static var isiOSAppOnMac: Bool {
        if #available(iOS 14.0, macOS 11.0, tvOS 14.0, watchOS 7.0, *) {
            return ProcessInfo.processInfo.isiOSAppOnMac
        }
        return false
    }
}

enum EmbeddedProfile {
    static let fileName = "embedded.mobileprovision"

    enum Lookup {
        case absent
        case unreadable
        case present([String: Any])
    }

    static func lookup(in bundle: IntegrityBundleProviding) -> Lookup? {
        guard let bundleURL = bundle.bundleURL else {
            return nil
        }
        let path = bundleURL.appendingPathComponent(fileName).path
        guard bundle.fileExists(atPath: path) else {
            return .absent
        }
        guard let data = bundle.contents(atPath: path), let plist = ProvisioningProfileParser.parsePlist(from: data) else {
            return .unreadable
        }
        return .present(plist)
    }
}
