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

/// Parses an embedded code signature SuperBlob (big-endian).
enum CodeSignatureParser {
    static let superBlobMagic: UInt32 = 0xFADE_0CC0
    static let codeDirectoryMagic: UInt32 = 0xFADE_0C02
    static let entitlementsMagic: UInt32 = 0xFADE_7171
    static let codeDirectorySlot: UInt32 = 0
    static let entitlementsSlot: UInt32 = 5
    static let adHocFlag: UInt32 = 0x2
    static let teamOffsetVersion: UInt32 = 0x20200

    struct Parsed {
        let identifier: String?
        let teamIdentifier: String?
        let isAdHoc: Bool
        let entitlements: [String: Any]
    }

    static func parse(_ data: Data) -> Parsed? {
        let blob = [UInt8](data)
        guard readUInt32(blob, 0) == superBlobMagic, let count = readUInt32(blob, 8) else {
            return nil
        }
        var codeDirectory: ArraySlice<UInt8>?
        var entitlements: [String: Any] = [:]
        for index in 0..<Int(min(count, 64)) {
            guard let type = readUInt32(blob, 12 + index * 8),
                  let offset = readUInt32(blob, 16 + index * 8),
                  let child = subBlob(blob, at: Int(offset)) else {
                return nil
            }
            if type == codeDirectorySlot, readUInt32(Array(child), 0) == codeDirectoryMagic {
                codeDirectory = child
            } else if type == entitlementsSlot, readUInt32(Array(child), 0) == entitlementsMagic {
                let xml = Data(child.dropFirst(8))
                entitlements = (try? PropertyListSerialization.propertyList(from: xml, format: nil)) as? [String: Any] ?? [:]
            }
        }
        guard let codeDirectory else {
            return nil
        }
        let directory = Array(codeDirectory)
        guard let version = readUInt32(directory, 8), let flags = readUInt32(directory, 12) else {
            return nil
        }
        let identifier = readUInt32(directory, 20).flatMap { cString(directory, at: Int($0)) }
        var teamIdentifier: String?
        if version >= teamOffsetVersion, let teamOffset = readUInt32(directory, 48), teamOffset != 0 {
            teamIdentifier = cString(directory, at: Int(teamOffset))
        }
        return Parsed(
            identifier: identifier,
            teamIdentifier: teamIdentifier,
            isAdHoc: flags & adHocFlag != 0,
            entitlements: entitlements
        )
    }

    private static func subBlob(_ blob: [UInt8], at offset: Int) -> ArraySlice<UInt8>? {
        guard let length = readUInt32(blob, offset + 4), length >= 8, offset + Int(length) <= blob.count else {
            return nil
        }
        return blob[offset..<(offset + Int(length))]
    }

    private static func readUInt32(_ bytes: [UInt8], _ offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= bytes.count else {
            return nil
        }
        return bytes[offset..<(offset + 4)].reduce(0) { $0 << 8 | UInt32($1) }
    }

    private static func cString(_ bytes: [UInt8], at offset: Int) -> String? {
        guard offset > 0, offset < bytes.count else {
            return nil
        }
        let terminated = bytes[offset...].prefix { $0 != 0 }
        guard terminated.endIndex < bytes.endIndex else {
            return nil
        }
        return String(bytes: terminated, encoding: .utf8)
    }
}
