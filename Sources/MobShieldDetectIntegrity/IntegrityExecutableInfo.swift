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

/// Code signature and encryption details of the app's main executable.
public struct IntegrityExecutableInfo: Sendable, Equatable {
    public let hasCodeSignature: Bool
    public let signingIdentifier: String?
    public let teamIdentifier: String?
    public let isAdHocSigned: Bool
    /// `application-identifier` from the signed entitlements, usually `TEAMID.bundle.id`.
    public let applicationIdentifier: String?
    public let getTaskAllow: Bool
    /// `cryptid != 0` of `LC_ENCRYPTION_INFO_64`; nil when the executable has no such load command.
    public let isEncrypted: Bool?

    public init(
        hasCodeSignature: Bool,
        signingIdentifier: String? = nil,
        teamIdentifier: String? = nil,
        isAdHocSigned: Bool = false,
        applicationIdentifier: String? = nil,
        getTaskAllow: Bool = false,
        isEncrypted: Bool? = nil
    ) {
        self.hasCodeSignature = hasCodeSignature
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.isAdHocSigned = isAdHocSigned
        self.applicationIdentifier = applicationIdentifier
        self.getTaskAllow = getTaskAllow
        self.isEncrypted = isEncrypted
    }
}

public protocol IntegrityExecutableProviding: Sendable {
    /// Nil when the main executable image cannot be read.
    func executableInfo() -> IntegrityExecutableInfo?
}

/// Reads the main executable's Mach-O image as loaded in memory.
public struct LiveExecutableProvider: IntegrityExecutableProviding {
    public init() {}

    public func executableInfo() -> IntegrityExecutableInfo? {
        guard let image = MachOImageReader.mainExecutable() else {
            return nil
        }
        guard let signature = image.codeSignature else {
            return IntegrityExecutableInfo(hasCodeSignature: false, isEncrypted: image.isEncrypted)
        }
        guard let parsed = CodeSignatureParser.parse(signature) else {
            return nil
        }
        return IntegrityExecutableInfo(
            hasCodeSignature: true,
            signingIdentifier: parsed.identifier,
            teamIdentifier: parsed.teamIdentifier,
            isAdHocSigned: parsed.isAdHoc,
            applicationIdentifier: parsed.entitlements["application-identifier"] as? String,
            getTaskAllow: parsed.entitlements["get-task-allow"] as? Bool ?? false,
            isEncrypted: image.isEncrypted
        )
    }
}
