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
import MachO

struct MachOImage {
    let codeSignature: Data?
    let isEncrypted: Bool?
}

enum MachOImageReader {
    static func mainExecutable() -> MachOImage? {
        for index in 0..<_dyld_image_count() {
            guard let header = _dyld_get_image_header(index),
                  header.pointee.magic == MH_MAGIC_64,
                  header.pointee.filetype == UInt32(MH_EXECUTE) else {
                continue
            }
            return read(UnsafeRawPointer(header), slide: _dyld_get_image_vmaddr_slide(index))
        }
        return nil
    }

    /// Walks the load commands of a 64-bit image mapped at `header`.
    static func read(_ header: UnsafeRawPointer, slide: Int) -> MachOImage? {
        let mach = header.loadUnaligned(as: mach_header_64.self)
        guard mach.magic == MH_MAGIC_64 else {
            return nil
        }
        var offset = MemoryLayout<mach_header_64>.size
        var linkedit: segment_command_64?
        var signatureCommand: linkedit_data_command?
        var isEncrypted: Bool?
        for _ in 0..<mach.ncmds {
            let command = header.loadUnaligned(fromByteOffset: offset, as: load_command.self)
            guard command.cmdsize >= UInt32(MemoryLayout<load_command>.size),
                  offset + Int(command.cmdsize) <= MemoryLayout<mach_header_64>.size + Int(mach.sizeofcmds) else {
                return nil
            }
            switch command.cmd {
            case UInt32(LC_SEGMENT_64):
                let segment = header.loadUnaligned(fromByteOffset: offset, as: segment_command_64.self)
                if segmentName(segment) == "__LINKEDIT" {
                    linkedit = segment
                }
            case UInt32(LC_CODE_SIGNATURE):
                signatureCommand = header.loadUnaligned(fromByteOffset: offset, as: linkedit_data_command.self)
            case UInt32(LC_ENCRYPTION_INFO_64):
                let info = header.loadUnaligned(fromByteOffset: offset, as: encryption_info_command_64.self)
                isEncrypted = info.cryptid != 0
            default:
                break
            }
            offset += Int(command.cmdsize)
        }

        var signature: Data?
        if let signatureCommand, let linkedit,
           signatureCommand.dataoff >= linkedit.fileoff,
           UInt64(signatureCommand.dataoff) + UInt64(signatureCommand.datasize) <= linkedit.fileoff + linkedit.filesize {
            let address = UInt(bitPattern: slide) &+ UInt(linkedit.vmaddr) &+ UInt(UInt64(signatureCommand.dataoff) - linkedit.fileoff)
            if let pointer = UnsafeRawPointer(bitPattern: address) {
                signature = Data(bytes: pointer, count: Int(signatureCommand.datasize))
            }
        }
        return MachOImage(codeSignature: signature, isEncrypted: isEncrypted)
    }

    private static func segmentName(_ segment: segment_command_64) -> String {
        withUnsafeBytes(of: segment.segname) { raw in
            String(bytes: raw.prefix { $0 != 0 }, encoding: .utf8) ?? ""
        }
    }
}
