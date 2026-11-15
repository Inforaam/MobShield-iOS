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

/// Default correlation groups for built-in signals, keyed by signal name.
///
/// Signals in the same group read the same evidence or detect the same tool, so they are not
/// independent observations. `SignalAggregator` combines a group with diminishing returns
/// (noisy-OR) instead of adding its members, which stops one artifact from being counted several
/// times. Signals without a group add independently, as before. See `docs/scoring.md`.
///
/// The table is shared with the Android library and contains names from both platforms.
public enum DefaultSignalGroups {
    /// Frida agent, gadget or server: maps, threads, symbols, port and inline hooks.
    public static let hookFrida = "hook.frida"
    /// Xposed / LSPosed bridge visible to the class loader and in stack traces (Android).
    public static let hookXposed = "hook.xposed"
    /// Mount-table changes read from the proc mount tables (Android).
    public static let rootMounts = "root.mounts"
    /// `stat()`-based probes of the same `su` and root paths (Android).
    public static let rootSuPaths = "root.su_paths"
    /// An attached tracer, seen as `TracerPid` and as a failing `PTRACE_TRACEME` (Android).
    public static let debugTracer = "debug.tracer"
    /// The loaded-image list read twice, by name and by Mach-O header.
    public static let jbDyldImages = "jb.dyld_images"

    public static let map: [String: String] = [
        "common.hook.frida_maps": hookFrida,
        "common.hook.prologue": hookFrida,
        "android.hook.frida_port": hookFrida,
        "android.hook.thread_name": hookFrida,
        "android.hook.suspicious_library": hookFrida,
        "ios.hook.frida_thread": hookFrida,
        "ios.hook.frida_symbols": hookFrida,
        "ios.hook.frida_port": hookFrida,
        "android.hook.art_dex": hookXposed,
        "android.hook.xposed": hookXposed,
        "android.hook.stack_leak": hookXposed,
        "android.root.mount_namespace": rootMounts,
        "android.root.overlayfs": rootMounts,
        "android.root.path_probe": rootSuPaths,
        "android.root.errno_deviation": rootSuPaths,
        "android.debug.tracerpid": debugTracer,
        "android.debug.ptrace": debugTracer,
        "ios.jb.dyld_image": jbDyldImages,
        "ios.jb.dyld_header": jbDyldImages,
    ]
}
