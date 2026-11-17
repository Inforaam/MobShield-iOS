# Process termination

MobShield runs in detect-only mode by default: it reports threats and never ends your process. This
page covers what happens when you opt in to termination, why the rules are what they are, and what
termination can and cannot do for you.

## When the process is terminated

With `detectOnly(false)` and a `TerminationPolicy` other than `.none`, a scan ends the process when
any threat event meets **all** of these conditions:

1. **Severity.** `.exitOnBypass` needs HIGH or CRITICAL; `.exitOnCritical` needs CRITICAL.
2. **Corroboration.** At least one of the event's signals reaches HIGH **on its own**, scored as if
   it were the only signal of its threat type.
3. **Type.** The event's threat type is in `terminateOn` (default: every type).

Your listener receives every event and `onAllChecksFinished` before the process is terminated.
Events that fail condition 2 or 3 are still reported exactly as before; they just cannot end the
process.

## Why corroboration is required

A threat's score adds up evidence from several checks (see [scoring.md](scoring.md)). That is useful
for reporting, but it means weak hints can reach a severity none of them reaches alone, and a
termination policy would then end the app for a user whose device merely looks unusual. The default
weights are not calibrated against real devices, so MobShield does not let an accumulation of weak
hints end the process by itself. The rule and its tests are the same as on Android.

## What can terminate, with the default weights

The single-signal table in [scoring.md](scoring.md#what-one-signal-can-do-on-its-own) shows each
signal's severity on its own; a signal rated HIGH or CRITICAL there can corroborate termination.

**With the default weights, the rule changes nothing on iOS.** Every default iOS signal is strong on
its own except these three, and each is the only weak signal of its threat type, below HIGH on its
own:

| Signal | Score alone |
|---|---|
| `ios.jb.url_scheme` | 10 (LOW) |
| `ios.hook.frida_port` | 15 (LOW) |
| `ios.integrity.receipt` | 35 (MEDIUM) |

The rule takes effect when you change weights with `detectionTuning`: weak signals that you make add
up to HIGH or CRITICAL are reported, but cannot terminate unless a strong signal of the same type is
also present. On Android, where several root and emulator signals are weak, the rule changes which
events terminate.

Some single signals are CRITICAL, so `.exitOnCritical` ends the process on them alone:
`ios.jb.fs_probe` (a known jailbreak path), Frida threads or symbols, a changed function prologue, a
Mach exception port, an invalid code signature, automation frameworks, and **the Simulator**. Leave
`.emulator` out of `terminateOn`, or keep termination off in debug builds, if you run the app in the
Simulator.

## Leaving a threat type out

Use `terminateOn` to keep reporting a type without ever terminating for it. Apps whose users may run
jailbroken devices for legitimate reasons can exclude privileged access:

```swift
var types = Set(ThreatType.allCases)
types.remove(.privilegedAccess)

let config = try MobShieldConfig.builder()
    .detectOnly(false)
    .terminationPolicy(.exitOnCritical)
    .terminateOn(types)
    .build()
```

## Termination is not a security boundary

Termination is a single call, `exit(EXIT_FAILURE)`. Anyone able to hook the app, which is exactly
what Frida and tweak injection do, can replace that call with a no-op, or suppress the checks that
would have triggered it. Termination therefore raises the cost of casual tampering; it does not stop a
determined attacker, and it should not be the only thing between an attacker and something valuable.

Make decisions that matter on your server. Everything the client sends, including MobShield's
reports, can be altered by the same attacker who can hook the app, so base those decisions on
platform attestation ([App Attest](https://developer.apple.com/documentation/devicecheck)) and use
MobShield's reports as additional context.

## Choosing a policy

1. Ship in detect-only mode first and look at what your real users' devices report.
2. If you then want termination, prefer `.exitOnCritical`, and limit `terminateOn` to the types whose
   false positives you can accept.
3. Use `.exitOnBypass` only if locking out some legitimate users is acceptable for your app. It acts
   on HIGH events, which the corroboration rule makes safer but which still rest on uncalibrated
   weights.

## Changes in this version

- Termination requires a signal that reaches HIGH on its own (corroboration). Weak hints that only
  add up to HIGH or CRITICAL no longer end the process.
- New `terminateOn` option (in `MobShieldConfig.init`, `make` and the builder), defaulting to every
  threat type.
- The builder gains `signalGroups(_:)`, which was previously available only through `init` and
  `make`.
