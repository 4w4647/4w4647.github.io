---
title: "Reversing HP's Kernel Drivers: When the Attack Surface Isn't Where You Expect It"
date: 2026-04-26T00:00:00+05:45
draft: false

description: "Auditing two HP kernel drivers with Ghidra reveals stub IOCTL handlers and a deliberate minimal-kernel-footprint design — and why that's a finding in itself."

tags: ["reverse-engineering", "windows", "kernel", "ghidra", "security-research"]
categories: ["security"]
---

**System:** Windows 11 (AMD64)  
**Tools:** Ghidra 11.x, DriverQuery  
**Verdict:** No kernel-level vulnerability found — and that's a research finding in itself.

---

## Where This Started

I was auditing the kernel drivers installed on my machine using `DriverQuery /v` — a standard first step when mapping local attack surface. Two HP drivers caught my eye immediately, not because they looked dangerous, but because they looked *suspiciously small*:

| Driver | Code Size | State |
|--------|-----------|-------|
| `hpomencustomcapdriver.sys` | 4,096 bytes | Running |
| `HPCustomCapD.sys` | 4,096 bytes | Running |

4,096 bytes is one memory page. A running kernel driver that fits in a single page is either a minimal stub or a tightly scoped handler doing something privileged with very little code to do it safely. Both possibilities are worth investigating — the latter especially, since hardware control drivers (fan speed, power limits, overclocking) are historically rich targets for local privilege escalation.

I loaded both into Ghidra and started tracing.

---

## Driver 1 — `hpomencustomcapdriver.sys`

### Triage

The "HP Omen" branding pointed toward gaming hardware control — the kind of functionality that often gets exposed through a userland app talking to a kernel driver via `DeviceIoControl`. That's a classic attack surface: a privileged kernel operation gated only by whatever validation the vendor thought to add.

I had my hypothesis. Time to test it.

### Tracing the Execution Chain

`DriverEntry` was a two-line wrapper:

```c
NTSTATUS DriverEntry(LONGLONG DriverObject, UNDEFINED8 RegistryPath)
{
    FUN_14000606c();
    uVar1 = FUN_14000105c(DriverObject, RegistryPath);
    return (NTSTATUS)uVar1;
}
```

The first call turned out to be `__security_check_cookie` — a compiler-inserted stack canary initializer. I renamed it and moved on. The second call was the real initialization.

Inside `FUN_14000105c`, three imports confirmed this was a **KMDF driver**:

```c
WdfVersionBind(param_1, &DAT_1400030b8, &DAT_140003030, &DAT_1400030d0);
FxStubBindClasses((_WDF_BIND_INFO *)&DAT_140003030);
FxStubInitTypes();
```

KMDF (Kernel Mode Driver Framework) abstracts away raw IRP handling — device creation and IOCTL dispatch happen through registered callbacks rather than direct `MajorFunction` table assignments. I also noticed this line:

```c
*(code **)(param_1 + 0x68) = FxStubDriverUnload;
```

`param_1` is the `DRIVER_OBJECT`. Offset `0x68` is `DriverObject->DriverUnload`. That's the driver registering its cleanup routine — readable directly from raw decompiler output once you know the struct layout.

The real initialization was delegated to `FUN_140006000`, which registered a `WdfDriverCreate` callback:

```c
local_20 = FUN_140005000;    // EvtDriverDeviceAdd
WdfDriverCreate(..., &config, ...);
```

### Device Setup

Inside `EvtDriverDeviceAdd` (`FUN_140005000`) I found the device setup sequence:

- `WdfDeviceCreate` — creates the device object. The internal name resolved to `"FDO_DATA"`, a WDF context label rather than a userland-accessible path.
- `WdfDeviceCreateSymbolicLink` — creates the accessible symlink
- `WdfDeviceCreateDeviceInterface` — registers the device with a GUID (`DAT_140002050`) so userland can discover it via `SetupDiGetClassDevs`
- `WdfIoQueueCreate` — registers two I/O callbacks:

```c
local_50 = FUN_14000514c;   // EvtIoDeviceControl
local_48 = FUN_140005194;   // EvtIoRead
```

This is the IOCTL handler. This is what I came for.

### The IOCTL Handler

```c
void EvtIoDeviceControl(undefined8 param_1, undefined8 param_2)
{
    uVar1 = WdfRequestGetParameters(DriverObject, Request, &local_res20);
    WdfRequestComplete(DriverObject, Request, uVar1, 0);
    return;
}
```

It gets the request parameters and immediately completes it. No switch statement. No buffer retrieval. No size check. No kernel operation. Just accept and complete.

The read handler was identical in spirit — retrieve parameters, return length, complete. No processing.

### Security Mitigations

Despite the minimal logic, the binary had proper mitigations compiled in:

- **Stack cookies** (`/GS`) — `__security_check_cookie` called on function entry/exit. Any stack overflow that corrupts the return address also corrupts the cookie, killing execution before it returns.
- **Control Flow Guard (CFG)** — every indirect call through the WDF function table is wrapped in `_guard_dispatch_icall`, validating the target against a bitmap of legitimate function addresses at runtime.

### Verdict

```
Attack Surface:  None
Exploitability:  N/A
Conclusion:      IOCTL handler is a stub. No input processing occurs
                 in kernel mode. Functional logic delegated to userland.
```

---

## Driver 2 — `HPCustomCapD.sys`

### First Difference: Ghidra Knows This One

When I traced into the KMDF init function on this driver, Ghidra's FLIRT signature database fired:

```
/* Library Function - Single Match: FxDriverEntryWorker
   Library: Visual Studio 2019 Release */
```

FLIRT (Fast Library Identification and Recognition Technology) matched the compiled code against known library signatures. I didn't have to reverse the framework boilerplate — Ghidra told me exactly what it was. This is one of the practical advantages of working in Ghidra: as you encounter more drivers, the framework code gets identified automatically and you can focus on the vendor-specific logic.

I also spotted a debug string that shouldn't be in a production binary:

```c
DbgPrintEx(0x4d, 0, "DriverEntry failed 0x%x for driver %wZ\n", uVar1, &DAT_1400032c8);
```

Vendors sometimes ship binaries with debug logging intact. These strings are gifts — they often reveal internal function names, error conditions, and architectural assumptions. No direct security impact here, but worth noting.

### Three Handlers This Time

`EvtDriverDeviceAdd` registered three callbacks instead of two:

```c
local_50 = FUN_140005180;   // EvtIoDeviceControl
local_48 = FUN_1400051e0;   // EvtIoRead
local_40 = FUN_140005150;   // EvtIoWrite
```

And the queue configuration included:

```c
uStack_90 = 0x100000001;    // MaximumRequests = 1
```

This is a **serialized queue** — requests are processed one at a time, not concurrently. From a vulnerability research perspective this constrains the race window for any TOCTOU (Time-of-Check to Time-of-Use) bugs. Worth noting even when the handlers themselves turn out to be stubs.

### The Handlers

**EvtIoDeviceControl:** Identical stub to Driver 1 — retrieve parameters, complete immediately.

**EvtIoRead:** Same pattern.

**EvtIoWrite:** This one was different:

```c
void EvtIoWrite(undefined8 param_1, undefined8 param_2)
{
    WdfRequestComplete(DriverObject, Request, 0xc0000010, 0);
    return;
}
```

`0xc0000010` is `STATUS_INVALID_DEVICE_REQUEST`. Write operations are explicitly refused before any processing occurs. This isn't an oversight or a stub — it's a deliberate rejection. The vendor made an active decision to block writes at the kernel boundary.

### Security Mitigations

- Stack cookies present on all non-trivial functions
- CFG annotated on every WDF indirect call (`guard_dispatch_icall`)

### Verdict

```
Attack Surface:  None
Exploitability:  N/A
Write Handler:   Explicit STATUS_INVALID_DEVICE_REQUEST — deliberate hardening
Conclusion:      Functional architecture identical to Driver 1.
                 No kernel-level vulnerability surface present.
```

---

## Understanding the Design: Minimal Kernel Footprint as a Security Choice

My first instinct when seeing two 4KB drivers with stub handlers was to wonder whether HP had shipped incomplete or placeholder code. After reversing both completely, I think the opposite is true — this is a considered architectural decision, and it reflects stronger security thinking than many third-party drivers I've read about.

Here's the reasoning behind the pattern:

**Windows requires kernel ownership of devices.** You cannot expose a discoverable device interface to userland — the kind that `SetupDiGetClassDevs` can find — without a kernel driver owning the device object. Even if there's zero kernel logic to implement, a driver must exist to satisfy the Windows driver model. HP needed the device interface; they just didn't need it to do anything in kernel mode.

**Keeping logic in userland shrinks the blast radius.** A bug in a userland process crashes that process. A bug in kernel mode crashes the machine, or worse — it hands an attacker the ability to execute arbitrary code at ring 0, bypassing all security boundaries. By pushing functional complexity into their userland service and keeping the kernel component as thin as possible, HP made a quiet but meaningful security tradeoff. The most dangerous code path is also the shortest one.

**WDF handles everything else automatically.** The KMDF framework takes care of PnP device arrival and removal, power state transitions, and system sleep/wake events without requiring any custom driver code. The kernel driver earns its existence just by being present and letting WDF do the work.

The research implication is worth internalizing: **attack surface follows the logic, not the privilege level.** These kernel drivers run at the highest privilege level in the system, but they do nothing with it. The actual functionality — and any bugs in it — lives in the HP userland service consuming the device interface GUID. That's where a thorough audit would continue.

---

## Methodology

```
1. Enumerate loaded drivers via DriverQuery /v
   └─ Flag: 4KB code size, third-party vendor, Running state

2. Import binaries into Ghidra, run auto-analysis

3. DriverEntry → trace call chain forward
   └─ Identify framework (KMDF confirmed via WdfVersionBind / FxStub*)
   └─ Locate EvtDriverDeviceAdd via WdfDriverCreate config struct

4. EvtDriverDeviceAdd
   └─ Extract device name and interface GUID
   └─ Identify WdfIoQueueCreate callbacks
   └─ Note queue configuration (serialized vs parallel)

5. Analyze each I/O handler
   └─ Look for IOCTL dispatch (switch statement on control code)
   └─ Check input buffer retrieval and size validation
   └─ Document behavior and result

6. Document findings and architectural conclusion
```

---

## Symbols Renamed During Analysis

Renaming functions as I understand them is a discipline I try to maintain throughout any analysis session. It keeps the symbol tree readable and prevents re-analyzing the same code twice.

| Original Name | Renamed To | Basis |
|---------------|------------|-------|
| `FUN_140006060` | `__security_check_cookie` | Code pattern + Ghidra hint |
| `FUN_140005000` (both drivers) | `EvtDriverDeviceAdd` | WDF callback registration position |
| `FUN_140005180` | `EvtIoDeviceControl` | WDF queue config slot offset |
| `FUN_1400051e0` | `EvtIoRead` | WDF queue config slot offset |
| `FUN_140005150` | `EvtIoWrite` | WDF queue config slot offset |

---

*Research conducted on personally owned hardware. All analysis is for educational purposes. No vulnerability was discovered or disclosed in connection with this post.*
