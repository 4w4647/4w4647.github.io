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
**Verdict:** No kernel-level vulnerability found. That's still a finding.

---

## Where This Started

I was poking around the kernel drivers loaded on my laptop, running `DriverQuery /v` to get a sense of what was sitting in ring 0. It's a habit I've gotten into. Most of what comes back is Microsoft and OEM stuff you'd expect, but every now and then something looks off, and that's where the interesting work begins.

Two HP drivers caught my eye. Not because they looked dangerous, but because they looked *suspiciously small*:

| Driver | Code Size | State |
|--------|-----------|-------|
| `hpomencustomcapdriver.sys` | 4,096 bytes | Running |
| `HPCustomCapD.sys` | 4,096 bytes | Running |

4,096 bytes is one memory page. A running kernel driver that fits in a single page is one of two things. Either it's a minimal stub that does basically nothing, or it's a tightly scoped handler doing something privileged with very little code to do it safely. Both possibilities are worth looking at, but the second one especially. Hardware control drivers (fan speed, power limits, overclocking) have a long history of being exploitable for local privilege escalation, and the "HP Omen" branding pointed in exactly that direction.

So I loaded both into Ghidra and started tracing.

---

## Driver 1: `hpomencustomcapdriver.sys`

### Triage

The HP Omen line is gaming hardware. The kind of stuff where a userland app talks to a kernel driver via `DeviceIoControl` to crank up fan speeds or read sensor values. That's a classic attack surface. A privileged kernel operation gated only by whatever validation the vendor remembered to add.

Working hypothesis: this driver exposes some kind of hardware control IOCTL with sketchy validation. Time to find out.

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

The first call follows the standard MSVC pattern for stack cookie initialization (`__security_init_cookie`). It's compiler boilerplate that runs once at driver load to set up the global stack canary used by all subsequent function-level `/GS` checks. Not interesting. The second call is where the actual work happens.

Inside `FUN_14000105c`, three imports gave away that this was a **KMDF driver**:

```c
WdfVersionBind(param_1, &DAT_1400030b8, &DAT_140003030, &DAT_1400030d0);
FxStubBindClasses((_WDF_BIND_INFO *)&DAT_140003030);
FxStubInitTypes();
```

KMDF (Kernel Mode Driver Framework) abstracts away most of the raw IRP plumbing. Device creation and IOCTL dispatch happen through registered callbacks instead of direct `MajorFunction` table assignments like you'd see in a classic WDM driver. Different mental model, same end result.

I also caught this line:

```c
*(code **)(param_1 + 0x68) = FxStubDriverUnload;
```

`param_1` is the `DRIVER_OBJECT`. Offset `0x68` is `DriverObject->DriverUnload`. So the driver is registering its cleanup routine. Once you know the struct layout, you can read this stuff straight out of raw decompiler output without needing symbols.

The real initialization got delegated one more level down to `FUN_140006000`, which set up the WDF driver object:

```c
local_20 = FUN_140005000;    // EvtDriverDeviceAdd
WdfDriverCreate(..., &config, ...);
```

### Device Setup

Inside `EvtDriverDeviceAdd` (`FUN_140005000`) I found the standard device setup sequence:

- `WdfDeviceCreate` to create the device object. The internal name resolved to `"FDO_DATA"`, which is a WDF context label, not a userland-accessible path.
- `WdfDeviceCreateSymbolicLink` to create the accessible symlink.
- `WdfDeviceCreateDeviceInterface` to register the device with a GUID (`DAT_140002050`) so userland can find it via `SetupDiGetClassDevs`.
- `WdfIoQueueCreate` to register two I/O callbacks:

```c
local_50 = FUN_14000514c;   // EvtIoDeviceControl
local_48 = FUN_140005194;   // EvtIoRead
```

That `EvtIoDeviceControl` callback is the IOCTL handler. That's where I needed to be.

### The IOCTL Handler

```c
void EvtIoDeviceControl(undefined8 param_1, undefined8 param_2)
{
    // Indirect call into WDF function table at offset 0x860
    // Pattern matches WdfRequestRetrieveInputBuffer or similar buffer retrieval API
    uVar1 = WdfFnTable[0x860](DriverObject, Request, &local_res20);
    WdfRequestComplete(DriverObject, Request, uVar1, 0);
    return;
}
```

Whatever the WDF function at offset `0x860` actually does, the pattern here is unmistakable. One WDF call returning a status, then `WdfRequestComplete` immediately using that status. There's no switch on the IOCTL code. No validation logic. No kernel operation that depends on what the request was actually asking for. The handler accepts whatever userland sends and completes the request.

The read handler was the same shape. Retrieve parameters, return length, complete. No processing.

That's not what I expected to find.

### Security Mitigations

Even though the handlers do nothing interesting, the binary itself was compiled with the standard mitigations:

- **Stack cookies (`/GS`)**: `__security_check_cookie` runs on function exit. Any stack overflow that overwrites the return address also clobbers the cookie, and the process dies before it returns.
- **Control Flow Guard (CFG)**: every indirect call through the WDF function table gets wrapped in `_guard_dispatch_icall`, which validates the target against a bitmap of legitimate function addresses at runtime.

Worth noting even when the handlers turn out to be stubs.

### Verdict

```
Attack Surface:  None
Exploitability:  N/A
Conclusion:      IOCTL handler is a stub. No input processing
                 happens in kernel mode. The functional logic
                 lives somewhere in userland.
```

---

## Driver 2: `HPCustomCapD.sys`

### Ghidra Recognized This One

When I traced into the KMDF init function on this driver, Ghidra's FLIRT signature database fired automatically:

```
/* Library Function - Single Match: FxDriverEntryWorker
   Library: Visual Studio 2019 Release */
```

FLIRT (Fast Library Identification and Recognition Technology) matches compiled code against a database of known library signatures. I didn't have to reverse the framework boilerplate myself. Ghidra just told me what it was. This is one of those quiet wins from working in a mature tool. The more drivers you analyze, the more framework code gets identified for you, and you spend more of your time on the vendor-specific bits that actually matter.

Something else I noticed: a debug string still sitting in what should be a production binary.

```c
DbgPrintEx(0x4d, 0, "DriverEntry failed 0x%x for driver %wZ\n", uVar1, &DAT_1400032c8);
```

These are gifts. They often reveal internal function names, error conditions, or assumptions the vendor made about how their code runs. No direct security impact in this case, but I file it away anyway.

### Three Handlers This Time

`EvtDriverDeviceAdd` registered three callbacks instead of two:

```c
local_50 = FUN_140005180;   // EvtIoDeviceControl
local_48 = FUN_1400051e0;   // EvtIoRead
local_40 = FUN_140005150;   // EvtIoWrite
```

The queue configuration set its dispatch type to a sequential value (`local_64 = 2` corresponds to `WdfIoQueueDispatchSequential` in the WDF SDK). That means requests get processed one at a time rather than in parallel. From a vulnerability research perspective this constrains the race window for any TOCTOU (Time-of-Check to Time-of-Use) bugs that might otherwise exist between handlers. Useful context, even when the handlers themselves are stubs.

### The Handlers

**EvtIoDeviceControl**: identical stub to Driver 1. Retrieve parameters, complete immediately.

**EvtIoRead**: same pattern.

**EvtIoWrite**: this one actually did something.

```c
void EvtIoWrite(undefined8 param_1, undefined8 param_2)
{
    WdfRequestComplete(DriverObject, Request, 0xc0000010, 0);
    return;
}
```

`0xc0000010` is `STATUS_INVALID_DEVICE_REQUEST`. Write operations get explicitly refused before any processing happens. This isn't an oversight or a stub. It's a deliberate rejection. Someone at HP made an active call to block writes at the kernel boundary.

### Security Mitigations

- Stack cookies present on all non-trivial functions
- CFG annotated on every WDF indirect call (`guard_dispatch_icall`)

### Verdict

```
Attack Surface:  None
Exploitability:  N/A
Write Handler:   Explicit STATUS_INVALID_DEVICE_REQUEST. Deliberate hardening.
Conclusion:      Functional architecture identical to Driver 1.
                 No kernel-level vulnerability surface present.
```

---

## So Why Are These Drivers Like This?

When I started, my gut reaction was that HP had shipped half-finished drivers. Two 4KB binaries with stub handlers? Looks like placeholder code. After actually reversing both of them, I think the opposite is true. This looks like a deliberate architectural choice, and it reflects better security thinking than a lot of third-party drivers I've seen.

Here's the logic behind the pattern.

**Windows requires kernel ownership of devices.** You can't expose a discoverable device interface to userland (the kind that `SetupDiGetClassDevs` can find) without a kernel driver owning the device object. Even if there's zero kernel logic to implement, a driver still has to exist for the Windows driver model to work. HP needed the device interface. They didn't need it to do anything in kernel mode.

**Keeping logic in userland shrinks the blast radius.** A bug in a userland process crashes that process. A bug in kernel mode crashes the machine, or worse, it hands an attacker arbitrary code execution at ring 0 with all the consequences that entails. By pushing the actual functionality into a userland service and keeping the kernel component as thin as possible, HP shrank the part of their attack surface where bugs hurt the most. The most dangerous code path is also the shortest one.

**WDF handles everything else automatically.** The KMDF framework takes care of PnP device arrival and removal, power state transitions, sleep and wake events, all without needing any custom driver code. The driver earns its existence just by being there and letting WDF do the work.

The implication is one of those things that's easy to forget if you're laser-focused on kernel research: **attack surface follows the logic, not the privilege level.** These kernel drivers run at the highest privilege level on the system, but they don't do anything with it. The real functionality (and any bugs in it) lives in the HP userland service that consumes the device interface GUID. That's where a serious audit would continue.

---

## Methodology

For anyone wanting to repeat this on their own system:

```
1. Enumerate loaded drivers via DriverQuery /v
   └─ Flag: 4KB code size, third-party vendor, Running state

2. Import binaries into Ghidra, run auto-analysis

3. DriverEntry → trace the call chain forward
   └─ Identify framework (KMDF confirmed via WdfVersionBind / FxStub*)
   └─ Locate EvtDriverDeviceAdd via WdfDriverCreate config struct

4. EvtDriverDeviceAdd
   └─ Extract device name and interface GUID
   └─ Identify WdfIoQueueCreate callbacks
   └─ Note queue configuration (serialized vs parallel)

5. Analyze each I/O handler
   └─ Look for IOCTL dispatch (switch statement on control code)
   └─ Check input buffer retrieval and size validation
   └─ Document the behavior

6. Write up findings and architectural conclusions
```

---

## Symbols Renamed During Analysis

Renaming functions as I figure them out is a discipline I try to maintain. It keeps the symbol tree readable and stops me from re-analyzing the same code twice when I come back to a project later.

| Original Name | Renamed To | Basis |
|---------------|------------|-------|
| `FUN_140006060` | `__security_init_cookie` | MSVC stack cookie init pattern (called once at DriverEntry) |
| `FUN_140005000` (both drivers) | `EvtDriverDeviceAdd` | WDF callback registration position |
| `FUN_140005180` | `EvtIoDeviceControl` | WDF queue config slot offset |
| `FUN_1400051e0` | `EvtIoRead` | WDF queue config slot offset |
| `FUN_140005150` | `EvtIoWrite` | WDF queue config slot offset |

---

*Research conducted on personally owned hardware. All analysis is for educational purposes. No vulnerability was discovered or disclosed in connection with this post.*
