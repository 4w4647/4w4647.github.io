---
slug: "stack-frames-the-foundation-of-every-stack-overflow"
title: "Stack Frames - The Foundation of Every Stack Overflow"
date: 2026-04-30T04:06:54+05:45
draft: false

description: "A deep dive into x86 stack frames, prologues, epilogues, calling conventions, little-endian memory, and how a simple buffer overflow leads to EIP control."
tags: [Exploit-Development, x86, OSED, WinDbg, Stack-Overflow, Assembly]
categories: [OSED]

cover:
  image: "/img/OSED.png"
  alt: "CIPHERFLARE"
---

## Where Everything Starts

Before you write a single byte of shellcode, before you talk about ROP chains or DEP bypasses, there is one mental model you need to have locked in cold. The stack frame.
 
Every stack-based exploit ever written comes down to the same thing: you overflow a buffer, you overwrite a return address, and when the function returns, the CPU jumps somewhere you control. That's it. The techniques that come later are just clever ways of working around defenses layered on top of that same primitive.
 
So let's build the model from scratch, at the instruction level, with no hand-waving.
 
---
 
## The x86 Stack
 
The stack is a region of memory that grows **downward**. Higher addresses are at the top conceptually, but as you push things onto the stack, the stack pointer moves toward lower addresses.
 
Two registers manage it:
 
- **ESP** (Stack Pointer) always points to the top of the stack, which is the lowest address currently in use
- **EBP** (Base Pointer) anchors the current function's frame so locals and arguments can be accessed at fixed offsets
Every `push` subtracts 4 from ESP and writes a value there. Every `pop` reads from ESP and adds 4. That is the whole mechanism.
 
---
 
## Before the Function: The Caller's Job
 
Take this C code:
 
```c
void foo(int a, int b) {
    char buf[16];
    int x;
}
 
foo(1, 2);
```
 
Before `foo` starts executing, the **caller** has to get the arguments onto the stack. In the **cdecl calling convention** (the default for most x86 C code), arguments are pushed right to left. Last argument first, first argument last.
 
```nasm
push 2          ; push b first (last argument)
push 1          ; push a second (first argument)
call foo        ; now jump into foo
```
 
Why right to left? Because after the push sequence, the first argument ends up closest to the top of the stack. Once the frame is set up, `a` will be at `[ebp+8]` and `b` will be at `[ebp+12]`, consistently, regardless of how many arguments there are. This is why `printf` can take a variable number of arguments and still find the first one reliably.
 
**What does CALL actually do?**
 
`CALL` is not magic. It is equivalent to two instructions:
 
```nasm
push eip        ; push the address of the instruction after CALL
jmp foo         ; jump to foo
```
 
The address it pushes is called the **return address**. It is where execution will resume after `foo` finishes. Without it, the program would have no idea where to go back to.
 
At this point, just before `foo` starts, the stack looks like this:
 
```
High Address
┌─────────────────┐
│        2        │  argument b
├─────────────────┤
│        1        │  argument a
├─────────────────┤
│  return address │  pushed by CALL, ESP points here
└─────────────────┘
Low Address
```
 
---
 
## Inside the Function: The Prologue
 
The moment execution lands inside `foo`, the first three instructions you will almost always see are the **prologue**:
 
```nasm
push ebp        ; save the caller's base pointer onto the stack
mov ebp, esp    ; point EBP at the current top of stack
sub esp, 20     ; carve out 20 bytes for local variables
```
 
Walk through each one:
 
**`push ebp`** saves the caller's EBP so it can be restored later. Every function does this so the chain of stack frames stays intact.
 
**`mov ebp, esp`** sets EBP to the current value of ESP. From this point forward, EBP is fixed for the duration of the function. It does not move. This gives you a stable anchor to reference locals and arguments by offset.
 
**`sub esp, 20`** moves ESP down by 20 bytes, reserving space for `buf[16]` and `int x` (4 bytes). The compiler calculates the total size of all locals at compile time and emits a single `sub esp` to reserve all of it at once. You will never see one `sub` per variable.
 
After the prologue, the stack looks like this:
 
```
High Address
┌─────────────────┐
│        2        │  [ebp+12]  argument b
├─────────────────┤
│        1        │  [ebp+8]   argument a
├─────────────────┤
│  return address │  [ebp+4]
├─────────────────┤
│   saved EBP     │  [ebp]     EBP points here
├─────────────────┤
│    buf[16]      │  [ebp-4] to [ebp-20]
├─────────────────┤
│      int x      │  [ebp-24]  ESP points here
└─────────────────┘
Low Address
```
 
Notice a few things:
 
Arguments live **above** EBP at positive offsets. Locals live **below** EBP at negative offsets. This is why you will constantly see things like `[ebp+8]` for the first argument and `[ebp-4]` for the first local in disassembly. That is not a coincidence. It is the direct result of the prologue.
 
Also notice that locals declared **first** end up at higher addresses (closer to saved EBP). Locals declared later end up at lower addresses. The stack grows downward, so as space gets reserved, it goes down. This ordering matters when you calculate overflow offsets.
 
---
 
## Leaving the Function: The Epilogue
 
When `foo` is done, it needs to tear down the frame and return. This is the **epilogue**:
 
```nasm
mov esp, ebp    ; point ESP back at saved EBP, discarding all locals
pop ebp         ; restore caller's EBP, ESP now points at return address
ret             ; pop return address into EIP, jump there
```
 
Walk through each one:
 
**`mov esp, ebp`** collapses the local variable space in one shot. ESP jumps back up to where EBP is pointing, which is saved EBP. All the locals are now gone as far as the stack is concerned.
 
**`pop ebp`** reads the saved EBP value off the stack into the EBP register, restoring the caller's frame. ESP moves up by 4, now pointing at the return address.
 
**`ret`** is the most important instruction in exploit development. It is equivalent to:
 
```nasm
pop eip         ; read whatever ESP points to, put it in EIP, add 4 to ESP
```
 
The CPU takes the return address off the stack and jumps there. Execution resumes in the caller right after the original `call foo`.
 
After `ret`, the stack is back to what it looked like before the call.
 
---
 
## A Note on Pointer Arguments
 
One thing that catches beginners out. When a function takes a pointer argument like `char *str`, the caller does not push the string onto the stack. It pushes a **4-byte address** pointing to where the string lives in memory.
 
```c
void bar(char *name, int age) { ... }
 
bar("alice", 25);
```
 
```nasm
push 25                  ; int age (4 bytes)
push <addr of "alice">   ; char* name (4-byte pointer, not the string itself)
call bar
```
 
The string `"alice"` itself sits somewhere in the data segment. What goes on the stack is a pointer to it. Always 4 bytes on x86, regardless of how long the string is.
 
---
 
## Little-Endian Memory
 
One more thing you need burned in before you write any exploit code.
 
x86 is **little-endian**. Multi-byte values are stored in memory with the least significant byte at the lowest address.
 
So the address `0x42658ade` in memory looks like:
 
```
Address:  0x00   0x01   0x02   0x03
Value:    de     8a     65     42
```
 
When you build a Python payload and need to put an address in your buffer, you have to account for this:
 
```python
import struct
struct.pack("<I", 0x42658ade)
# produces: b'\xde\x8a\x65\x42'
```
 
The `<I` means little-endian unsigned 32-bit integer. Get this backwards and your exploit crashes every time at `ret` because EIP gets loaded with the wrong address. This is one of the most common reasons a first exploit attempt fails.
 
---
 
## The Exploit Primitive
 
Here is where it all connects.
 
`buf[16]` lives near the bottom of the stack frame. If a function copies user-controlled data into `buf` without checking the length, that data writes upward in memory. It fills the buffer first, then keeps going.
 
Starting from the first byte of `buf`:
 
```
Bytes 1-16    fill buf[16]
Bytes 17-20   overwrite saved EBP
Bytes 21-24   overwrite the return address
```
 
**Offset to EIP = 20 bytes**
 
When the function returns and `ret` executes, it pops whatever is at ESP into EIP. You put your own address at offset 21. The CPU jumps there. You own execution.
 
That is the primitive. That is what every stack overflow in this course is built on.
 
---
 
## Calculating the Offset: The Formula
 
```
offset to EIP = size of buf
              + size of locals at HIGHER addresses than buf
              + 4 bytes for saved EBP
```
 
The tricky part is the second term. Locals at higher addresses than `buf` sit between `buf` and `saved EBP`. You have to overflow through them to reach `saved EBP` and then the return address.
 
Locals at **lower** addresses than `buf` are irrelevant. The overflow travels upward, away from them.
 
Example:
 
```c
void vuln(char *input, int len) {
    char buf[64];
    int check;
}
```
 
Stack after prologue:
 
```
High Address
┌─────────────────┐
│      len        │  argument
├─────────────────┤
│   input ptr     │  argument (4-byte pointer)
├─────────────────┤
│  return address │  [ebp+4]
├─────────────────┤
│   saved EBP     │  [ebp]
├─────────────────┤
│    buf[64]      │
├─────────────────┤
│     check       │  ESP points here
└─────────────────┘
Low Address
```
 
`check` is below `buf`. Overflow never touches it. `saved EBP` is directly above `buf`.
 
Offset to EIP = 64 + 4 = **68 bytes**.
 
---
 
## WinDbg: Reading the Stack Live
 
Once you are in a debugger staring at a crash, these are the commands you run immediately:
 
```
dd ebp      read saved EBP (tells you if the frame is corrupted)
dd ebp+4    read the return address (tells you what EIP will become)
dd esp      read the top of the stack
k           show the full call stack
r           dump all registers
```
 
If you see a pattern like `41414141` at `[ebp+4]`, that means you've overwritten the return address with `AAAA` and you now know your overflow is reaching EIP. From there it is a matter of finding the exact offset and replacing those bytes with something useful.
 
---
 
## Quick Reference
 
| Instruction    | What It Does                                        |
|----------------|-----------------------------------------------------|
| `push ebp`     | Save caller's frame pointer onto the stack          |
| `mov ebp, esp` | Anchor EBP to current stack top                     |
| `sub esp, N`   | Reserve N bytes for local variables                 |
| `mov esp, ebp` | Collapse locals, ESP jumps back to saved EBP        |
| `pop ebp`      | Restore caller's EBP, ESP moves to return address   |
| `ret`          | Pop return address into EIP, jump there             |
 
---
 
## Key Takeaways
 
- The stack grows downward. Push moves ESP toward lower addresses.
- Arguments are pushed right to left by the caller before `CALL`.
- `CALL` = push return address + jump to function.
- The prologue sets up the frame in three instructions. The epilogue tears it down in three instructions.
- EBP is fixed for the life of the function. Arguments are at positive offsets from EBP. Locals are at negative offsets.
- `ret` = pop EIP. If you control what is at ESP when `ret` executes, you control where the CPU goes next.
- Overflow travels upward in memory. Locals below the buffer are never reached.
- x86 is little-endian. Addresses in payloads must be packed bytes-reversed.
- Offset to EIP = size of buf + locals above buf + 4 (saved EBP).