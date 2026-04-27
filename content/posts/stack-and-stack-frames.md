---
title: "What's Actually Happening on the Stack"
date: 2026-04-28T00:34:37+05:45
draft: false
description: "A ground up walkthrough of stacks, stack frames, and why RET is the most dangerous instruction in x64."
tags: ["windows", "internals", "exploitation", "x64", "fundamentals"]
categories: ["security-research"]
cover:
  image: "/img/stack-and-stack-frames.jpeg"
  alt: "Stack frame diagram showing return address and locals"
---

I spent the last few hours actually understanding the stack. Not the "the stack stores function calls" answer you give in an interview. The real thing. Where every byte goes, why RET is mechanically dangerous, and why a buffer overflow is just physics happening in memory.
 
I want to write this down while it's still fresh, because every resource I read assumed I already knew half of it. This is the version I wish I'd found.
 
## The Confusing Part First
 
The word "stack" gets used for two different things and nobody bothers to separate them.
 
**The stack** is a region of memory. Windows reserves about 1 MB of address space per thread for it. It just sits there for the whole life of the thread.
 
**A stack frame** is one slice of that region belonging to one function call. When `main` runs, it has a frame. When `main` calls `foo`, `foo` gets its own frame. When `foo` calls `bar`, `bar` gets a frame. Three functions running, three frames stacked up.
 
So when someone says "the stack grows down", they mean the next frame goes at a lower memory address than the previous one. The region itself doesn't move. Frames just keep getting placed lower and lower as functions get called.
 
```
HIGH ADDRESS
┌────────────────────┐
│   main's frame     │   first frame, highest address
├────────────────────┤
│   foo's frame      │   foo was called by main
├────────────────────┤
│   bar's frame      │   bar is currently running
└────────────────────┘
LOW ADDRESS              RSP points somewhere in here
```
 
The CPU has a register called RSP (stack pointer) that always points to the top of the stack, which is actually the lowest address currently in use. This trips people up. "Top" means "most recently allocated", not "highest in memory".
 
## Seeing It Live
 
Before getting into mechanics, let me show you what this looks like in a real program. I wrote a small C program that prints the addresses of variables in different memory regions:
 
```c
#include <stdio.h>
#include <stdlib.h>
 
int global_initialized = 42;
int global_uninitialized;
 
int main() {
    int local_var = 10;
    int *heap_var = (int*)malloc(sizeof(int));
    *heap_var = 99;
    
    printf("Code (main):           %p\n", (void*)main);
    printf("Initialized global:    %p\n", (void*)&global_initialized);
    printf("Uninitialized global:  %p\n", (void*)&global_uninitialized);
    printf("Stack (local_var):     %p\n", (void*)&local_var);
    printf("Heap (malloc'd):       %p\n", (void*)heap_var);
    
    free(heap_var);
    return 0;
}
```
 
Output:
 
```
Code (main):           00007FF7AAE412A8
Initialized global:    00007FF7AAE4C000
Uninitialized global:  00007FF7AAE4C2F4
Stack (local_var):     000000D7BF4FF924
Heap (malloc'd):       000002242A688160
```
 
Three completely different address ranges. The code and globals live together in the loaded executable image around `0x00007FF7...`. The stack is in its own region around `0x000000D7...`. The heap is somewhere else entirely around `0x00000224...`.
 
Run it again and you see something interesting:
 
```
Run 2:
Code (main):           00007FF7AAE412A8     ← same
Initialized global:    00007FF7AAE4C000     ← same
Stack (local_var):     000000253ECFFC64     ← changed
Heap (malloc'd):       00000204CBC67C20     ← changed
 
Run 3:
Code (main):           00007FF7AAE412A8     ← same
Initialized global:    00007FF7AAE4C000     ← same
Stack (local_var):     0000006BACDCFC04     ← changed
Heap (malloc'd):       0000023856DA81A0     ← changed
```
 
Code and global addresses don't change between runs. Stack and heap addresses do. That's ASLR. The image base only randomizes once per boot, but stack and heap re-randomize every time a process starts.
 
For exploit dev this matters. Each region needs its own information leak to defeat ASLR. A code address leak doesn't help you if you need stack addresses, and vice versa.
 
## Why Down
 
There are two real answers to why the stack grows down. Both are correct.
 
The historical answer is that in the 70s memory was tiny. Designers wanted the stack and heap to share whatever memory was available. So they put the stack at the top of memory growing down, and the heap at the bottom growing up. They'd meet in the middle only when memory truly ran out. Clever for its time.
 
The hardware answer is that the CPU has it baked in. The PUSH instruction on x86/x64 literally does this:
 
```
RSP = RSP - 8
[RSP] = value
```
 
Decrement first, then store. There is no "grow up" mode. It's silicon.
 
So when I say frames stack downward, that's not a metaphor. That's the CPU mechanically subtracting from RSP every time something gets pushed.
 
## What's Inside a Frame
 
This is where it gets interesting. A stack frame is not just "local variables". It's a structured chunk of memory with very specific contents.
 
Here's the layout for x64 Windows:
 
```
HIGH ADDRESS
┌──────────────────────────┐
│  Return address          │   8 bytes, pushed by CALL
├──────────────────────────┤
│  Saved RBP               │   8 bytes, old frame pointer
├──────────────────────────┤
│  Saved non-volatile regs │   if function uses RBX, R12-R15, etc.
├──────────────────────────┤
│  Stack canary            │   /GS cookie, security check
├──────────────────────────┤
│  Local variables         │   your int x, char buf[64]
├──────────────────────────┤
│  Shadow space (32 bytes) │   reserved for callees
└──────────────────────────┘
LOW ADDRESS                    RSP points here
```
 
Going through these one at a time, because each one matters.
 
The **return address** is 8 bytes and it's the most important thing on the stack. When function A calls function B, the CPU pushes the address of the next instruction in A onto the stack. That's the return address. When B finishes, the CPU reads this value to know where to jump back to. We'll come back to this.
 
**Saved RBP** exists because some functions use RBP as a frame pointer. They save the caller's RBP before overwriting it. Debuggers use this to walk the call stack.
 
**Saved non-volatile registers** are registers that the calling convention requires the function to preserve. On Windows x64, RBX, RBP, RDI, RSI, R12-R15 must come back unchanged. If the function uses them, it has to save them on entry and restore them on exit.
 
The **stack canary** is a security feature. The compiler inserts a random 8-byte value at function entry, then checks it before returning. If a buffer overflow corrupts it, the program detects this and terminates instead of returning to attacker controlled code. Microsoft calls it `/GS`. We'll see how to bypass it later, but for now know it's there.
 
**Local variables** are your stuff. `int x`, `char buffer[256]`, whatever. Allocated by the function prologue with `sub rsp, N`.
 
**Shadow space** is uniquely Windows. The x64 Windows calling convention requires the caller to reserve 32 bytes on the stack before any call, even though the first four arguments go in registers. The callee can use this space to spill the register arguments to memory. Linux does not do this. It's why a function with no arguments still has 32 bytes reserved before any internal call.
 
## CALL and RET
 
These two instructions are where the magic happens. They're also where exploits happen.
 
When you write `call B`, the CPU does two things:
 
```
push (address of next instruction)
jmp B
```
 
The pushed value is the return address. It's now sitting on top of the stack inside B's frame.
 
When B finishes and executes `ret`, the CPU does:
 
```
pop 8 bytes from [RSP]
RIP = those 8 bytes
```
 
That's it. That's the entire mechanism. Read 8 bytes from the top of the stack, jump there.
 
Notice what's missing. There's no validation. The CPU doesn't check if the address is reasonable. It doesn't verify that the bytes are a real return address. It just trusts whatever is sitting at RSP and jumps.
 
This is the single most important fact in stack-based exploitation. If you can write 8 bytes at the right place on the stack before RET executes, you have completely controlled where the CPU goes next. You don't need fancy techniques. You just need those 8 bytes.
 
## Watching Frames Stack
 
I wrote another small program with a recursive function. Each call to `recurse(n)` printed the address of its local variable.
 
```c
#include <stdio.h>
 
void recurse(int depth) {
    int marker = depth;
    printf("Recursion depth %d: marker at %p\n", depth, (void*)&marker);
    if (depth < 5) {
        recurse(depth + 1);
    }
}
 
int main() {
    recurse(1);
    return 0;
}
```
 
The output:
 
```
Recursion depth 1: marker at 00000068BAEFFBF4
Recursion depth 2: marker at 00000068BAEFFAD4
Recursion depth 3: marker at 00000068BAEFF9B4
Recursion depth 4: marker at 00000068BAEFF894
Recursion depth 5: marker at 00000068BAEFF774
```
 
Each frame sits 0x120 bytes (288) lower than the previous. That's the size of one frame for `recurse`. Just one local int and the frame is 288 bytes. The rest is saved registers, return address, stack canary, padding for alignment, and Visual Studio's debug-mode runtime checks. Release builds would be much tighter.
 
Five frames stacked downward in memory, each one with its own copy of the marker variable, each one with its own return address pointing back to the previous depth. When `recurse(5)` finishes, its frame disappears, and `recurse(4)` resumes from where it left off. When that finishes, `recurse(3)` resumes. And so on back up to main.
 
The thing is, "frame disappears" is not really accurate. Nothing gets erased. RSP just moves back up. The old data is still sitting in memory until the next function call overwrites it. This is why old stack data sometimes leaks into new frames if functions don't initialize their locals.
 
## Debug Versus Release
 
This caught me off guard. I declared three pointer variables in order:
 
```c
int x = 42;
int *p = &x;
int **pp = &p;
```
 
Common sense says they should be allocated on the stack in declaration order. They are not. Here are the addresses from a Debug build:
 
```
&x  = 000000C9F7BEFA74
&p  = 000000C9F7BEFA98     (36 bytes higher than x)
&pp = 000000C9F7BEFAB8     (32 bytes higher than p)
```
 
So `x` is declared first but ends up at the lowest address. There's also 36 bytes of space between consecutive locals even though an int and a pointer together are only 12 bytes. That's all the debug-mode padding and security checks.
 
Compiling the same code as Release:
 
```
&x  = 00000036950FF990     (highest!)
&p  = 00000036950FF980     (lowest)
&pp = 00000036950FF988
```
 
Completely different. Different ordering, different spacing. The compiler reordered the variables and packed them tightly with only 8 bytes between locals.
 
The lesson is you cannot predict variable layout from source code. You have to look at the actual compiled binary. Two builds of the same code can have completely different stack frames. This is why exploit writeups always reference specific binary versions and offsets.
 
## Why This Matters
 
Everything I've described is the foundation of stack buffer overflow exploits. The pattern is always the same:
 
A function declares a local buffer like `char buf[16]`. The function takes user input and copies it into that buffer without checking the length. The user provides 100 bytes instead of 16. The extra 84 bytes flow upward in memory because the buffer is at a lower address and writing happens forward.
 
Those extra bytes overwrite the next thing on the stack. Then the next thing. Then the next. Eventually they reach the saved registers, then the canary, then the return address.
 
When the function finishes and executes RET, it pops the corrupted return address into RIP and jumps there. If the attacker chose a useful address, like the start of code they injected somewhere in memory, the CPU now executes their code with the privileges of the original program.
 
That's it. That's the whole concept. It's not magic. It's just the CPU doing exactly what it was designed to do, with input that the program author didn't expect.
 
The mitigations we have today exist because of this exact pattern. Stack canaries detect the corruption before RET. DEP marks the stack non-executable so injected code can't run. ASLR randomizes addresses so the attacker can't easily predict where to jump. Each one closes a specific hole in this attack chain.
 
But the underlying mechanic, RET trusting the stack, never went away. It's still there. Every exploitation technique developed since has been about working around the mitigations while exploiting that same trust.
 
## What I Took Away
 
Three things stuck with me from working through this.
 
The first is that low level stuff is mechanical, not mystical. Every behavior I called "weird" had a reason. The CPU subtracts from RSP because the silicon was designed that way. Variables are at strange offsets because the compiler chose to put them there. Code crashes at specific addresses because of specific bytes overwriting specific fields. Once you internalize that nothing is random, the whole space stops being scary.
 
The second is that source code lies to you. The C you write is not what runs. The compiler reorganizes, optimizes, adds checks, removes things. To actually understand what a program does at runtime, you have to look at the binary. This is why reverse engineering is a real skill and not just "reading code backwards".
 
The third is that security mitigations make sense once you see what they're protecting against. Stack canaries seemed like magic until I understood that RET trusts the stack blindly. Now they seem obvious. Same with DEP, ASLR, CFG, all of it. They're each a response to a specific way the underlying mechanics can be abused.
 
Next thing I want to dig into is what actually happens when you call malloc. The heap is the other major piece of process memory and I have basically the same level of intuition about it that I had about the stack two hours ago, which is to say none.