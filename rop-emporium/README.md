# ROP Emporium

## What is ROP?

**ROP (Return-Oriented Programming)** is an exploitation technique used to bypass security protections like **NX (No-Execute)** , which prevents code execution on the stack.

### A Simple Analogy

Imagine a criminal in prison who wants to send a threatening letter. He's not allowed to write anything himself. But he has access to old newspapers and magazines. He cuts out individual letters from these newspapers — letters that already exist — and glues them together to form his message.

**ROP works the same way:**

- The **newspapers** = the binary's existing code
- The **cut-out letters** = gadgets (small instruction sequences ending with `ret`)
- The **glued message** = the ROP chain
- The **criminal** = the attacker controlling the stack

Instead of injecting new code (which is blocked), the attacker reuses small pieces of code already present in the binary — each piece ending with a `ret` instruction — and chains them together to perform any operation.

### Why ROP?

ROP allows attackers to:
- Bypass NX protection
- Call functions with custom arguments
- Write to memory
- Build complex exploits without injecting shellcode

## Challenges

The ROP Emporium challenges teach this technique step by step:

```
ret2win
split
callme
write4
badchars
fluff
pivot
ret2csu
```

---

[🏠 Home](../README.md)
