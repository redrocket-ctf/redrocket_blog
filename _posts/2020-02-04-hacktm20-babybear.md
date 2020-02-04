---
layout: post
category: Rev
title: HackTM - Babybear
tags: 
    - kowu
---

Babybear was a simple reversing challenge, and I solved it the hard way by reversing the whole thing.

```
user@KARCH ~/ctf/bear % ./baby_bear 

  (c).-.(c)    █  █         █         █
   / ._. \     █  █         █         █
 __\( Y )/__   █  ███   ███ ███  █  █ ███   ███   ███ █ ██
(_.-/'-'\-._)  █  █  █ █  █ █  █  ██  █  █ █████ █  █ ██
   || X ||     █  █  █ █  █ █  █  █   █  █ █     █  █ █
 _.' `-' '._   █  ███   ███ ███  █    ███   ███   ███ █
(.-./`-'\.-.)  █
 `-'     `-'   █  Baby bear says: 1110111010010001101111100110000001110000000110

What do you say? AAAAAAAA
1111001100110011001100110011001101000101010101
Baby bear is thinking...

"Someone's been eating my porridge and they ate it all up!" cried the Baby bear.
```

There is some translation function, which translates input into a sequence of 1s and 0s.
The challenge is to find some input which leads to the same sequence as the one babybear got.
Bruteforcing is not an option because we neet to proove against the remote server and the secret is a 16Byte value from urandom.

## Unpacking

The whole thing is UPX packed, however it would not unpack by using the default UPX tool.
So I just started the packed executable in radare2, continued until the text input appears, and took a memory snapshot of the unpacked region. (which is a valid ELF file for itself as well)

```
[0x004005dd]> dm
0x0000000000400000 - 0x0000000000401000 * usr     4K s r-x /home/user/ctf/bear/baby_bear /home/user/ctf/bear/baby_bear ; map.home_user_ctf_bear_baby_bear.r_x
0x0000000000600000 - 0x0000000000601000 - usr     4K s rwx /home/user/ctf/bear/baby_bear /home/user/ctf/bear/baby_bear ; map.home_user_ctf_bear_baby_bear.rwx
0x0000000000601000 - 0x0000000000602000 - usr     4K s rwx unk0 unk0 ; map.unk0.rwx
0x00007ffc88b21000 - 0x00007ffc88b43000 - usr   136K s rwx [stack] [stack] ; map.stack_.rwx
0x00007ffc88bcd000 - 0x00007ffc88bd0000 - usr    12K s r-- [vvar] [vvar] ; map.vvar_.r
0x00007ffc88bd0000 - 0x00007ffc88bd1000 - usr     4K s r-x [vdso] [vdso] ; map.vdso_.r_x
[0x004005dd]> s 0x0000000000600000
[0x00600000]> dmd
Dumped 4096 byte(s) into 0x00600000-0x00601000-rwx.dmp
[0x00600000]> 
```
We can now continue working with the unpacked version.

## Reversing

Initially my first thought was to just bruteforce byte by byte, as the input seemed to be transformed linear (i.e. leaving the first byte the same least to the same start of the output sequence).
But as the challenge was network based I was afraid of hitting a timeout before I could obain some result. So I started reversing the translation function. As the binary seemed to be handwritten in assembly this was a little painful.


Basically what it does is creating a binary representation of the input bytes in memory. Then it traverses some Graph, where each node consumes one bit of the input. Depending on the input the next node is choosen, and sometimes value(s) are omitted ("1" or "0", leading to the output sequence). After 46 omitted values the translation function returns.


So what I did was placing brakepoints on all `cmpsb byte [rsi], byte ptr [rdi]`, `scasb al, byte [rdi]` and `lodsb al, byte [rsi]` instructions, as well as on the output function. Those are my nodes. Then I took pen and paper and traced the graph for a known input until I reconstructed the whole graph. This was some kind of a sisiphus work and I got mad on every new node, but it must have been worse for the challenge author to construct this task in plain ASM :D

![m1](/assets/img/beargraph.jpg)

Then, I implemented the graph in Python so I could perform a fast translation. Based on this I did a simple bruteforce search, even had to limitate the amount of states kept to 10 to avoid a combinatorial explosion.

```python
import string


class Graph:
    def __init__(self, data):
        self.path = []
        self.data = data[:]
        self.length = 0x2e

    def finished(self):
        return self.length <= 0 or not self.data

    def emit(self, value):
        self.path.append(value)
        self.length -= 1

    def x366(self, x):
        if x:
            self.emit(1)
            return self.x34d
        self.emit(0)
        return self.x3de

    def x34d(self, x):
        if x:
            return self.x457
        return self.x40b

    def x457(self, x):
        if x:
            self.emit(0)
            return self.x3b0
        return self.x37e

    def x40b(self, x):
        if x:
            self.emit(1)
            self.emit(0)
            return self.x3b0
        self.emit(1)
        return self.x37e

    def x3de(self, x):
        if x:
            self.emit(0)
            return self.x379
        return self.x3e9

    def x3e9(self, x):
        if x:
            return self.x37e
        self.emit(0)
        return self.x470

    def x470(self, x):
        if x:
            self.emit(1)
            return self.x482
        return self.x44c

    def x44c(self, x):
        if x:
            self.emit(0)
            return self.x3c4
        return self.x3c7

    def x482(self, x):
        if x:
            self.emit(0)
            return self.x3c4
        return self.x44c

    def x3c4(self, x):
        if x:
            return self.x3c7
        return self.x366

    def x3c7(self, x):
        if x:
            self.emit(1)
            return self.x366
        self.emit(1)
        return self.x11b

    def x11b(self, x):
        if x:
            return self.x366
        self.emit(0)
        return self.x470

    def x39c(self, x):
        if x:
            self.emit(0)
            return self.x3b0
        self.emit(1)
        return self.x482

    def x3b0(self, x):
        if x:
            self.emit(0)
            return self.x3c4
        return self.x366

    def x37e(self, x):
        if x:
            return self.x39c
        self.emit(1)
        return self.x482

    def x379(self, x):
        if x:
            return self.x40b
        return self.x37e

    def traverse(self):
        current = self.x366
        while not self.finished():
            current = current(self.data.pop(0))
        return self.path


def tobin(key):
    res = ''
    for c in key:
        res += '{:08b}'.format(ord(c))[::-1]
    return [1 if c == '1' else 0 for c in res]


def arrstartswith(arr, pre):
    return arr[:len(pre)] == pre


result = [1 if x == '1' else 0 for x in '0010111111001000100111101111111011000100100100']


states = ['']
for _ in range(12):
    newstates = []
    for state in states:
        newstates += [state + x for x in string.letters]
    states = filter(lambda x: arrstartswith(result, Graph(tobin(x)).traverse()), newstates)[:10]

print(states)

```
