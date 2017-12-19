---
layout: post
category: Misc
tags: 
    - kowu
---

When connecting to the challenge we were greeted with a matrix like animation.

![m1](http://blog.redrocket.club/assets/img/3ds_matty1.png)

I first tried to find some hidden messages in the printed chars. I did:
* Check the distance between chars
* Check the amount of printed chars
* Check for hidden bitstrings encoded as bold and thin printed chars
* Check for whitespace and 'whitespace like' character use

But realised (pretty late) that everything was completely equally distributed and no cyclic occurrences at all. So probably no hidden mesages in there.

However there is still hope. If we write some data it would be echoed. This is unusual behaviour as it needs to be implemented on purpose. I tried a lot of special chars, quoutes and escape sequences without success. Also the challenge was in misc, so propably no pwnage here.

I was really clueless at that moment and spend way too much time on the challenge by that time so I decided to just pipe some random bullshit into it and wait for what it returns.
```python
from pwn import *
import random

r = remote('mattryx01.3dsctf.org', 8012)


if __name__ == '__main__':
    while True:
        pl = ''
        for n in range(random.randint(1, 20)):
            pl += chr(random.randint(0, 255))
        r.sendline(pl)
        print(r.recvline())
```
Aaaand we got a crash after a few seconds. And a base64 encoded string.
![m1](http://blog.redrocket.club/assets/img/3ds_matty2.png)
It turns out that the base64 string decodes to '3DS{M3rRy_ChR', wich is the beginning of a flag.
Okay I see we probably send some control characters and for some reason it crashed and gave us a part of the flag.
We now could investigate more and look wich secquence caused the crash, but I had an even better Idea. Just crash it a few more times.
Finally we got three different base64 encoded strings wich, decrypted and concaternated, resulted in the flag:

`3DS{M3rRy_ChR15Tm45_W17H_0uR_S1Gn4L5_}`
