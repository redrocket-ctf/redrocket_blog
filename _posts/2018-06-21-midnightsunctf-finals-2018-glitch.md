---
layout: post
category: Pwn
title: MidnightsunCTF finals 2018 glitch
tags: 
    - kowu
---

We got some 32 bit binary with the following metalogic:
```c
int secret = gettruerandomnum() & 0x10decafe;
char *username = readusername();
int guess = readguess();
logattempt(username, guess);
sleep(3);
if (guess == secret)
    system("/bin/sh");
exit(0);
```

long story short, in the `logattempt` function we had a formatstring vulnerability. But we could not overwrite the secret with `%n` as there was no pointer to it on the stack. Also there was a small size limit for the formatstring to do anything else. The only interesting thing we could overwrite was our own guess. If we open up the man(3) page of printf we see an example for the usage of a variable argument `printf("%2$*1$d", width, num);`. It will print num in decimal format padded by whitespaces so it reaches the length num. Now thats something we could use. We just print something and use the secret as a padding. Then we can write the number of written bytes (correct secret) into our guess. Finally we get some payload like this `%26$*26$d%15$n`.
