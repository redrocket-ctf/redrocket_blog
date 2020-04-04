---
layout: post
category: Rev
title: HackTM - Papabear
tags: 
    - kowu
---

The challenge generates a mustache based on argv[1] input. Challenge authors supplied us with the target mustache, which we had to match.


[Download](../assets/bin/hacktm_papa_bear)

```
user@KARCH ~/ctf/papa % ./papa_bear AAAAA
   ______   _______  ______   _______      ______   _______  _______  ______
  (_____ \ (_______)(_____ \ (_______)    (____  \ (_______)(_______)(_____ \
   _____) ) _______  _____) ) _______      ____)  ) _____    _______  _____) )
  |  ____/ |  ___  ||  ____/ |  ___  |    |  __  ( |  ___)  |  ___  ||  __  /
  | |      | |   | || |      | |   | |    | |__)  )| |_____ | |   | || |  \ \
  |_|      |_|   |_||_|      |_|   |_|    |______/ |_______)|_|   |_||_|   |_|

            dWMM=-        dWWMWWMMWWMWb  dWMMWWMWWMMWb        -=WMWb
          dWMMP       dWWMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMb        qMMb
          MMMMb   dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMb    dMMM
          qMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMP
            QMMMMMMMMMMMMMMMMMMMMMMMMMP  QMMMMMMMMMMMMMMMMMMMMMMMMMMP
              QMMMMMMMMMMMMMMMMMMMP          QMMMMMMMMMMMMMMMMMMMP
                     QMMMMMMP                         QMMMMMMP

```

Like in babybear, the input transformation into the mustache was linear. So this time I tried to solve it without reversing at all, just by bruteforce.

## Patching
I tried to run the binary with python subprocess.getoutput aaaand it did not work. (output was always empty)
A look with strace on the binary revealed that the output is written to stdin, and not stdout.
As there was only one position where the output is written, I just patched the file descriptor from 0 to 1. (`r2 -w papa_bear`, seek to the write, and patch the rdi assignment to `wa mov rdi, 1`)
Now everything works as expected.

## Bruteforcing

We now can just guess byte by byte until we match the desired mustache. Sometimes manual intervention is necessary to prevent a path explosion (it seems like the @ symbol can cause recursion).

```python
import subprocess
import string

soll = """
dWWW=- dWWMWWWWWMWMb dMMWWWWWWWWWb -=MMMb
dWMWP dWWWMWWWMMWMMMWWWWWMMMMMMWMMMWWWMMMb qMWb
WMWWb dMWWMMMMMMWWWWMMWWWMWWWWWWMMWWWWMWMWMMMWWWWb dMMM
qMMWMWMMMWMMWWWMWMMMMMMMMWMMMMWWWMMWWMWMWMMWWMWWWWMWWMMWMMWP
QWWWWWWWMMWWWWWWWMMWWWWMMWP QWWWMWMMMMWWWWWMMWWMWWWWWWMP
QWMWWWMMWWMWMWWWWMWWP QWWMWWMMMWMWMWWWWMMMP
QMWWMMMP QMMMMMMP
"""


def normalize(data):
    return ''.join(filter(lambda c: c if c in ['W', 'M'] else '', data)).replace('W', '1').replace('M', '0')


soll = normalize(soll)

states = ['HackTM{F4th3r bEaR s@y$: Smb']
while states:
    newstates = []
    for state in states:
        for c in string.digits + string.ascii_letters + string.whitespace + r"""!"#%&'()*+,-./:;<=>?@[\]^_`{|}~""":
            ist = subprocess.getoutput("./papa_bear '{}'".format((state + c).replace("'", "'\\''")))
            ist = ''.join(ist.splitlines()[7:])
            ist = normalize(ist)
            ist = ist[:ist.rfind('1') + 1]
            if soll.startswith(ist):
                newstates.append(state + c)
    states = newstates
    print(states)
```
