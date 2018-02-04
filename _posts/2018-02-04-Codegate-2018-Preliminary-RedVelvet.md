---
layout: post
category: Rev
title: Codegate CTF 2018 Preliminary RedVelvet
tags: 
    - kowu
---

This writeup describes how to solve the challenge with the help of angr.
The challenge itself is a simple password input prompt wich outputs the flag afterwards.

As the disassembled code looked like it would be easily solveable by angr I just wrote a small script.
From looking at the disassembled code we can tell angr
- where we want to go (right after passing all checks)
- what to avoid (exit calls)
- the needed length of the input string

Furthermore I patched out a useless ptrace call and filled it with nops. I don't know if that was necessary, but it reduced complexity for angr (no need to emulate it).

```python
import angr

p = angr.Project('./RedVelvetPatch', load_options={"auto_load_libs": False})

st = p.factory.entry_state()

# in printable range
for _ in xrange(26):
    k = st.posix.files[0].read_from(1)
    st.solver.add(k >= 0x20)
    st.solver.add(k <= 0x7e)

# Constrain the last byte to be a newline
k = st.posix.files[0].read_from(1)
st.solver.add(k == 10)

# Reset the symbolic stdin's properties and set its length.
st.posix.files[0].seek(0)
st.posix.files[0].length = 27

sm = p.factory.simulation_manager(st)
sm.explore(avoid=0x004007d0, find=0x0040152d)

print(sm.found[0].posix.dumps(0))
```
After a few Minutes we got `What_You_Wanna_Be?:)_lc_la`, but this is not the correct password / flag. Sometimes there are more than one solution when dealing with constraint solvers. But I noticed that there is a md5sum check included in the binary, so I just wrote a Python script bruteforcing the last 6 characters as the rest looked pretty good. This took too much time so i just decided to bruteforce the "lc" and "la" part, assuming the "_" to be correct.
I immediately got the flag `What_You_Wanna_Be?:)_la_la`.
