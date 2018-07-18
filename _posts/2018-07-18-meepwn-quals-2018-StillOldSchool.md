---
layout: post
category: Crypto
title: MeePwn CTF Quals 2018 - Still Old School
tags: 
    - rg
---

In this nice challenge we were given the following Python script and a
TCP port to connect to:

```python
from secret import flag, mask1, mask2
import string
import random
import sys
import os
import signal
import hashlib
from Crypto.Cipher import AES

menu = """
CHOOSE 1 OPTION
1. Encrypt message
2. Decrypt message
3. Get encrypted flag
4. Exit\n
"""

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
bs = 16

def to_string(num, max_len = 128):
    tmp = bin(num).lstrip('0b')[-max_len:].rjust(max_len, '0')
    return "".join(chr(int(tmp[i:i+8], 2)) for i in range(0, max_len, 8))

def pad(s):
	padnum = bs - len(s) % bs
	return s + padnum * chr(padnum)

def unpad(s):
	return s[:-ord(s[-1])]

def gen_key(mask):
	tmp1 = random.random()
	tmp2 = random.random()
	key = int(tmp1 * 2**128) | int(tmp2 * 2**75) | (mask & 0x3fffff)
	key = to_string(key)
	return key

def encrypt_msg(msg, key1, key2):
	iv = to_string(random.getrandbits(128))
	aes1 = AES.new(key1, AES.MODE_CBC, iv)
	aes2 = AES.new(key2, AES.MODE_CBC, iv)
	enc = aes1.encrypt(aes2.encrypt(pad(msg)))
	return (iv + enc).encode("hex")

def proof_of_work():
    """
    This function has very special purpose 
    :)) Simply to screw you up
    """
    prefix = to_string(random.getrandbits(64), 64)
    print 'prefix = {}'.format(prefix.encode('hex'))
    challenge = raw_input('> ')
    tmp = hashlib.sha256(prefix + challenge).hexdigest()
    if tmp.startswith('00000'):
        return True
    else:
        return False

key1 = gen_key(mask1)
key2 = gen_key(mask2)

signal.alarm(300)

if not proof_of_work():
	exit(0)

for _ in range(256):
	print menu
	try:
		choice = int(raw_input("> "))
	except:
		print "wrong option"
		exit(-1)
	if choice == 1:
		msg = raw_input("give me a string: ")
		print encrypt_msg(msg, key1, key2)
	elif choice == 2:
		print "Not implement yet..."
	elif choice == 3:
		print encrypt_msg(flag, key1, key2)
	elif choice == 4:
		exit(-1)
	else:
		print "wrong option"
		exit(-1)
```

So with this service we are able to get either the flag or a submitted string,
encrypted two times with AES using two different keys: 

```python
def encrypt_msg(msg, key1, key2):
	iv = to_string(random.getrandbits(128))
	aes1 = AES.new(key1, AES.MODE_CBC, iv)
	aes2 = AES.new(key2, AES.MODE_CBC, iv)
	enc = aes1.encrypt(aes2.encrypt(pad(msg)))
	return (iv + enc).encode("hex")
```

The two AES keys get generated on startup using Pythons random function:

```python
def gen_key(mask):
	tmp1 = random.random()
	tmp2 = random.random()
	key = int(tmp1 * 2**128) | int(tmp2 * 2**75) | (mask & 0x3fffff)
	key = to_string(key)
	return key
```

Each key also contains a secret mask that could be up to 22 bits long.

The `to_string` method just creates a byte string out of the calculated numbers, equivalently to Python3's `int.to_bytes`.

Pythons random.random function is not a cryptographically secure RNG, so we should be able
to recover the variables tmp1 and tmp2 once we get our hands on enough outputs.

Luckily, the used IV for the CBC mode encryption supplied to us uses the same PRNG:

```python
iv = to_string(random.getrandbits(128))
```

After recovering the variables tmp1 and tmp2 for each key, we need to brute force the mask
for each of the keys.

## Reversing the Mersenne Twister

The server side uses Python2, which can be seen on the `print` statements.
CPython 2.7 uses (as many other Interpreters and Libraries) the Mersenne Twister Pseudo Random Number
Generator.

The Mersenne Twister works on an internal state of 624 int32 values. 
The numbers of the internal state have the following relationship:

{% katex display %}
\begin{array}{lcl}
h   & := & Y_{i-N} - Y_{i-N} \, \bmod \, 2^{31} + Y_{i-N+1} \, \bmod \, 2^{31} \\
Y_i & := & Y_{i-227} \;\oplus\; \lfloor h/2 \rfloor \;\oplus\; ((h \, \bmod \, 2) \cdot \mathtt{9908B0DF_{hex}})
\end{array}
{% endkatex %}

With `N = 624` as the size of the internal state.
Meaning that every number depends on 3 numbers that came before it.

Before the current number is outputted, it gets mangled to meet some statistical properties.
The [CPython source code](https://github.com/certik/python-2.7/blob/master/Modules/_randommodule.c) shows this:

```c
[...]
y = mt[self->index++];
y ^= (y >> 11);
y ^= (y << 7) & 0x9d2c5680UL;
y ^= (y << 15) & 0xefc60000UL;
y ^= (y >> 18);
return y;
```

So in order to recover the variable tmp1, we'd need to:

* Request 156 random IVs (since every IV is made of four `int32`)
* Reverse the bit mangling of the output to receive the internal state {% katex %} Y_i {% endkatex %}
* Calculate the state {% katex %} Y_{i - N + 1} {% endkatex %} which was used in the `random.random` function
* Recreate the `gen_key` function with our recovered pseudo random number

Unfortunately it's not that easy. But almost. 
By looking at the way, internal states get calculated we see that the last bit of our targeted state
is lost in the process. The highest bit of our targeted state can be recovered by looking at the successor 
state {% katex %} Y_{i + 1} {% endkatex %}  (only the highest bit gets used, see above). 
This means we get 2 possible numbers per recovered internal state.

Since the `random.random` function uses two int32 values:

```c
static PyObject * random_random(RandomObject *self)
{
    unsigned long a=genrand_int32(self)>>5, b=genrand_int32(self)>>6;
    return PyFloat_FromDouble((a*67108864.0+b)*(1.0/9007199254740992.0));
}
``` 

We get `2*2` possible outputs per `random.random` call. Since the function is called two times 
per key and we have two keys, there are {% katex %} (2^2)^2  = 16{% endkatex %} possibilities how each
keys could look like.

So after requesting 156 128-bit IVs we split them up in 32 bit chunks that represent the output
of the mersenne twister:

```python
def output128_to_32(outputs):
    for o in outputs:
        bn = o.to_bytes(16, "little")
        for i in range(4):
            outputs32.append(int.from_bytes(bn[i*4:(i+1)*4], "little"))
    return outputs32
```

We then proceed to reverse the mangling of the outputs to get the internal state  {% katex %} Y_i {% endkatex %}
and finally calculate the candidates for all the pseudo random int32's that were used during key generation:

```python
def inv(x):
    x ^= (x >> 18)
    # Lowest 16 bit stay how they are, so we can just repeat...
    x ^= (x << 15) & 0xEFC60000
    # Do it step by step
    x ^= (x << 7) & 0x1680
    x ^= (x << 7) & 0xC4000
    x ^= (x << 7) & 0xD200000
    x ^= (x << 7) & 0x90000000
    # Only highest 11 bits are untouched
    x ^= (x >> 11) & 0xFFC00000
    # Do step by step again
    x ^= (x >> 11) & 0x3FF800
    x ^= (x >> 11) & 0x7FF
    return x
    
def recover_state(i, outputs32):
    """
    return all possible candidates for state how it was (i-624) iterations ago!
    """


    Y = inv(outputs32[i - 1])
    h_1 = Y ^ inv(outputs32[i - 227 - 1])
    Y_old = inv(outputs32[i])
    h_1_msb = ((Y_old ^ inv(outputs32[i - 227]))>>30) & 1

    h_2 = h_1 
    h_2_alt = h_1 ^ 0x9908B0DF

    # even case
    h_2 = (h_2 << 1) & 0x7fffffff
    # odd case
    h_2_alt = ((h_2_alt << 1)|1) & 0x7fffffff
    
    # Add the missing highest bit (recovered from successive output)
    h_2 = (h_1_msb<<31)|h_2
    h_2_alt = (h_1_msb<<31)|h_2_alt

    candidates = [h_2, h_2_alt]
    return candidates
```

We then use those candidates to create all 16 possible combinations of float values that could have been created using
the `random.random` function:

```python
def float_magic(a, b):
    """
    Rebuild of random_rancom from randommodule.c
    uses two outsputs!
    """
    a = a >> 5
    b = b >> 6
    return (a*67108864.0+b)*(1.0/9007199254740992.0)

def floats_for_cands(a_cs, b_cs):
    """
    Applies float_magic to all candidate combinations
    """
    floats = []
    for a_c in a_cs:
        for b_c in b_cs:
            floats.append(float_magic(a_c, b_c))
    return floats
```

*(The link of the full exploit script is below.)*

We also have to keep in mind that the proof of work challenge of the server uses 64 bits (two internal states)
of the PRNG between key generation and first IV. 

## Meet in the Middle
So after we can nail the variables `tmp1` and `tmp2` down to 16 candidates, we just need 
to find the secret masks of the keys.

Since we have two keys with a mask of 22 bits, we would need to brute force
{% katex %}2^{22} \cdot 2^{22} = 2^{44}{% endkatex %} keys, right? **Wrong!** 
We can employ a meet in the middle attack.

By decrypting the flag's ciphertext with all {% katex %}16 \cdot 2^{22}{% endkatex %} possible `key2` keys
and storing the results of the decryption together with the keys, we can go through all possible `key1` keys 
encrypting our plaintext and comparing the results.

So the attack works as follows:

* Send a plaintext to the server, store the returned ciphertext
* Go through all 67 million possible candidates for key2 and decrypt the ciphertext with them
* Save all 67 million ciphertext/key2 pairs in a hash table
* Go through all possible candidates for key1 and encrypt our plaintext with key1
* Compare if the encryption with key1 yields the same result as the decryption of a candidate of key2

If we found a case where the encryption of key1 matches the decryption of key2, we found our two keys!
Instead of having to go through {% katex %} 2^{44} = 17592186044416 {% endkatex %} we only have 
to go through roughly  {% katex %} 2 \cdot 2^{22} = 8388608 {% endkatex %} possible values for
`mask1` and `mask2`.

## Putting it together

The full exploit script can be found on [github](https://gist.github.com/rugo/77036ee81f6e5bd99b8ade03317b2e0b).

It is far from beeing optimized but uses the `multiprocessing` module to distribute the
work over 16 processes.

We ran the script on a optimized droplet with 64 GB RAM and 16 physical cores to get good performance.

After running the script for a couple of minutes, we got:

```
$ p3 swag.py
After Pow
At  0
At  1
At  2
At  3
[...]
The flag is: MeePwnCTF{DO_n0t_trust_anyth1ng}
```
\o/
