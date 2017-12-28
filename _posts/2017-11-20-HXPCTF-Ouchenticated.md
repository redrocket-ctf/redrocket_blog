---
layout: post
category: Crypto
title: hxpCTF Ouchenticated
tags: 
    - rg
---

The challenge came with the "description":

```
Nobody ain’t need no proper crypto!

Connection:
nc 35.198.105.111 32773
```

and the following Python program:

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os, binascii, struct, zlib, json

enc_key = os.urandom(0x10)
mac_key = os.urandom(0x10)

def crc(bs):
    return 0xffffffff ^ zlib.crc32(bs)

def authenc(m):
    s = m + mac_key
    s = s + struct.pack('<L', crc(s))
    assert not crc(s)
    aes = AES.new(enc_key, AES.MODE_CTR, counter = Counter.new(128))
    return aes.encrypt(s)

def authdec(c):
    aes = AES.new(enc_key, AES.MODE_CTR, counter = Counter.new(128))
    s = aes.decrypt(c)
    assert not crc(s)
    assert s[-4-16:-4] == mac_key
    return s[:-4-16]

cipher = authenc(json.dumps({'admin': 0}).encode())
print(binascii.hexlify(cipher).decode())
cipher = binascii.unhexlify(input().strip())
obj = json.loads(authdec(cipher).decode())
if obj['admin']:
    print('The flag is: {}'.format(open('flag.txt').read().strip()))
```

The program tries to implement an authenticated encryption system using AES-128 in counter mode using a CRC-32 "MAC", a random 16 bytes MAC key and a random 16 bytes encryption key.

The service issues an encrypted version of the JSON object ```{'admin': 0}```. The goal is, to change the value of the admin attribute to something that is true in Python terms. In other words: we have to manipulating the given cipher text to decrypt to ```{'admin': 1}```.

Since the encryption is done in CTR mode and we know the encrypted string, changing the 0 to 1 is fairly easy. 

In [counter mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR), the encryption of plaintext P works by XORing the output of the AES encryption with key K and the counter value CTR:{% katex %}C_i = P_i \oplus E_K(CTR_i){% endkatex %}. 

The decryption works analogously: {% katex %}P_i = C_i \oplus E_K(CTR_i){% endkatex %}.

This means that, given a ciphertext, we can change the values in the resulting decrypted text just by XORing the bits we want to flip (here X) with the ciphertext. The decryption then proceeds as {% katex %}P'_i = C_i \oplus X \oplus E_K(CTR_i){% endkatex %}, resulting in an attacker controlled plaintext.

To change the value of the plaintext in this task from ASCII 0 to ASCII 1, we just need to flip the corresponding bit in the cipher text. In our case, thats the last bit of the eleventh byte. Doing that in Python is simple:

```python
import binascii

hex_stuff = input("Hex string:")

b_str = bytearray(binascii.unhexlify(hex_stuff))

b_str[10] ^= 1

print(binascii.hexlify(b_str))
```

This is equivalent to XORing the given ciphertext with the same length byte string X: 

```X = 0x00000000000000000000010000000000000000000000000000000000```.

The next problem is, that the service checks decrypted strings for modification by evaluating the CRC-32 sum and checking the MAC key for modifications in the decryption routine:

```python
def authdec(c):
    aes = AES.new(enc_key, AES.MODE_CTR, counter = Counter.new(128))
    s = aes.decrypt(c)
    assert not crc(s)
    assert s[-4-16:-4] == mac_key
    return s[:-4-16]
```

Fortunately, CRC values are a very bad choice for implementing authenticated encryption. Most CRCs, such as CRC-32, work by using the bits of data as coefficients for binary polynomials. Those polynomials are divided by a specified binary generator polynomial, the remainder of this division then becomes the result. This makes CRC a linear function with respect to XOR: {% katex %}crc(a \oplus b)  = crc(a) \oplus crc(b){% endkatex %}.

In this task we can use this property, since we can compute the CRC-32 value of X. The CRC-32 value of the modified plaintext P' is the XOR result of the old plain text (including the mac key) and X: {% katex %}CRC(P') = CRC(P) \oplus CRC(X) \oplus CRC(0){% endkatex %}, where 0 is the CRC initalization vector consisting of zero bytes.

This Python snippet shows the linearity by outputting the difference between the encrypted CRC-32 values:

```python

def crc(bs):
    return 0xffffffff ^ zlib.crc32(bs)

def authenc(m):
    s = m + mac_key
    s = s + struct.pack('<L', crc(s))
    return s

for i in range(3):
    mac_key = os.urandom(0x10)
    crc_zero = authenc(json.dumps({'admin': 0}).encode())[-4:]
    crc_one = authenc(json.dumps({'admin': 1}).encode())[-4:]

    xor_res = bytearray([crc_zero[i] ^ crc_one[i] for i in range(4)])
    print("XOR: ",
          binascii.hexlify(xor_res).decode(), 
          "->", 
          bin(int.from_bytes(xor_res, "little"))
    )
```

The output, given different MAC keys is:

```
XOR:  e1b652ef -> 0b11101111010100101011011011100001
XOR:  e1b652ef -> 0b11101111010100101011011011100001
XOR:  e1b652ef -> 0b11101111010100101011011011100001
```

Meaning that, independent of the MAC, the difference between the encryped versions of the CRC value is always the same.

This difference is the CRC-32 value of X: {% katex %}CRC(X) \oplus CRC(0){% endkatex %}.

For the funsies, we can verify that by calculating the CRC 32 value of X:

```python
import zlib
from binascii import hexlify
import struct
X = int.to_bytes(
    0x00000000000000000000010000000000000000000000000000000000, 
    60, "big")
zero = bytes(len(X))

crc_X = zlib.crc32(X)
crc_zero = zlib.crc32(zero)

print(hex(crc_X ^ crc_zero))
```

which also gives us: `0xef52b6e1`!

Using all that we can exploit the service with this script:

```python

from binascii import hexlify, unhexlify

hex_stuff = input("Hex string:")

b_str = bytearray(unhexlify(hex_stuff))
b_str[10] = b_str[10] ^ 1 # flip 0 to 1

# Difference between encrypted CRCs
mask = unhexlify("e1b652ef")

# align crc 32
for i in range(-4, 0):
    b_str[i] = b_str[i] ^ mask[i]

print(hexlify(b_str))
```

Running it with an encrypted string gives us:

```
$ python3 expl.py
Hex string:b909dfa17ed9d0af67b35a0201f5094e6e36b90fecce0f034fa2c9439c29155d
b'b909dfa17ed9d0af67b35b0201f5094e6e36b90fecce0f034fa2c9437d9f47b2'
```

Entered in the original service, we get:

```
b909dfa17ed9d0af67b35a0201f5094e6e36b90fecce0f034fa2c9439c29155d
b909dfa17ed9d0af67b35b0201f5094e6e36b90fecce0f034fa2c9437d9f47b2

hxp{CRC:_c0mpL3t3ly_r3duNd4nT_crYpT0gr4pH1c4LLy}
```

\o/
