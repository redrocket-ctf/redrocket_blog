---
layout: post
category: Crypto
title: hxpCTF 2018 - daring
tags: 
    - rg
---

Daring was a pretty straight forward entry level task of this years hxp CTF.

We're giving this python script:

```python
#!/usr/bin/env python3
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from Crypto.PublicKey import RSA

flag = open('flag.txt', 'rb').read().strip()

key = RSA.generate(1024, e=3)
open('pubkey.txt', 'w').write(key.publickey().exportKey('PEM').decode() + '\n')
open('rsa.enc', 'wb').write(pow(int.from_bytes(flag.ljust(128, b'\0'), 'big'), key.e, key.n).to_bytes(128, 'big'))

key = SHA256.new(key.exportKey('DER')).digest()
open('aes.enc', 'wb').write(AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(flag))
```

as well as the public key and the encrypted files rsa.enc and aes.enc.

Since AES is used in counter mode, we know that the flag is 43 bytes long.
 
Looking at the RSA encryption we see two things:

* Small exponent (3)
* The flag is padded with trailing null bytes


Since we know the size of the flag, we can just multiply the cipher text with the encryption of the multiplicative inverse of the padding (0x100000000...).

The result would be (with m=flag and p=padding):

{% katex display %}
(m \cdot p)^3 \cdot (p^{-1})^3 \equiv m^3 \mod N
{% endkatex %}

For a small m, we should be able to simply compute the third root of the resulting ciphertext. Since m is small we don't need to worry about the modulus N.

Unfortunately its not *quite* that simple, because the flag is one byte too long for this to work.

There are multiple ways to still make this work. 

I decided to just cancel out some factor of the number that represents the flag. To do this, I just ran a loop multiplying the cipher text with the inverse of this factor, taking the cube root, then multiply by this factor.

Once we hit a factor x of the flag, we get the number z:

{% katex display %}
z \equiv (m \cdot x^{-1})^3 \mod N
{% endkatex %}

This number should be short enough for us to be able to take the cube root, then multiply it by the factor x:

{% katex display %}
m = x \cdot \sqrt[3]{(m \cdot x^{-1})^3}
{% endkatex %}

The exploit looks like this:

```python
from Crypto.PublicKey import RSA
import gmpy2

pubkey = RSA.import_key(open("pubkey.txt").read())
rsa_enc = int.from_bytes(open("rsa.enc", "rb").read(), "big")

flag_len = 43

for factor_candidate in range(10000):
    r = gmpy2.invert(2**((128 - flag_len)*8), pubkey.n)
    try:
        fac_r =  gmpy2.invert(factor_candidate, pubkey.n)
    except Exception:
        continue
    enc_r = pow(r, pubkey.e, pubkey.n)
    enc_fac = pow(fac_r, pubkey.e, pubkey.n)

    new_enc = (rsa_enc * enc_r * enc_fac) % pubkey.n
    root, succ = gmpy2.iroot(new_enc, pubkey.e)
    res = int.to_bytes(int(root) * factor_candidate, 100, "big")

    if b"hxp" in res:
        print("factor {}: {}".format(factor_candidate, res[-43:]))
        break
```

And gives us:

```
factor 83: b'hxp{DARINGPADS_1s_4n_4n4gr4m_0f_RSAPADDING}'
```

\o/
