---
layout: post
category: Crypto
title: HarekazeCTF 2018 - 2 Easy Crypto Chals
tags: 
    - rg
---

The first HarakezeCTF came with some easy RSA based challenges.
Since they were fun to do and a nice math refresher, I'm gonna document two of them briefly.

## Round and Round

The first challenge came with two files, a Python script and a text file:

```python
from Crypto.Util.number import *
from Crypto.Random.random import randint

import gmpy
import key
import binascii

flag = key.FLAG
FLAG = binascii.hexlify(flag)
FLAG = int(FLAG.decode('utf-8'), 16)

def gen_n(bits=1024):
  p = getStrongPrime(bits)
  q = getStrongPrime(bits)
  return p*q, p, q

def main():
    n, p, q = gen_n()
    e = (1<<16)+1
    enc = pow(FLAG, e, n)
    p1 = (sum([pow(p-1, i, p) for i in range(q)]))
    q1 = (sum([pow(q-1, i, q) for i in range(p)]))

    print("enc =",enc)
    print("p1 =",p1)
    print("q1 =",q1)

if __name__ == "__main__":
    main()
```

```
enc = 15507598298834817042463704681892573844935925207353671096676527782423920390858333417805014479686241766827314370902570869063203100704151010294869728739155779685640415815492312661653450808873691693721178331336833872996692091804443257630828512131569609704473214724551132715672202671586891813211353984388741035474991608860773895778988812691240069777435969326282770350038882767450912160134013566175657336041694882842590560100668789803775001750959648059363722039014522592751510672658328196379883088392541680852726136345115484827400366869810045573176782889745710174383221427352027041590910694360773085666697865554456816396551
p1 = 14606124773267989759790608461455191496412830491696356154942727371283685352374696106605522295947073718389291445222948819019827919548861779448943538887273671755720708995173224464135442610773913398114765000584117906488005860577777765761976598659759965848699728860137999472734199231263583504465555230926206555745572068651194660027408008664437845821585312159573051601404228506302601502000674242923654458940017954149007122396560597908895703129094329414813271877228441216708678152764783888299324278380566426363579192681667090193538271960774609959694372731502799584057204257039655016058403786035676376493785696595207371994520
q1 = 14606124773267989759790608461455191496412830491696356154942727371283685352374696106605522295947073718389291445222948819019827919548861779448943538887273671755720708995173224464135442610773913398114765000584117906488005860577777765761976598659759965848699728860137999472734199231263583504465555230926206555745568763680874120108583912617489933976894172558366109559645634758298286470207143481537561897150407972412540709976696855267154744423609260252738825337344339874487812781362826063927023814123654794249583090654283919689841700775405866650720124813397785666726161029434903581762204459888078943696756054152989895680616
```

So we're given an RSA encrypted flag and two helper numbers {% katex %}p_1{% endkatex %} and {% katex %}q_1{% endkatex %}. The goal is to recover the two primes p and q to compute the inverse of e in {% katex %}\phi(p \cdot q){% endkatex %} (the private key) and decrypt the flag.

The helper numbers are build like this: {% katex %}p_1 = \sum_{i=0}^{q-1}{[(p-1) \mod p}]{% endkatex %}, calculating {% katex %}q_1{% endkatex %} works analogous.

An example with smaller primes shows how we can approach the problem of finding p and q. Assuming we use {% katex %}p = 5, q = 7{% endkatex %}, if we write down the sum: {% katex display %}p_1 = 1 \mod 5 + 4 \mod 5 + 16 \mod 5 + 64 \mod 5 + ...{% endkatex %}
we can see that the sum actually is:
{% katex display %}p_1 = 1  + 4  + 1 + 4 + ...{% endkatex %}
Meaning that {% katex %}(p - 1)^{2i} \equiv 1 \mod p{% endkatex %} and {% katex %}(p - 1)^{2i+1} \equiv (p-1) \mod p{% endkatex %}. Since q is odd (its prime, duh...), the series ends with an even exponent. So by subtracting one we get a multiple of p: {% katex display %}p_1 - 1 = \frac{(q-1)}{2} \cdot p{% endkatex %}
The same of course also works for the other helper number: {% katex %}q_1 - 1 = \frac{(p-1)}{2} \cdot q{% endkatex %}. Given those two equations we can calculate the primes p and q.

The exploit uses sympy's equation solving abilities:

```python
import sympy
import binascii

x = sympy.Symbol("x", integer=True)

def xgcd(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1 
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

enc = 15507598298834817042463704681892573844935925207353671096676527782423920390858333417805014479686241766827314370902570869063203100704151010294869728739155779685640415815492312661653450808873691693721178331336833872996692091804443257630828512131569609704473214724551132715672202671586891813211353984388741035474991608860773895778988812691240069777435969326282770350038882767450912160134013566175657336041694882842590560100668789803775001750959648059363722039014522592751510672658328196379883088392541680852726136345115484827400366869810045573176782889745710174383221427352027041590910694360773085666697865554456816396551
p1 = 14606124773267989759790608461455191496412830491696356154942727371283685352374696106605522295947073718389291445222948819019827919548861779448943538887273671755720708995173224464135442610773913398114765000584117906488005860577777765761976598659759965848699728860137999472734199231263583504465555230926206555745572068651194660027408008664437845821585312159573051601404228506302601502000674242923654458940017954149007122396560597908895703129094329414813271877228441216708678152764783888299324278380566426363579192681667090193538271960774609959694372731502799584057204257039655016058403786035676376493785696595207371994520
q1 = 14606124773267989759790608461455191496412830491696356154942727371283685352374696106605522295947073718389291445222948819019827919548861779448943538887273671755720708995173224464135442610773913398114765000584117906488005860577777765761976598659759965848699728860137999472734199231263583504465555230926206555745568763680874120108583912617489933976894172558366109559645634758298286470207143481537561897150407972412540709976696855267154744423609260252738825337344339874487812781362826063927023814123654794249583090654283919689841700775405866650720124813397785666726161029434903581762204459888078943696756054152989895680616

p1_l = p1 - 1
q1_l = q1 - 1

# we only care about the positive root
p = int(sympy.solve((x * ((2*p1_l)/(x-1) - 1)) - 2*q1_l)[1])
q = int(sympy.solve((x * ((2*q1_l)/(x-1) - 1)) - 2*p1_l)[1])

N = p * q
phi = (p-1)*(q-1)
e = (1<<16)+1

_, x, _ = xgcd(e, phi)
d = (x + phi) % phi # in case x is negative

print("Found primes and inverse:")
print("p: ", hex(p))
print("q: ", hex(q))
print("d: ", hex(d))

m = pow(enc, d, N)

print(binascii.unhexlify(hex(m)[2:]))
```

Giving us the flag: `HarekazeCTF{d1d_y0u_7ry_b1n4ry_se4rch?}`

## Fight
This challenge came with the Python script:

```python
import random
import base64
import key

def xor(msg, key):
    return bytes([ch1^ch2 for ch1, ch2 in zip(msg, key)])

def gcd(x, y):
  while y != 0:
    r = x % y
    x = y
    y = r
  return x

def gen_seed(n):
  seed = 0
  for k in range(1,n):
    if gcd(k,n)==1:
      seed += 1
  return seed

s = 1
for p in b"Enjoy_HarekazeCTF!!":
  s *= p
seed = gen_seed(s)
random.seed(str(seed).rstrip("0"))

flag = key.FLAG
key = bytes([random.randint(0,255) for _ in flag])

enc = xor(flag, key)
#7XDZk9F4ZI5WpcFOfej3Dbau3yc1kxUgqmRCPMkzgyYFGjsRJF9aMaLHyDU=
print(base64.b64encode(enc).decode('utf-8')) 
```

Since we are given the encryped flag in form of a comment and the script uses a stream cipher, we just need to run the script again with the base64 decoded version of the encrypted flag. The only problem is the calculation in the `gen_seed` function which would take waaay to long. 

The code:

```python
seed = 0
  for k in range(1,n):
    if gcd(k,n)==1:
      seed += 1
  return seed
```

calculates the seed by counting the numbers coprime to n. Since n is given in the form of:

```python
for p in b"Enjoy_HarekazeCTF!!":
  s *= p
```

which turns out to be 4529255040439033800342855653030016000. We can calculate the numbers coprime
to this number by using [eulers phi function](https://en.wikipedia.org/wiki/Euler%27s_totient_function)
which is fast for such a small number. The script:

```python
import sympy.ntheory
sympy.ntheory.totient(4529255040439033800342855653030016000)
```

gives us the seed 765753154007029226621575888896000000 in no time.

Embedded in the original script:

```python
import random
import base64

def xor(msg, key):
    return bytes([ch1^ch2 for ch1, ch2 in zip(msg, key)])

seed = 765753154007029226621575888896000000
random.seed(str(seed).rstrip("0"))


key = bytes([random.randint(0,255) for _ in range(50)])
flag = base64.b64decode("7XDZk9F4ZI5WpcFOfej3Dbau3yc1kxUgqmRCPMkzgyYFGjsRJF9aMaLHyDU=")
print(xor(flag, key))
```

gives us the flag `HarekazeCTF{3ul3rrrrrrrrr_t0000000t1nt!!!!!}`.

\o/