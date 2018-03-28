---
layout: post
category: Crypto
title: VolgaCTF Quals 2018 - Nonsense
tags: 
    - rg
---

The Task came with the description:

```
We've intercepted several consecutive signatures. 
Take everything you need and find the secret key. Send it to us in hex.
```

As well as a Python script:

```python
import hashlib
import gmpy2
import os
from secret import x, seed


class DSA():
    def __init__(self):
        self.g = 88125476599184486094790650278890368754888757655708027167453919435240304366395317529470831972495061725782138055221217302201589783769854366885231779596493602609634987052252863192229681106120745605931395095346012008056087730365567429009621913663891364224332141824100071928803984724198563312854816667719924760795
        self.y = 18433140630820275907539488836516835408779542939919052226997023049612786224410259583219376467254099629677919271852380455772458762645735404211432242965871926570632297310903219184400775850110990886397212284518923292433738871549404880989194321082225561448101852260505727288411231941413212099434438610673556403084
        self.p = 89884656743115795425395461605176038709311877189759878663122975144592708970495081723016152663257074178905267744494172937616748015651504839967430700901664125135185879852143653824715409554960402343311756382635207838848036159350785779959423221882215217326708017212309285537596191495074550701770862125817284985959
        self.q = 1118817215266473099401489299835945027713635248219
        self.x = x

    def sign(self, m, k):
        h = int(hashlib.md5(m).hexdigest(), 16)
        r = pow(self.g, k, self.p) % self.q
        s = int(((self.x * r + h) * gmpy2.invert(k, self.q)) % self.q)
        return (r, s)

    def verify(self, m, r, s):
        if 0 < r and r < self.q and 0 < s and s < self.q:
            h = int(hashlib.md5(m).hexdigest(), 16)
            w = gmpy2.invert(s, self.q)
            u1 = (h * w) % self.q
            u2 = (r * w) % self.q
            v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
            return v == r
        return None


class LCG():
    def __init__(self):
        self.a = 3437776292996777467976657547577967657547
        self.b = 828669865469592426262363475477574643634
        self.m = 1118817215266473099401489299835945027713635248219
        self.seed = seed
        self.state = (self.a * self.seed + self.b) % self.m

    def next_number(self):
        self.state = (self.a * self.state + self.b) % self.m
        return self.state


generator = LCG()
signature = DSA()

for _ in range(2):
    message = "VolgaCTF{" + os.urandom(16).encode('hex') + "}"
    k = generator.next_number()
    (r, s) = signature.sign(message, k)
    print (message, r, s)
    print signature.verify(message, r, s)
```

And a file with signatures:

```
('VolgaCTF{nKpV/dmkBeQ0n9Mz0g9eGQ==}', 1030409245884476193717141088285092765299686864672, 830067187231135666416948244755306407163838542785)
('VolgaCTF{KtetaQ4YT8PhTL3O4vsfDg==}', 403903893160663712713225718481237860747338118174, 803753330562964683180744246754284061126230157465)
[...]
```

So the goal here is to recover the private key given signature pairs.
The Python script creates a [DSA](https://de.wikipedia.org/wiki/Digital_Signature_Algorithm) signature of the given message using a secret private key *x* and a pseudo random exponent *k* that is created using a [LCG](https://en.wikipedia.org/wiki/Linear_congruential_generator).

Using LCGs in the sphere of IT security is almost always a very bad idea. Here it is as well.

The DSA signing step works as follows:

* Choose Random *k*
* Calculate  {% katex %} r = (g^k \mod p) \mod q {% endkatex %}
* Calculate  {% katex %} s = k^{-1}(Hash(m) + rx) \mod q {% endkatex %}
* The signature is (r, s)

For details of the parameters see the linked Wikipedia article.

So the signing step in DSA needs a random exponent *k*, if *k* can be guessed or calculated, you can recover the private key and break the crypto system.

Since an LCG is used to determine *k*, all *k*s in the signatures are related.
In this case, if we have two signatures we can recover k by solving this system of equations ([source](https://link.springer.com/content/pdf/10.1007%2FBFb0052242.pdf)):


{% katex display %}
s_1 k_1 - r_1 x \equiv m_1 \mod q
{% endkatex %}

{% katex display %}
s_2 k_2 - r_2 x \equiv m_2 \mod q
{% endkatex %}

{% katex display %}
k_2 \equiv a k_1 +b \mod M
{% endkatex %}

The first two equation are given by the DSA algorithm. The third one shows the relation between two successive outputs of a LCG.
In this task (that actually took me a while to see...) *q* and *M* are identical. 
Making this a an equation system with three equations and three unknowns.

We can calculate the secret by calculating:

{% katex display %}
x \equiv r_1^{-1} (s_1 k_1 -m_1) \mod q
{% endkatex %}

and the "random" k with:

{% katex display %}
k_1 \equiv (r_1^{-1} m_1 - r_2^{-2}(m_2 - s_2 b)) \cdot (s_1 r_1^{-1} - a s_2 r_2^{-1})^{-1} \mod q
{% endkatex %}

This Python script does the calculations for us:

```python
from hashlib import md5
from sympy import invert as inv

q = 1118817215266473099401489299835945027713635248219
a = 3437776292996777467976657547577967657547
b = 828669865469592426262363475477574643634

r1 = 1030409245884476193717141088285092765299686864672
r2 = 403903893160663712713225718481237860747338118174

s1 = 830067187231135666416948244755306407163838542785
s2 = 803753330562964683180744246754284061126230157465

m1 = int.from_bytes(md5(b"VolgaCTF{nKpV/dmkBeQ0n9Mz0g9eGQ==}").digest(), "big")
m2 = int.from_bytes(md5(b"VolgaCTF{KtetaQ4YT8PhTL3O4vsfDg==}").digest(), "big")

term1 = (inv(r1, q) * m1 - inv(r2, q) * (m2 - s2*b))
term2 = inv((s1 * inv(r1, q) - a * s2 * inv(r2, q)), q)

k1 = (term1 * term2) % q
x = (inv(r1, q) * (s1*k1 - m1)) %  q
print("VolgaCTF{" + hex(x)[2:].upper() + "}")
```

Giving us the flag `VolgaCTF{9D529E2DA84117FE72A1770A79CEC6ECE4065212}`
\o/