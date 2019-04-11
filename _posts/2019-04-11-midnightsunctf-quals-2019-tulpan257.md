---
layout: post
category: Crypto
title: MidnightsunCTF Quals 2019 - tulpan257
tags: 
    - Manf
---


Tulpan257
=========
{% katexmm %}
We were given the following sage script:
```
flag = "XXXXXXXXXXXXXXXXXXXXXXXXX"
p = 257
k = len(flag) + 1

def prover(secret, beta=107, alpha=42):
    F = GF(p)
    FF.<x> = GF(p)[]
    r = FF.random_element(k - 1)
    masked = (r * secret).mod(x^k + 1)
    y = [
        masked(i) if randint(0, beta) >= alpha else
        masked(i) + F.random_element()
        for i in range(0, beta)
    ]
    return r.coeffs(), y

sage: prover(flag)
[141, 56, 14, 221, 102, 34, 216, 33, 204, 223, 194, 174, 179, 67, 226, 101, 79, 236, 214, 198, 129, 11, 52, 148, 180, 49]
[138, 229, 245, 162, 184, 116, 195, 143, 68, 1, 94, 35, 73, 202, 113, 235, 46, 97, 100, 148, 191, 102, 60, 118, 230, 256, 9, 175, 203, 136, 232, 82, 242, 236, 37, 201, 37, 116, 149, 90, 240, 200, 100, 179, 154, 69, 243, 43, 186, 167, 94, 99, 158, 149, 218, 137, 87, 178, 187, 195, 59, 191, 194, 198, 247, 230, 110, 222, 117, 164, 218, 228, 242, 182, 165, 174, 149, 150, 120, 202, 94, 148, 206, 69, 12, 178, 239, 160, 7, 235, 153, 187, 251, 83, 213, 179, 242, 215, 83, 88, 1, 108, 32, 138, 180, 102, 34]
```

It doesn't work quite as given - `prover()` must be given a polynomial, not a string. I figured that this polynomial was probably just using the flag string as coefficients, and just tried to recover that secret polynomial first (under the assumption that it was of degree $k$).
The `r.coeffs()` output has length $26$, so this means that $k=26$.

Now the hard part was recovering the polynomial `masked` - if I knew that, I could just multiply by the multiplicative inverse of $r$ in the ring $GF(p)[x]/(x^k+1)$ (which fortunately exists). The known output `y` is obtained by evaluating `masked` at the positions $0,1,\ldots,106$ - however, with random chance of $\frac{42}{107}$, a random output modulo $p$ is chosen instead. I also know that `masked` is a polynomial of degree $k-1$ - so if I just knew $k$ correct points, I could simply construct the Lagrange Polynomial through these points.

With the output containing errors I had two choices:

- Guessing: If I just guess 26 points that had the correct output, I could recover the original polynomial. A quick calculation shows that this has about chance $2\cdot 10^{-6}$ of happening - and it is easy to detect, as some random polynomial through 26 of the points will match `y` in far less places than the correct one. Having now tried it after the CTF, it works very well.
- Using someone elses work: My first instinct however was to search for a more elegant algorithm for the problem. In retrospect, just using brute force would probably have saved me some time - but this variant was at least quite educational.
 
I knew that problems of the type "given a set of discrete equations, find a solution that satisfies a high number of them" were quite typical for *Coding theory*, so I started looking at well-known error-correcting codes. After a little reading, the *Reed-Solomon Code* jumped out to me - Wikipedia gives the codewords of a Reed-Solomon Code as $\{(p(a_1), p(a_2), \ldots, p(a_n))\mid p \text{ is a polynomial over } F \text{ of degree } k\}$. Setting $n=107, a_i=i-1, k=26, F=GF(p)$, this is exactly the kind of output we are dealing with. So now I just needed to *decode* the codeword given to me in `y` to one that lies in that Reed-Solomon Code. Fortunately, sage has [builtin functions](http://doc.sagemath.org/html/en/reference/coding/sage/coding/grs.html) for everything:

```
sage: p, k = 257, 26
sage: F = GF(p)
sage: FF.<x> = F[]
sage: from sage.coding.grs import *
sage: C=GeneralizedReedSolomonCode([F(i) for i in range(107)],26)
sage: D=GRSBerlekampWelchDecoder(C)
sage: D.decode_to_message(vector(y,F))
DecodingError: Decoding failed because the number of errors exceeded the decoding radius
sage: D.decoding_radius()
40
```
Whoops - it seems there are just a few errors too many in the output for the `BerlekampWelchDecoder` to handle. All the other decoders seemed to have the same problem... until I somehow managed to find the [Guruswami-Sudan decoder](http://doc.sagemath.org/html/en/reference/coding/sage/coding/guruswami_sudan/gs_decoder.html). It conveniently takes a parameter `tau` that specifies (within limits) the number of errors it will be able correct:

```
sage: from sage.coding.guruswami_sudan.gs_decoder import *
sage: D=GRSGuruswamiSudanDecoder(C,45)
sage: masked=D.decode_to_message(vector(y,F))[0]
sage: masked
136*x^25 + 181*x^24 + 158*x^23 + 233*x^22 + 215*x^21 + 95*x^20 + 235*x^19 + 76*x^18 + 133*x^17 + 199*x^16 + 105*x^15 + 46*x^14 + 53*x^13 + 123*x^12 + 150*x^11 + 28*x^10 + 87*x^9 + 122*x^8 + 59*x^7 + 177*x^6 + 174*x^5 + 200*x^4 + 143*x^3 + 77*x^2 + 65*x + 138
```

Finally it's just a matter of multiplying by $r^{-1}$:
```
sage: R = FF.quo(x^k+1)
sage: flag = R(masked)*R(r)^(-1)
sage: "".join([chr(i) for i in flag]) # iterates over coefficients
'N0p3_th1s_15_n0T_R1ng_LpN\x00'
```


Lessons learned
------
- Coding theory has all kinds of useful stuff for "out of n relations, only k hold, but we don't know which"-type situations
- If a builtin function of sage isn't quite good or general enough, there is probably a better one somewhere
- Don't waste time on elegant solutions if you can just guess
{% endkatexmm %}
