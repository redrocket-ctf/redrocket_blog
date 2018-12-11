---
layout: post
category: Crypto
title: hxpCTF 2018 - uff
tags: 
    - rg
---

This challenge came with [c code](https://gist.github.com/rugo/534f5e2325813fcebaa2a2788b50471d) and this description:

```
The crypto_sign function is designed to meet the standard notion of unforgeability for a public-key signature scheme under chosen-message attacks.
```

The code implements a service that creates 8 random key pairs for [ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519), it then lets you sign up to 1000 arbitrary messages. The keys used for signing can be chosen by us, by supplying the respective public key. The output looked like this:

```
 ./hxpcry                     [0]
Welcome to the Ed25519 existential forgery game!  Enjoy and good luck.
public key: 0609355a5505f116b6232dfc4aaedf99fef2c03376dc05f782e2b5f26454b353
public key: d24d6a7e6da062de8b0bf8b9f0efcb7617c6d6c44027af1d1e052359a80bf36d
public key: 7cf253c5667ea674ec4675a49731b3c58ee72e633212d8df05a44f9f2160bf63
public key: 3afe84a3480cae670d27363966929dd6d879981116b20600c50494378d84acb6
public key: 9c806c7bd9a890c43b2b89dc9ebe091888345ed958ef5f2fa60b42e8feb9fa98
public key: 909ec9496a787af72e444d314eb1c4910950ca7b757240a017149d7872bd6d55
public key: 816f1e428660418f942fec895e6fb75fc3db41c650578e636593e0c800064c6d
public key: d5db5e4ca30154a7266e75d6da77071e72c363fe6f0b2305810432b5ee0fd592

public key> d5db5e4ca30154a7266e75d6da77071e72c363fe6f0b2305810432b5ee0fd592
length>     1
message>    aa
signed:     d06d3f94beea2e8e71fbeb74f0558c92bea4121e666f35585544829b57b274d97c39da375c3b2333103f39bff3a5d1f2b48990d33473c4cac3ad8b78bc145409aa
public key>
[...]
forgery>    FORGED_SIGNATURE
```

If we manage to supply a valid signature for any of the given public keys and an arbitrary message (that we haven't submitted to the service) the flag will be printed.

## C and strings

As it can be seen by the includes, the library uses djb's [tweetnacl](https://tweetnacl.cr.yp.to/) library.
Knowing that this library probably has no direct vulnerability, we looked at the provided C file.
In C it is extermely easy to screw up string handling or buffer sizes.
Since the authors layed some false trails, it took us a bit to find the actually pretty obvious bug.

The code reads in the provided public key: 

```c
printf("public key> "); fflush(stdout);
if (sizeof(pk) != read_hex(pk, sizeof(pk)) || K == (idx = find(pk)))
    break;
```

and checks if the given public key is in the list of public keys via the `find` function.
If the public key is in the list, it then uses the **user supplied** public key within the signing function (along with its private key).

```c
printf("signed:     ");
print_hex(m, sign(m, n, keys[idx].sk, pk));
printf("\n");
```

The `find` function looks like this:


```c
unsigned find(unsigned char const *pk)
{
    unsigned idx;
    for (idx = 0; idx < K; ++idx)
        if (!strncmp(pk, keys[idx].pk, 32))
            break;
    return idx;
}
```

It uses `strncmp` to compare the user supplied public key to the one stored in its internal list.

Since strncmp only compares until the first null byte (the string terminator in C),
we could wait until the service gives us a public key that contains a null byte.

From that null byte on, we could submit different bytes for the public key and it would still be used
during signing.

So if we get an output like this:

```
Welcome to the Ed25519 existential forgery game!  Enjoy and good luck.
[...]
22bfe776234f54e70fead863c49b13ece4ed218e00e201426618e1af551216c6
[...]
public key>
```

We could submit the correct public key `22bfe776234f54e70fead863c49b13ece4ed218e00e201426618e1af551216c6`, but we could also submit `22bfe776234f54e70fead863c49b13ece4ed218e00aaaaaaaaaaaaaaaaaaaaaa`. The service would use both public keys with the same private key to sign our messages.

But why does this matter?

## ed25519
The services signs our messages using the libraries ed25519 implementation. Ed25519 is a edDSA scheme, so basically a Schnorr signature on a twisted elliptic edwards curve. 

An edDSA signature consists of two parts {% katex %} (R, S) {% endkatex %}, where R is a curve point and S a scalar. R is calculated as {% katex %} R = rB {% endkatex %}, with r beeing essentially a random value (it's not actually random, it's deterministic, but it serves as a random value) {% katex %} r = H(H_{b,\dots,2b - 1}(k), M) {% endkatex %}. B is the defined base point, H a one way hash function and k is the private key. 
Check out the linked Wikipedia article for the exact parameters of ed25519. 

The S of the signature is calculated as follows:

{% katex display %}
S \equiv r + H(R, A, M) s \pmod \ell.
{% endkatex %}

The secret r is added to the hash of R, the public key A, and the message multiplied by the secret s (derived from the private key).

So if we manage to sign the same message two times, using the same private key, but two different public keys we would get the following equations:

{% katex display %}
S_1 \equiv r_1 + H(R_1, A_1, M) s \pmod \ell.
{% endkatex %}

and 

{% katex display %}
S_2 \equiv r_2 + H(R_2, A_2, M) s \pmod \ell.
{% endkatex %}

For these two equations, we have all the variables, except for the secret key s. Given this secret key s, we could just sign messages our selves.

The secret s can easily be calculated:

{% katex display %}
s =  \frac{S_1 - S_2}{H(R_1, A_1, M) - H(R_2, A_2, M)}
{% endkatex %}

Note that this calculation is done modulo, so it actually reads like this:

{% katex display %}
s \equiv  (S_1 - S_2) \cdot (H(R_1, A, M) - H(R_2, A, M))^{-1} \mod \ell.
{% endkatex %}

## Putting it together

So the exploit works as follows:

1. Connect to the service until it gives us a public key containing a null byte
2. Use this public key to create a wrong public key (differs after the null byte)
3. Request two signatures for the same message using the differnt public keys
4. Calculate the secret s
5. Sign a message of our choice and submit it
6. Enjoy the flag

The final exploit can be found [here](https://gist.github.com/rugo/217526abe17f0dcb425459003598bbc9). It uses the [pure25519 python lib](https://github.com/warner/python-pure25519) by Brian Warner.

Running the exploit gives us:
```
[+] Opening connection to 159.69.218.92 on port 25519: Done
('Found weak key', '\x14\xec5\xb3\x04]\x05\x12Ss\xaf\xdb\xbaj\xf6\x00\xf2\xa5QV\xd4~\x9a\xe9\x1f\x0b\x90\x88\xd2\xd7*+')
('Signature: ', 'cfa1a0255fb0cdab6c8183a68674e7755f2d04f0990fc67e5cbd4bea9e6661df81da90f1ef2ee990f8c6ff4f970d7955b595691a0e6d135a4a1ab7c964f63c03')

hxp{Th3_m0sT_f00lpr00f_sYsT3m_br34kz_1f_y0u_4bU5e_1t_h4rD_eN0u9h}
[*] Closed connection to 159.69.218.92 port 25519
```

\o/
