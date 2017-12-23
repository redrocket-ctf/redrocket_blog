---
layout: post
category: Crypto
title: TUCTF Crypto Clock
tags: 
    - rg
---

The challenge came with the description:

```
These damn hackers have hit our NTP server with something called crypto clock... 
Our sysadmin found these suspicious packets just before our systems went down. 
Can you get back in??? nc cryptoclock.tuctf.com 1230
```

and a downloadable pcap. The network traffic in the pcap contained a base64 string that contained the following Python program:

```python
#!/usr/bin/env python
import sys
import random
import arrow

big_1=44125640252420890531874960299151489144331823129767199713521591380666658119888039423611193245874268914543544757701212460841500066756559202618153643704131510144412854121922874915334989288095965983299150884589072558175944926880089918837606946144787884895502736057098445881755704071137014578861355153558L
big_2=66696868460135246134548422790675846019514082280010222055190431834695902320690870624800896599876321653748703472303898494328735060007496463688173184134683195070014971393479052888965363156438222430598115999221042866547813179681064777805881205219874282594291769479529691352248899548787766385840180279125343043041L


flag = "THEFLAG"
keys = {
    "n":142592923782837889588057810280074407737423643916040668869726059762141765501708356840348112967723017380491537652089235085114921790608646587431612689308433796755742900776477504777927984318043841155548537514797656674327871309567995961808817111092091178333559727506289043092271411929507972666960139142195351097141,
    "e": 3
}

#now to get some randomness in here!
with open('/dev/urandom', 'rb') as f:
    rand = f.read(8)

rand_int = int(rand.encode('hex'),16)

#now lets use something easier.
random.seed(rand_int)

offset = random.randint(big_1,big_2)

while True:
    sys.stdout.write( '''Welcome to the ntp server
What would you like to do?
    1) get current time
    2) enter admin area
    3) exit
:''')
    sys.stdout.flush()
    response = raw_input('')
    if response == '1':
        time = arrow.utcnow().timestamp + offset
        enc_time = pow(time,keys['e'],keys['n'])
        sys.stdout.write('HAHAHAHAHAHA, this NTP server has been taken over by hackers!!!\n')
        sys.stdout.write('here is the time encrypted with sweet RSA!\n')
        sys.stdout.write(str(enc_time))
        sys.stdout.write('\n')
        sys.stdout.flush()
    elif response == '2':
        # lets get even more random!
        time = arrow.utcnow().timestamp + offset
        random.seed(time)
        guessing_int = random.randint(0,999999999999)
        sys.stdout.write('''ACCESS IS ONLY FOR TRUE HACKERS!
to prove you are a true hacker, predict the future:''')
        sys.stdout.flush()
        response = raw_input('')
        if response == str(guessing_int):
            sys.stdout.write('''Wow, guess you are a hacker.\n''')
            sys.stdout.write(flag)
            sys.stdout.write('\n')
            break
        else:
            sys.stdout.write('''I knew you weren't a hacker''')
            sys.stdout.write('\n')
            break
    else:
        print 'Good by.'
        break
```

This service gives us the flag once we input the next random number from `random.randint(0,999999999999)`. The PRNG is seeded with the UTC time and a fairly large offset 
```python
rand_int = int(rand.encode('hex'),16)

#now lets use something easier.
random.seed(rand_int)

offset = random.randint(big_1,big_2)
```

The service also offers us the RSA encrypted seed `enc_time = pow(time,keys['e'],keys['n'])`. Important here ist that we can request as many `enc_time`'s with the same secret offset as we want. Because of that we could probably request a couple of cipher texts and then calculate the seed. 

More interesting though: this is a pitch perfect example of a related cipher text vulnerablility. Since the point of CTFs is to learn, we decided to go into that direction.

A practical attack for this scenario is the [Franklin Reiter Related Message Attack](http://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf).

Franklin and Reiter stated that, given an RSA public key {% katex %} \langle N, e \rangle
{% endkatex %} with low exponent (such as 3 in this case) and two related plain texts
{% katex %}M_1 \neq M_2 \in Z_{N}^{\ast}{% endkatex %} that satisfy {% katex %}M_1 \equiv f(M_2) \pmod{N}{% endkatex %} with linear {% katex %}f = ax + b, b \neq 0{% endkatex %} we can recover the plaintext in {% katex %}log N{% endkatex %}. 

This is obviously given here, since we can wait one second between requesting the cipher texts, so in our case it is {% katex %}f = x + 1{% endkatex %}. 

Given all this we can create the two polynomials {% katex %}g_1(x) = f(x)^e - C_1 \in \mathbb{Z}_N{% endkatex %} and {% katex %}g_2(x) = x^e - C_2 \in \mathbb{Z}_N{% endkatex %}.
{% katex %} M_2 {% endkatex %} is a root of both polynomials, so {% katex %} x-M_2 {% endkatex %} divides them both.

This means, to find {% katex %} M_2 {% endkatex %} we have to compute the {% katex %}gcd(g_1, g_2){% endkatex %} giving us the common factor {% katex %} x-M_2 {% endkatex %}. To see why this always works for the exponent 3 (and mostly for other small exponents) see the mentioned paper.

Unfortunately I didn't find any Python code for calculating the GCD for a ring over a composite modulus. I was half way through writing the eea for polynomials over a ring myself when I stumpled upon the nifty ```Poly.set_modulus``` method in [sympy's polynomials implementation](http://docs.sympy.org/latest/modules/polys/reference.html) that does exactly what is needed here.

Using that, the exploit is rather short. We can use sympys `gcd` function:

```python
f1 = poly(x**e - c1).set_modulus(n)
f2 = poly((x + 1)**e - c2).set_modulus(n)

-gcd(f1, f2).coeffs()[-1]  # sympy is awesome!
```

We take the negated last coefficient of the resulting term ({% katex %} x-M_2 {% endkatex %}), which is our plain text string {% katex %} M_2 {% endkatex %}.

After receiving the plain text, which is used as seed, we can compute the next random number.

After way too much time of running the exploit locally and failing remotely, I realized that the server side is using Python 2. The PRNG implementations between Python 2 (LCG) and Python 3 (Mersenne-Twister) do not have much in common.

The final exploit looks like this:

```python
import pexpect
import subprocess
import re
from sympy import poly, symbols, gcd
from time import sleep


n = 142592923782837889588057810280074407737423643916040668869726059762141765501708356840348112967723017380491537652089235085114921790608646587431612689308433796755742900776477504777927984318043841155548537514797656674327871309567995961808817111092091178333559727506289043092271411929507972666960139142195351097141
e = 3


x = symbols('x')
num_re = re.compile("RSA!\r\n([0-9]+)\r\nWelcome")


def get_plain(c1, c2, offset):
    f1 = poly(x**e - c1).set_modulus(n)
    f2 = poly((x + 1)**e - c2).set_modulus(n)

    return -gcd(f1, f2).coeffs()[-1]  # sympy is awesome!

def next_rand(offset):
    out = subprocess.check_output(["python2", "-c",  'import random; random.seed({}); print(random.randint(0,999999999999))'.format(offset)], stderr=subprocess.STDOUT)
    return int(out.decode().strip()) 


def extract_num(s):
    return int(num_re.findall(s)[0])


while True:
    cmd = pexpect.spawn("nc cryptoclock.tuctf.com 1230")
    cmd.expect(":")
    
    cmd.sendline("1")
    cmd.expect(":")
    c1 = extract_num(cmd.before.decode())

    sleep(0.5)

    cmd.sendline("1")
    cmd.expect(":")

    c2 = extract_num(cmd.before.decode())

    if c1 == c2:
        continue  # Didnt get different seconds, skipping.
    
    plain_text = get_plain(c1, c2, 1)
    
    cmd.sendline("2")
    cmd.expect("future:")

    n_rand = next_rand(plain_text + 1)
    
    print("Next random number: {}".format(n_rand))
    
    cmd.sendline(str(n_rand))

    cmd.expect("}")
    print(cmd.before.decode() + "}")
    break
```

Running it gives us:

```
Next random number: 70906011219
70906011219
Wow, guess you are a hacker.
TUCTF{g00d_th1ng_th3_futur3_i5_r3lated!}
```

\o/
