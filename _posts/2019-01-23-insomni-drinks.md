---
layout: post
category: Crypto
title: InsomnihackCTF 2019 - drinks
tags: 
    - rg
---

In this task we're given an IP, a port and the source code of the service.

The service offers a JSON based API:
```python
from flask import Flask,request,abort
import gnupg
import time
app = Flask(__name__)
gpg = gnupg.GPG(gnupghome="/tmp/gpg")

couponCodes = {
    "water": "WATER_2019",
    "beer" : "" # REDACTED
}

@app.route("/generateEncryptedVoucher", methods=['POST'])
def generateEncryptedVoucher():

    content = request.json
    (recipientName,drink) = (content['recipientName'],content['drink'])

    encryptedVoucher = str(gpg.encrypt(
        "%s||%s" % (recipientName,couponCodes[drink]),
        recipients  = None,
        symmetric   = True,
        passphrase  = couponCodes[drink]
    )).replace("PGP MESSAGE","DRINK VOUCHER")
    return encryptedVoucher

@app.route("/redeemEncryptedVoucher", methods=['POST'])
def redeemEncryptedVoucher():

    content = request.json
    (encryptedVoucher,passphrase) = (content['encryptedVoucher'],content['passphrase'])

    # Reluctantly go to the fridge...
    time.sleep(15)

    decryptedVoucher = str(gpg.decrypt(
        encryptedVoucher.replace("DRINK VOUCHER","PGP MESSAGE"),
        passphrase = passphrase
    ))
    (recipientName,couponCode) = decryptedVoucher.split("||")

    if couponCode == couponCodes["water"]:
        return "Here is some fresh water for %s\n" % recipientName
    elif couponCode == couponCodes["beer"]:
        return "Congrats %s! The flag is INS{ %s}\n" % (recipientName, couponCode)
    else:
        abort(500)

if __name__ == "__main__":
    app.run(host='0.0.0.0')
```

This service encrypts a user generated string concatinated with `||` and the encryption key.

The goal here was to find the de-/encryption key of the beer voucher. 

The code is using a wrapper for the GnuPGP library.
The corresponding RFC says, PGP is using a block cipher in [CFB mode](https://de.wikipedia.org/wiki/Cipher_Feedback_Mode). Since we didn't see how we could directly attack this service, we were buffeled for a bit.

We decided to find out the length of the encryption key, since it might be to short. To do so, we send the service `receipientName`s with an increasing amount of `A`s. To our surprise, the ciphertext size didn't increase per character. 

This means, OpenPGP uses compression before encrypting the data!
This opens the door for a compression side channel!

Since we control what comes before the encryption key, we can try out different characters. Everytime we get a shorter ciphertext, we know another character of the key, since our `receipientName` got compressed together with the key. Because the compression starts at a size of three bytes, we can start our search with `||A`. This would result in the text `||A||$SECRET_KEY`, which should be compressed (and therefore shorter) if the `$SECRET_KEY` starts with an A.

The exploit script (see below) first determines a maximum ciphertext length by sending a non-compressible 40 byte string to the service. Then it tries out new characters by appending them to the known key string (in the beginning `||`) and filling the remaining 40 bytes with non compressible data. 
Everytime a ciphertext shorter than the previous one is received, we know another byte of the key!

The exploit script is not optimal (CTF code quality...), since it doesn't necessarily find the patterns in correct order.

Running it the first time gave us the key `G1M_V3RY_TH1RSTY`, which seems wierd and also didn't work for decryption. Forbidding the first underline, it would give us the key `G1MME_B33RY_TH1RSTY`, which also doesn't make sense. This is because the key contains repeating patterns (e.g. `B33RY` compresses, just as `B33R_` because of the word `V3RY`). 

To fix this we'd need a more sophisticated approach, storing all candidate characters... But it was 3 a.m. and we were tired. So we just fixed the prefix to `||G1MME_B33R_` which seemed reasonable. 

This worked and gave us: 

```
p3 explcry.py
[...]
||G1MME_B33R_PLZ_1M_S0_V3RY_TH1RSTY
```

Which is the flag.

Full Exploit Script:

```python
import os

import random
import base64
import requests
import string

SEARCHSP = list("_" + string.printable[:-6])

PAD = string.ascii_lowercase + "!§$%&()=?-:;#'+*<>|"

MAX_LEN = 40

for c in PAD:
    if c in SEARCHSP:
        SEARCHSP.remove(c)

def gen_pad(l):
    a = random.randint(0, len(PAD)-l)
    return PAD[a:a+l]

def convert_to_hex(p):
    return base64.b64decode("".join(p.split("\n")[2:-3])).hex()

def get_enc(recipient, drink):
    r=requests.post('http://localhost:5000/generateEncryptedVoucher',json={'recipientName': recipient, 'drink': drink}) 
    return r.text


def get_uncompressed_len(PREFIX):
    while True:
        l_high_ent = []
        for i in range(20):
            l_high_ent.append(convert_to_hex(get_enc(PREFIX + gen_pad(MAX_LEN - len(PREFIX)), "beer")))

        len_ct = len(l_high_ent[0])
        for p in l_high_ent:
            if len(p) != len_ct:
                break
        else:
            break
    return len_ct

KNOWN = "||G1MME_B33R_"
len_ct = get_uncompressed_len(KNOWN)
print("Ciphertext len without compression: ", len_ct)


num = 0
for _ in range(26):
    for c in string.ascii_uppercase + "_0123456789":
        pw = KNOWN + c + PAD[:MAX_LEN - len(KNOWN) - 1]
        test = convert_to_hex(get_enc(pw, "beer"))
        num += 1
        if len(test) < len_ct:
            len_ct = len(test)
            print(len(test))
            KNOWN += c
            print(KNOWN)
            break 
print(KNOWN)
```

