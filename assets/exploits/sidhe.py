#!/usr/bin/python3
# exploit by manf for sidhe (plaidctf 2020)
import sys
# sys.stdout.buffer = os.fdopen(1, 'wb')
from pwn import *
from sage.all import *
import hashlib
from Crypto.Cipher import AES
import itertools

def getPOW(s):
    print(s)
    b=s.encode()
    for x in itertools.product(b"abcdefghijklmnopqrstuvwxyz",repeat=8):
        d = hashlib.sha256(b+bytes(x)).digest()
        if d[-1]==0xff and d[-2]==0xff and d[-3]==0xff and d[-4]&0xf==0xf:
            return s+bytes(x).decode()

local = False
if local:
    t = process(["sage","server.sage"])
else:
    t = tcp("149.28.9.162",31337)

if not local:
    s = t.readline().decode().split(" with ")[1].split(" of ")[0]
    assert len(s)==10
    p =getPOW(s)
    print(p)
    t.sendline(p)

ii = var("ii")
x = var("x")
e2 = 0xD8
e3 = 0x89
p = (2**e2)*(3**e3)-1
BR = GF(p)
ii = BR[x](x)
K = GF(p**2, name="ii",modulus=ii**2+1)
ii = K(ii)
E = EllipticCurve(K, [0,6,0,1,0])
xP20 = 0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48
xP21 = 0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50
yP20 = 0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0
yP21 = 0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F
xQ20 = 0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C
xQ21 = 0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5
yQ20 = 0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5
yQ21 = 0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6
xP30 = 0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9
xP31 = 0x00000000
yP30 = 0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B
yP31 = 0x00000000
xQ30 = 0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846
xQ31 = 0x00000000
yQ30 = 0x00000000
yQ31 = 0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2
P2 = E(xP20+ii*xP21, yP20+ii*yP21)
Q2 = E(xQ20+ii*xQ21, yQ20+ii*yQ21)
P3 = E(xP30+ii*xP31, yP30+ii*yP31)
Q3 = E(xQ30+ii*xQ31, yQ30+ii*yQ31)

def elem_to_coefficients(x):
    l = x.polynomial().list()
    l += [0]*(2-len(l))
    return l

def readElem(s):
    l=safeeval.expr(s.strip())
    return K(l)
    
def sendElem(x):
    t.sendline(str(x.polynomial()[0]))
    t.sendline(str(x.polynomial()[1]))
    
def elem_to_bytes(x):
    n = ceil(log(p,2)/8)
    x0,x1 = elem_to_coefficients(x) # x == x0 + ii*x1
    x0 = ZZ(x0).digits(256, padto=n)
    x1 = ZZ(x1).digits(256, padto=n)
    return bytes(x0+x1)

def isogen2(sk2):
    Ei = E
    P = P3
    Q = Q3
    S = P2+sk2*Q2
    for i in range(e2):
        phi = Ei.isogeny((2**(e2-i-1))*S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei,P,Q)
    
def isogen3(sk3):
    Ei = E
    P = P2
    Q = Q2
    S = P3+sk3*Q3
    for i in range(e3):
        phi = Ei.isogeny((3**(e3-i-1))*S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei,P,Q)

    
def isoex2_c(sk2, pk3):
    Ei, P, Q = pk3
    S = P+sk2*Q
    for i in range(e2):
        R = (2**(e2-i-1))*S
        phi = Ei.isogeny(R)
        Ei = phi.codomain()
        S = phi(S)
    return Ei

print(t.recvuntil("public key:\n").decode())
t.recvuntil("a1: ")
a1 =readElem(t.recvline().decode())
t.recvuntil("a2: ")
a2 =readElem(t.recvline().decode())
t.recvuntil("a3: ")
a3 =readElem(t.recvline().decode())
t.recvuntil("a4: ")
a4 =readElem(t.recvline().decode())
t.recvuntil("a6: ")
a6 =readElem(t.recvline().decode())
t.recvuntil("Px: ")
Px =readElem(t.recvline().decode())
t.recvuntil("Py: ")
Py =readElem(t.recvline().decode())
t.recvuntil("Qx: ")
Qx =readElem(t.recvline().decode())
t.recvuntil("Qy: ")
Qy =readElem(t.recvline().decode())

EA = EllipticCurve(K, [a1, a2, a3, a4, a6])
PA = EA(Px, Py)
QA = EA(Qx, Qy)
pk3=(EA,PA,QA)

def oracle(E,R,S,Ep):
    sendElem(E.a1())
    sendElem(E.a2())
    sendElem(E.a3())
    sendElem(E.a4())
    sendElem(E.a6())
    sendElem(R[0])
    sendElem(R[1])
    sendElem(S[0])
    sendElem(S[1])
    j = Ep.j_invariant()
    K = hashlib.sha256(elem_to_bytes(j)).digest()
    C = AES.new(K, AES.MODE_ECB).encrypt(b"Hello world.\x00\x00\x00\x00").hex()
    t.recvuntil("ciphertext")
    t.sendline(C)
    r = t.recvuntil("ciphertext")
    return b"Good" in r

skt = 5
Et,Pt,Qt = isogen2(5)
EAB = isoex2_c(skt,(EA,PA,QA))

def submitFlag(E,R,S,sec):
    sendElem(E.a1())
    sendElem(E.a2())
    sendElem(E.a3())
    sendElem(E.a4())
    sendElem(E.a6())
    sendElem(R[0])
    sendElem(R[1])
    sendElem(S[0])
    sendElem(S[1])
    j = EAB.j_invariant()
    K = hashlib.sha256(elem_to_bytes(j)).digest()
    M = hashlib.sha256(str(sec).encode("ascii")).digest()[:16]
    print(M)
    #M = b"Hello world.\x00\x00\x00\x00"
    C = AES.new(K, AES.MODE_ECB).encrypt(M)
    t.sendline(C.hex())
    t.interactive()

    
def test_sk(a,i):
    Pmod = Pt-a*(3**(e3-i-1))*Qt
    Qmod = (1+3**(e3-i-1))*Qt
    RR = Zmod(3**e3)
    psi = ZZ(1/RR(1+3**(e3-i-1)).sqrt())
    print(EAB)
    return oracle(Et,psi*Pmod,psi*Qmod,EAB)
    
def get_sk_trit(i,a=0):
    if test_sk(a,i):
        return a
    a += 3**i
    if test_sk(a,i):
        return a
    return a + 3**i

def get_sk():
    a = 0
    for i in range(e3-2):
        a = get_sk_trit(i,a)
        print((i,a))
    for x in range(9):
        ar = a + x*3**(e3-2)
        Eat,_,_ = isogen3(ar)
        if Eat.j_invariant() == EA.j_invariant():
            return ar

sec=get_sk()
print(sec)
submitFlag(Et,Pt,Qt,sec)

