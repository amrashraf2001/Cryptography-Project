import random
import hashlib

def gcd(a,b):
    while b!=0:
        a,b=b,a%b
    return a

def is_primitive_root(alpha, q):
    seen = set()
    for i in range(1, q):
        val = pow(alpha, i, q)
        if val in seen:
            return False
        seen.add(val)
    return len(seen) == q - 1

def find_primitive_root(q):
    for alpha in range(2, q):
        if is_primitive_root(alpha, q):
            return alpha

def generate_keys(q, p):
    Xa = random.randint(1, q - 1)
    Ya = pow(p, Xa, q)
    PublicKey = Ya
    PrivateKey = Xa
    return PublicKey, PrivateKey

q = 71
p = find_primitive_root(q)

PublicKey, PrivateKey = generate_keys(q, p)
