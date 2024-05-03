import random
from math import gcd
import hashlib

def is_primitive_root(g, p):
    seen = set()
    for i in range(1, p):
        val = pow(g, i, p)
        if val in seen:
            return False
        seen.add(val)
    return len(seen) == p - 1

def find_primitive_root(p):
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
   
def generate_random_k(q):
    while True:
        k = random.randint(1, q - 1)
        if gcd(k, q - 1) == 1:
            return k

q = 71
alpha = find_primitive_root(q)

#Key Generation
Xa = random.randint(2, q - 2)
Ya = pow(alpha, Xa, q)
PrivateKey = Xa
PublicKey = Ya

print(f"Public Key: {PublicKey}")
print(f"Private Key: {PrivateKey}")

k = generate_random_k(q)
K = pow(Ya, k, q) #lecture
K = pow(alpha, k, q) #GPT


