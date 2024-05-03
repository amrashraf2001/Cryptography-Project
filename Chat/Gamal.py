import random

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
   
q = 71
alpha = find_primitive_root(q)

#Key Generation
Xa = random.randint(1, q - 1)
Ya = pow(alpha, Xa, q)
PrivateKey = Xa
PublicKey = Ya

print(f"Public Key: {PublicKey}")
print(f"Private Key: {PrivateKey}")

