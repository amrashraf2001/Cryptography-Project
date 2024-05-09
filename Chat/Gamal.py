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

def generate_keys(q):
    alpha = find_primitive_root(q)
    Xa = random.randint(2, q - 2)
    Ya = pow(alpha, Xa, q)
    PublicKey = (q, alpha, Ya)
    PrivateKey = Xa
    return PublicKey, PrivateKey

def generate_random_k(q):
    while True:
        k = random.randint(1, q - 1)
        if gcd(k, q - 1) == 1:
            return k

def sign_message(message, public_key, private_key):
    
    q, alpha, _ = public_key
    Xa = private_key
    k = generate_random_k(q)    
    C1 = pow(alpha, k, q)
    h = int(hashlib.sha1(message.encode()).hexdigest(), 16)
    C2 = (h - Xa * C1) * pow(k, -1, q - 1)
    return C1, C2

def check_signature(message, signature, public_key):

    q, alpha, Ya = public_key
    C1, C2 = signature
    h = int(hashlib.sha1(message.encode()).hexdigest(), 16)
    P1 = pow(Ya, C1, q)
    P2 = pow(C1, C2, q)
    V1 = P1 * P2 % q
    V2 = pow(alpha, h, q)
    return V1 == V2


# Main 
q = 71
PublicKey, PrivateKey = generate_keys(q)

print(f"Public Key: {PublicKey}")
print(f"Private Key: {PrivateKey}")

message = "Hello World"
C1, C2 = sign_message(message, PublicKey, PrivateKey)

print(f"Message: {message}")
print(f"Signature: {C1}, {C2}")

print(f"Signature is valid: {check_signature(message, (C1, C2), PublicKey)}")