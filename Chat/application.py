import random
import hashlib

def gcd(a,b):
    while b!=0:
        a,b=b,a%b
    return a

def generate_keys_diffie(q, alpha):
    Xa = random.randint(1, q - 1)
    Ya = pow(alpha, Xa, q)
    PublicKey = Ya
    PrivateKey = Xa
    return PublicKey, PrivateKey

def generate_keys_gamal(q, alpha):
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

#for diffie hellman
q_DH = 71
alpha_DH = 7
PublicKey_DH, PrivateKey_DH = generate_keys_diffie(q_DH, alpha_DH)

#Gamal
q_Gamal = 71
alpha_Gamal = 7
PublicKey_Gamal, PrivateKey_Gamal = generate_keys_gamal(q_Gamal, alpha_Gamal)

#sockets for gamal public key

C1, C2 = sign_message(PublicKey_DH, PublicKey_Gamal, PrivateKey_Gamal)

#sockets for DH public after sign

valid = check_signature(PublicKey_DH, (C1, C2), PublicKey_Gamal)
if valid:
    print("Signature is valid")
else:   
    print("Signature is not valid")
    exit

