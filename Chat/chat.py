import random
import hashlib
import socket
import base64
from Crypto.Cipher import AES
import os

SERVER_PORT = 54321  # Define your server port

def read_parameters():
    with open("parameters.txt", "r") as file:
        q, alpha = map(int, file.read().split())
    return q, alpha

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

def adjust_number(number, lower_bound, upper_bound):
    if number < lower_bound or number > upper_bound:
        lsb = 1 if number < lower_bound else 0
        adjusted_number = (number & ~(1 << 0)) | (lsb << 0)
        return adjusted_number
    return number

def sign_message(message, public_key, private_key):
    q, alpha, _ = public_key
    
    h = int(hashlib.sha1(str(message).encode()).hexdigest(), 16)

    adjust_number(int(h), 0, q - 1)

    Xa = private_key
    k = generate_random_k(q)    
    C1 = pow(alpha, k, q)
    C2 = (h - Xa * C1) * pow(k, -1, q - 1)
    return C1, C2

def check_signature(message, signature, public_key):
    q, alpha, Ya = public_key
    C1, C2 = signature
    h = int(hashlib.sha1(str(message).encode()).hexdigest(), 16)
    P1 = pow(Ya, C1, q)
    P2 = pow(C1, C2, q)
    V1 = P1 * P2 % q
    V2 = pow(alpha, h, q)
    return V1 == V2

def generate_aes_key(shared_key):
    sha256 = hashlib.sha256()
    sha256.update(str(shared_key).encode())
    aes_key = sha256.digest()[:32]  # Take the first 32 bytes for a 256-bit key
    return aes_key

def pad(data):
    # Pad the data to be a multiple of AES block size (16 bytes)
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    # Unpad the data
    padding_len = data[-1]
    return data[:-padding_len]

def encrypt(data, shared_key):
    key = generate_aes_key(shared_key)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode())
    ct = cipher.encrypt(padded_data)
    return base64.b64encode(ct).decode('utf-8')

def decrypt(ct, shared_key):
    key = generate_aes_key(shared_key)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = cipher.decrypt(base64.b64decode(ct))
    return unpad(padded_data).decode('utf-8')

q_param, alpha_param = read_parameters()

def act_as_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of the port
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        server_socket.bind(("localhost", SERVER_PORT))
        server_socket.listen()
        print("Running as server on port:", SERVER_PORT)
        conn, addr = server_socket.accept()
        with conn:
            print("Connected by", addr)
            # Implement logic for sending and receiving messages
            # Implement logic for sending and receiving messages
                            #Diffie Hellman
            q_DH = q_param
            alpha_DH = alpha_param
            PublicKey_DH, PrivateKey_DH = generate_keys_diffie(q_DH, alpha_DH)

            #Gamal
            q_Gamal = q_param
            alpha_Gamal = alpha_param
            PublicKey_Gamal, PrivateKey_Gamal = generate_keys_gamal(q_Gamal, alpha_Gamal)
            
            print("Alice send:", PublicKey_Gamal)
            data_to_send = str(PublicKey_Gamal)
            conn.sendall(str(data_to_send).encode())
            PublicKey_Gamal_Bob = conn.recv(1024).decode()
            print("send from Bob:", PublicKey_Gamal_Bob)
            
            C1, C2 = sign_message(PublicKey_DH, PublicKey_Gamal, PrivateKey_Gamal)
            temp = (C1, C2, PublicKey_DH)
            data_to_send = str(temp)
            print("Alice send:", data_to_send)
            conn.sendall(str(data_to_send).encode())
            C1_C2_Yb_Bob = conn.recv(1024).decode()
            print("send from Bob:", C1_C2_Yb_Bob)
            if(C1_C2_Yb_Bob == "exit"):
                return

            C1_Bob, C2_Bob, PublicKey_DH_Bob = C1_C2_Yb_Bob.strip("()").split(", ")
            q_G_Bob, alpha_G_Bob, Yb_Bob = PublicKey_Gamal_Bob.strip("()").split(", ")
            PublicKey_Gamal_Bob = (int(q_G_Bob), int(alpha_G_Bob), int(Yb_Bob))
            valid = check_signature(int(PublicKey_DH_Bob), (int(C1_Bob), int(C2_Bob)), PublicKey_Gamal_Bob)
            if valid:
                conn.sendall("VALID".encode())
                print("Signature is valid")
            else:   
                print("Signature is not valid")
                conn.sendall("exit".encode())
                return

            K = pow(int(PublicKey_DH_Bob), PrivateKey_DH, q_DH)
            print("K:", K)
            aes_key = generate_aes_key(K)
            print("AES Key:", aes_key)

            while True:
                message = input("Alice: ")
                cipher = encrypt(message, aes_key)
                print("Encrypted Message to send from alice : ", cipher)
                conn.sendall(cipher.encode())
                data = conn.recv(1024)
                print("Cipher Recived from bob : ",data)
                plaintext = decrypt(data.decode(), aes_key)
                print("Bob sent:", plaintext)

def act_as_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect(("localhost", SERVER_PORT))
            print("Running as client, connected to server")
            # Implement logic for sending and receiving messages
            #Diffie Hellman
            q_DH = q_param
            alpha_DH = alpha_param
            PublicKey_DH, PrivateKey_DH = generate_keys_diffie(q_DH, alpha_DH)

            #Gamal
            q_Gamal = q_param
            alpha_Gamal = alpha_param
            PublicKey_Gamal, PrivateKey_Gamal = generate_keys_gamal(q_Gamal, alpha_Gamal)

            PublicKey_Gamal_Alice = client_socket.recv(1024).decode()
            print("send from Alice:", PublicKey_Gamal_Alice)
            print("Bob send:", PublicKey_Gamal)
            client_socket.sendall(str(PublicKey_Gamal).encode())

            C1_C2_Ya_Alice = client_socket.recv(1024).decode()
            print("send from Alice:", C1_C2_Ya_Alice)

            C1_Alice, C2_Alice, PublicKey_DH_Alice = C1_C2_Ya_Alice.strip("()").split(", ")
            q_G_Alice, alpha_G_Alice, Ya_Alice = PublicKey_Gamal_Alice.strip("()").split(", ")
            PublicKey_Gamal_Alice = (int(q_G_Alice), int(alpha_G_Alice), int(Ya_Alice))
            valid = check_signature(int(PublicKey_DH_Alice), (int(C1_Alice), int(C2_Alice)), PublicKey_Gamal_Alice)
            if valid:
                print("Signature is valid")
            else:   
                print("Signature is not valid")
                client_socket.sendall("exit".encode())
                return
            
            C1, C2 = sign_message(PublicKey_DH, PublicKey_Gamal, PrivateKey_Gamal)
            temp = (C1, C2, PublicKey_DH)
            data_to_send = str(temp)
            print("Bob send:", data_to_send)
            client_socket.sendall(str(data_to_send).encode())
            C1_C2_Yb_Alice = client_socket.recv(1024).decode()
            print("send from Alice:", C1_C2_Yb_Alice)
            if(C1_C2_Yb_Alice == "exit"):
                return

            K = pow(int(PublicKey_DH_Alice), PrivateKey_DH, q_DH)
            print("K:", K)
            aes_key = generate_aes_key(K)
            print("AES Key:", aes_key)

            while True:
                cipher = client_socket.recv(1024)
                print("Bob Recived : ",cipher)
                plain = decrypt(cipher.decode(), aes_key)
                print("Alice sent:", plain)
                message = input("Bob: ")
                encrypted_message = encrypt(message, aes_key)
                print("Encrypted Message to send from bob : ", encrypted_message)
                client_socket.sendall(encrypted_message.encode())
        except ConnectionRefusedError:
            print("No server found. Please start another instance to connect.")

def main():
    try:
        act_as_server()
 
    except OSError:
        act_as_client()

if __name__ == "__main__":
    main()
