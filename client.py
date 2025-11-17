import socket
import DES
import SimpleRSA
import json
import random
import string

SERVER_IP = '20.40.52.181' 
PORT = 65432

def generate_session_key():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(8))

pesan_string = input("Enter message: ")
pesan_bytes = pesan_string.encode('utf-8')

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to {SERVER_IP}:{PORT}...")
        s.connect((SERVER_IP, PORT))
        print("Connected.")

        pub_key_data = s.recv(1024)
        public_key = tuple(json.loads(pub_key_data.decode('utf-8')))
        print(f"Received Public Key: {public_key}")

        key_str = generate_session_key()
        KEY_BYTES = key_str.encode('utf-8')
        print(f"Generated Session Key: {KEY_BYTES}")

        encrypted_key_int = SimpleRSA.encrypt_key(public_key, KEY_BYTES)
        s.sendall(str(encrypted_key_int).encode('utf-8'))
        
        s.recv(1024) 

        print("Encrypting message...")
        data_terenkripsi = DES.des_encrypt(pesan_bytes, KEY_BYTES)
        
        print(f"Original: '{pesan_string}'")
        print(f"Encrypted: {len(data_terenkripsi)} bytes")
        
        s.sendall(data_terenkripsi)
        print("Data sent.")
        
except ConnectionRefusedError:
    print("Connection failed.")
except Exception as e:
    print(f"Error: {e}")

print("Client closed.")