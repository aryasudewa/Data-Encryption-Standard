import socket
import DES
import SimpleRSA 
import json

HOST = '0.0.0.0'
PORT = 65432

print("Server started.")
public_key, private_key = SimpleRSA.generate_keypair()
print(f"Public Key: {public_key}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    
    with conn:
        print(f"Connected by {addr}")
        
        pub_key_str = json.dumps(public_key)
        conn.sendall(pub_key_str.encode('utf-8'))

        encrypted_key_bytes = conn.recv(1024)
        encrypted_key_int = int(encrypted_key_bytes.decode('utf-8'))
        
        KEY_BYTES = SimpleRSA.decrypt_key(private_key, encrypted_key_int)
        KEY_BYTES = KEY_BYTES.rjust(8, b'\0')
        
        print(f"Secret Key received: {KEY_BYTES}")
        conn.sendall(b"ACK")

        data_terenkripsi = conn.recv(1024)
        
        if not data_terenkripsi:
            print("No data received.")
        else:
            print(f"Received {len(data_terenkripsi)} bytes.")
            
            try:
                data_didekripsi = DES.des_decrypt(data_terenkripsi, KEY_BYTES)
                
                pesan_asli = data_didekripsi.decode('utf-8')
                
                print(f"Decrypted message: {pesan_asli}")
                
            except Exception as e:
                print(f"Decryption failed: {e}")

print("Server closed.")