import socket
import threading
import DES
import SimpleRSA
import json
import random
import string
import sys
import time

SERVER_IP = '127.0.0.1'
PORT = 65432

pub_key, priv_key = SimpleRSA.generate_keypair()
print(f"My Public Key: {pub_key}")

def generate_session_key():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(8))

def receive_messages(sock, session_key):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("\nDisconnected from server.")
                break

            data_didekripsi = DES.des_decrypt(data, session_key)
            print(f"\n[Incoming]: {data_didekripsi.decode('utf-8')}")
            print("Enter message: ", end='', flush=True)

        except ConnectionResetError:
            print("\nConnection lost.")
            break
        except Exception as e:
            print(f"\nError receiving: {e}")
            break
    sys.exit()

def start_client():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to {SERVER_IP}:{PORT}...")
        s.connect((SERVER_IP, PORT))
        print("Connected.")

        data = s.recv(4096)
        server_pub_key = tuple(json.loads(data.decode('utf-8')))
        print(f"Received Server Public Key.")

        s.sendall(json.dumps(pub_key).encode('utf-8'))
        key_str = generate_session_key()
        KEY_BYTES = key_str.encode('utf-8')
        print(f"Generated Session Key: {KEY_BYTES}")

        encrypted_key_int = SimpleRSA.encrypt_key(server_pub_key, KEY_BYTES)
        time.sleep(0.1)
        s.sendall(str(encrypted_key_int).encode('utf-8'))

        ack = s.recv(1024) 
        if ack != b"ACK":
            print("Handshake failed.")
            return

        recv_thread = threading.Thread(target=receive_messages, args=(s, KEY_BYTES))
        recv_thread.daemon = True
        recv_thread.start()

        while True:
            pesan_string = input("Enter message: ")
            if pesan_string.lower() == 'exit':
                break
                
            pesan_bytes = pesan_string.encode('utf-8')

            signature_int = SimpleRSA.sign(priv_key, pesan_bytes)
            packet = pesan_bytes + b"||SIGN||" + str(signature_int).encode('utf-8')

            data_terenkripsi = DES.des_encrypt(packet, KEY_BYTES)

            s.sendall(data_terenkripsi)

    except ConnectionRefusedError:
        print("Connection failed.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()
        print("Client closed.")

if __name__ == "__main__":
    start_client()
