import socket
import threading
import DES
import SimpleRSA
import json

HOST = '0.0.0.0'
PORT = 65432

clients = {} 
clients_lock = threading.Lock()

print("Server started.")
public_key, private_key = SimpleRSA.generate_keypair()
print(f"Public Key: {public_key}")

def broadcast_message(sender_conn, message_bytes):
    sender_key = clients[sender_conn]

    try:
        data_didekripsi = DES.des_decrypt(message_bytes, sender_key)
        print(f"Decrypted message: {data_didekripsi.decode('utf-8')}")
        
    except Exception as e:
        print(f"Error decrypting from sender: {e}")
        return

    with clients_lock:
        for client_conn, client_key in clients.items():
            if client_conn != sender_conn:
                try:
                    data_terenkripsi = DES.des_encrypt(data_didekripsi, client_key)
                    client_conn.sendall(data_terenkripsi)
                except Exception as e:
                    print(f"Error sending to client: {e}")

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    try:
        pub_key_str = json.dumps(public_key)
        conn.sendall(pub_key_str.encode('utf-8'))

        encrypted_key_bytes = conn.recv(1024)
        encrypted_key_int = int(encrypted_key_bytes.decode('utf-8'))

        KEY_BYTES = SimpleRSA.decrypt_key(private_key, encrypted_key_int)
        KEY_BYTES = KEY_BYTES.rjust(8, b'\0')

        print(f"Session Key established for {addr}: {KEY_BYTES}")
        with clients_lock:
            clients[conn] = KEY_BYTES
        conn.sendall(b"ACK")

        while True:
            data_terenkripsi = conn.recv(1024)
            if not data_terenkripsi:
                break
            broadcast_message(conn, data_terenkripsi)
    except Exception as e:
        print(f"Error with client {addr}: {e}")
    finally:
        with clients_lock:
            if conn in clients:
                del clients[conn]
        conn.close()
        print(f"Connection closed for {addr}")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.bind((HOST, PORT))
      s.listen()
      print(f"Listening on {HOST}:{PORT}...")

      while True:
          conn, addr = s.accept()
          thread = threading.Thread(target=handle_client, args=(conn, addr))
          thread.start()

if __name__ == "__main__":
    start_server()
