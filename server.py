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
server_pub, server_priv = SimpleRSA.generate_keypair()
print(f"Server RSA Public Key: {server_pub}")

def broadcast_message(sender_conn, encrypted_packet):
    sender_data = clients[sender_conn]
    session_key = sender_data['key']
    sender_pub_rsa = sender_data['pub_rsa']

    try:
        decrypted_packet = DES.des_decrypt(encrypted_packet, session_key)

        msg_bytes, sig_str_bytes = decrypted_packet.rsplit(b"||SIGN||", 1)
        signature_int = int(sig_str_bytes.decode('utf-8'))

        is_valid = SimpleRSA.verify(sender_pub_rsa, msg_bytes, signature_int)
        
        if is_valid:
            print(f"Signature verified from {sender_conn.getpeername()}.")
            data_didekripsi = msg_bytes.decode('utf-8', errors='ignore')
            
            with clients_lock:
                for client_conn, client_data in clients.items():
                    if client_conn != sender_conn:
                        try:
                            final_msg = f"[User {sender_conn.fileno()}]: {data_didekripsi}".encode('utf-8')
                            data_terenkripsi = DES.des_encrypt(final_msg, client_data['key'])
                            client_conn.sendall(data_terenkripsi)
                        except Exception as e:
                            print(f"Error sending to client: {e}")
        else:
            print(f"Invalid Signature from {sender_conn.getpeername()}.")

    except Exception as e:
        print(f"Error decrypting from sender: {e}")
        return

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    try:
        pub_key_str = json.dumps(server_pub)
        conn.sendall(pub_key_str.encode('utf-8'))

        client_pub_data = conn.recv(1024)
        client_pub_key = tuple(json.loads(client_pub_data.decode('utf-8')))

        encrypted_key_bytes = conn.recv(1024)
        encrypted_key_int = int(encrypted_key_bytes.decode('utf-8'))

        KEY_BYTES = SimpleRSA.decrypt_key(server_priv, encrypted_key_int)
        KEY_BYTES = KEY_BYTES.rjust(8, b'\0')

        print(f"Session Key established for {addr}: {KEY_BYTES}")
        with clients_lock:
            clients[conn] = {'key': KEY_BYTES, 'pub_rsa': client_pub_key}
        conn.sendall(b"ACK")

        while True:
            data_terenkripsi = conn.recv(4096)
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
