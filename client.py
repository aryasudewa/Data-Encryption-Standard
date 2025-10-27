import socket
import DES

# Dari server ipconfig, masuka ip nya kesini

SERVER_IP = '127.0.0.1' 
PORT = 65432

KEY_STRING = "kuncirahasia123"
KEY_BYTES = KEY_STRING.encode('utf-8')
# --------------------

pesan_string = input("Masukkan pesan yang ingin dikirim: ")
pesan_bytes = pesan_string.encode('utf-8')

print("Melakukan enkripsi pesan...")
try:
    data_terenkripsi = DES.des_encrypt(pesan_bytes, KEY_BYTES)
    
    print(f"Pesan asli: '{pesan_string}' ({len(pesan_bytes)} bytes)")
    print(f"Data terenkripsi: ({len(data_terenkripsi)} bytes)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # buat socket buat ngehubungin client ke server
        print(f"Menghubungkan ke server di {SERVER_IP}:{PORT}...")
        s.connect((SERVER_IP, PORT))
        print("Berhasil terhubung.")
        
        s.sendall(data_terenkripsi)
        print("Data terenkripsi telah terkirim.")
        
except ConnectionRefusedError:
    print(f"Koneksi Gagal. Pastikan server di {SERVER_IP} sudah berjalan.")
except Exception as e:
    print(f"Terjadi error: {e}")

print("Client ditutup.")