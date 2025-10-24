import socket
import DES  # Mengimpor file DES.py Anda

# --- Konfigurasi ---
# Ganti '127.0.0.1' dengan ALAMAT IP Device B (Server)
# Jika Anda menjalankan di device yang sama, biarkan '127.0.0.1' (localhost)
SERVER_IP = '127.0.0.1' 
PORT = 65432 # Port harus sama dengan server

# Kunci ini HARUS sama persis dengan yang ada di server
KEY_STRING = "kuncirahasia123"
# Fungsi DES Anda memerlukan kunci dalam bentuk bytes
KEY_BYTES = KEY_STRING.encode('utf-8')
# --------------------

# Ambil input string dari pengguna
pesan_string = input("Masukkan pesan yang ingin dikirim: ")
# Ubah string ke bytes
pesan_bytes = pesan_string.encode('utf-8')

print("Melakukan enkripsi pesan...")
try:
    # --- Proses Inti: Enkripsi ---
    # Gunakan fungsi des_encrypt dari file DES.py
    # Fungsi ini sudah otomatis menangani padding
    data_terenkripsi = DES.des_encrypt(pesan_bytes, KEY_BYTES)
    
    print(f"Pesan asli: '{pesan_string}' ({len(pesan_bytes)} bytes)")
    print(f"Data terenkripsi: ({len(data_terenkripsi)} bytes)")

    # Membuat socket TCP/IP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Menghubungkan ke server di {SERVER_IP}:{PORT}...")
        s.connect((SERVER_IP, PORT))
        print("Berhasil terhubung.")
        
        # Mengirim data yang SUDAH terenkripsi
        s.sendall(data_terenkripsi)
        print("Data terenkripsi telah terkirim.")
        
except ConnectionRefusedError:
    print(f"Koneksi Gagal. Pastikan server di {SERVER_IP} sudah berjalan.")
except Exception as e:
    print(f"Terjadi error: {e}")

print("Client ditutup.")