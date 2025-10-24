import socket
import DES  # Mengimpor file DES.py Anda

# --- Konfigurasi ---
# '0.0.0.0' berarti server akan mendengarkan di semua alamat IP 
# yang tersedia di device ini (termasuk IP jaringan lokal).
HOST = '0.0.0.0'  
PORT = 65432        # Port yang akan didengarkan (bisa angka apa saja > 1023)

# Kunci ini HARUS sama persis dengan yang ada di client
KEY_STRING = "kuncirahasia123"
# Fungsi DES Anda memerlukan kunci dalam bentuk bytes
KEY_BYTES = KEY_STRING.encode('utf-8')
# --------------------

print("Menjalankan server...")
# Membuat socket TCP/IP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server mendengarkan di {HOST}:{PORT}...")

    # Menunggu koneksi masuk (program akan "berhenti" di sini)
    conn, addr = s.accept()
    
    with conn:
        print(f"Terhubung dengan client dari {addr}")
        
        # Menerima data dari client (maksimal 1024 bytes)
        data_terenkripsi = conn.recv(1024)
        
        if not data_terenkripsi:
            print("Client terputus, tidak ada data.")
        else:
            print(f"Menerima {len(data_terenkripsi)} byte data terenkripsi.")
            
            try:
                # --- Proses Inti: Dekripsi ---
                # Gunakan fungsi des_decrypt dari file DES.py
                data_didekripsi = DES.des_decrypt(data_terenkripsi, KEY_BYTES)
                
                # Ubah kembali dari bytes ke string
                pesan_asli = data_didekripsi.decode('utf-8')
                
                print(f"Pesan Asli Berhasil Didekripsi: {pesan_asli}")
                
            except Exception as e:
                print(f"GAGAL mendekripsi data: {e}")
                print("Ini bisa terjadi jika Kunci (KEY) salah atau data rusak.")

print("Server ditutup.")