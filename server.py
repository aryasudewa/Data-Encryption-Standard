import socket
import DES


HOST = '0.0.0.0' # listen ke semua IP
PORT = 65432

KEY_STRING = "kuncirahasia123"
KEY_BYTES = KEY_STRING.encode('utf-8')

print("Menjalankan server...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # buat socket
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server mendengarkan di {HOST}:{PORT}...")

    conn, addr = s.accept()
    
    with conn:
        print(f"Terhubung dengan client dari {addr}")

        data_terenkripsi = conn.recv(1024)
        
        if not data_terenkripsi:
            print("Client terputus, tidak ada data.")
        else:
            print(f"Menerima {len(data_terenkripsi)} byte data terenkripsi.")
            
            try:
                data_didekripsi = DES.des_decrypt(data_terenkripsi, KEY_BYTES)
                
                pesan_asli = data_didekripsi.decode('utf-8')
                
                print(f"Pesan Asli Berhasil Didekripsi: {pesan_asli}")
                
            except Exception as e:
                print(f"GAGAL mendekripsi data: {e}")
                print("Ini bisa terjadi jika Kunci (KEY) salah atau data rusak.")

print("Server ditutup.")