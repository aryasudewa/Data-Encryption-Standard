import random
import hashlib

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi

def is_prime(num):
    if num < 2: return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_prime(min_val, max_val):
    while True:
        num = random.randint(min_val, max_val)
        if is_prime(num):
            return num

def generate_keypair():
    min_prime = 5000000000
    max_prime = 10000000000
    p = generate_prime(min_prime, max_prime)
    q = generate_prime(min_prime, max_prime)

    while p == q:
        q = generate_prime(min_prime, max_prime)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537

    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = multiplicative_inverse(e, phi)

    return ((e, n), (d, n))

def encrypt_key(public_key, des_key_bytes):
    e, n = public_key
    m = int.from_bytes(des_key_bytes, byteorder='big')
    if m >= n:
        raise ValueError("Key too large")
    c = pow(m, e, n)
    return c

def decrypt_key(private_key, cipher_int):
    d, n = private_key
    m = pow(cipher_int, d, n)
    try:
        return m.to_bytes(8, byteorder='big')
    except OverflowError:
        length = (m.bit_length() + 7) // 8
        return m.to_bytes(length, byteorder='big')

def sign(private_key, message_bytes):
    d, n = private_key
    msg_hash = hashlib.sha256(message_bytes).digest()
    m = int.from_bytes(msg_hash, byteorder='big')
    m = m % n
    signature = pow(m, d, n)
    return signature

def verify(public_key, message_bytes, signature_int):
    e, n = public_key
    hash_int_from_sig = pow(signature_int, e, n)
    actual_hash_bytes = hashlib.sha256(message_bytes).digest()
    actual_hash_int = int.from_bytes(actual_hash_bytes, byteorder='big')
    actual_hash_int = actual_hash_int % n
    return hash_int_from_sig == actual_hash_int
