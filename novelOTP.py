import os
import struct

PRIME_64 = (1 << 61) - 1

def generate_random_key(length: int) -> bytes:
    return os.urandom(length)

def xor_operation(data1: bytes, data2: bytes) -> bytes:
    if len(data1) != len(data2):
        raise ValueError("Inputs must have the same length")
    return bytes(a ^ b for a, b in zip(data1, data2))

def otp_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return xor_operation(plaintext, key)

def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return xor_operation(ciphertext, key)

def save_bytes(path: str, data: bytes, overwrite: bool = False):
    mode = 'wb' if overwrite else 'xb'
    with open(path, mode) as f:
        f.write(data)

def load_bytes(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

def overwrite_and_delete_file(path: str, passes: int = 1):
    try:
        size = os.path.getsize(path)
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
    except FileNotFoundError:
        pass

def polynomial_hash(data: bytes, a: int, b: int, mod: int = PRIME_64) -> int:
    h = b % mod
    for x in data:
        h = (h * a + x) % mod
    return h

def generate_mac_key() -> tuple[int, int]:
    mod = PRIME_64
    a = int.from_bytes(os.urandom(8), 'big') % (mod - 1) + 1
    b = int.from_bytes(os.urandom(8), 'big') % mod
    return (a, b)

def create_mac_tag(data: bytes, mac_key: tuple[int, int]) -> bytes:
    a, b = mac_key
    tag_int = polynomial_hash(data, a, b)
    return struct.pack('>Q', tag_int)

def verify_mac_tag(data: bytes, mac_key: tuple[int, int], tag: bytes) -> bool:
    expected = create_mac_tag(data, mac_key)
    return expected == tag

def encrypt_with_mac(plaintext: bytes):
    key = generate_random_key(len(plaintext))
    ciphertext = otp_encrypt(plaintext, key)
    mac_key = generate_mac_key()
    tag = create_mac_tag(ciphertext, mac_key)
    return ciphertext, key, mac_key, tag

def decrypt_with_mac(ciphertext: bytes, key: bytes, mac_key: tuple[int, int], tag: bytes):
    if not verify_mac_tag(ciphertext, mac_key, tag):
        raise ValueError("MAC verification failed")
    return otp_decrypt(ciphertext, key)

if __name__ == "__main__":
    message = b"Secret message: OTP is powerful if used correctly!"
    ciphertext, key, mac_key, tag = encrypt_with_mac(message)
    print("Ciphertext (hex):", ciphertext.hex())
    recovered = decrypt_with_mac(ciphertext, key, mac_key, tag)
    # print("Recovered:", recovered)
