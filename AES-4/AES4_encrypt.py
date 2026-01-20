# AES_encrypt.py — TOY AES-4 FILE ENCRYPTION (EDUCATIONAL ONLY)

import os

def load_key():
    with open("aes.key", "r") as f:
        return int(f.read()) & 0x0F  # force 4-bit

def encrypt_byte(byte, key):
    return byte ^ key

def main():
    key = load_key()

    input_file = input("Enter plaintext file name: ")
    output_file = input_file + ".enc"

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = bytearray(encrypt_byte(b, key) for b in plaintext)

    with open(output_file, "wb") as f:
        f.write(ciphertext)

    os.remove(input_file)

    print(f"File encrypted → {output_file}")
    print(f"Original file '{input_file}' deleted")
    print(f"(Used 4-bit key: {key})")

if __name__ == "__main__":
    main()

