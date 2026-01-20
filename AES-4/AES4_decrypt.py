# AES_decrypt.py — TOY AES-4 FILE DECRYPTION (EDUCATIONAL ONLY)

import os

def load_key():
    with open("aes.key", "r") as f:
        return int(f.read()) & 0x0F

def decrypt_byte(byte, key):
    return byte ^ key

def main():
    key = load_key()

    input_file = input("Enter encrypted file name (e.g. message.txt.enc): ")
    if not input_file.endswith(".enc"):
        raise ValueError("Encrypted file must end with .enc")

    output_file = input_file[:-4]

    with open(input_file, "rb") as f:
        ciphertext = f.read()

    plaintext = bytearray(decrypt_byte(b, key) for b in ciphertext)

    with open(output_file, "wb") as f:
        f.write(plaintext)

    os.remove(input_file)

    print(f"File decrypted → {output_file}")
    print(f"Encrypted file '{input_file}' deleted")

if __name__ == "__main__":
    main()

