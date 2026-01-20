# RSA_decrypt.py — TOY RSA FILE DECRYPTION (EDUCATIONAL ONLY)
import os
from cryptography.hazmat.primitives import serialization


def load_private_key():
    """
    Load OpenSSL-compatible PEM private key
    Returns (d, n) integers for toy RSA
    """
    with open("private.key", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    numbers = private_key.private_numbers()
    return numbers.d, numbers.public_numbers.n


def main():
    d, n = load_private_key()

    input_file = input("Enter encrypted file name (e.g. message.txt.enc): ")

    if not input_file.endswith(".enc"):
        raise ValueError("Encrypted file must have a .enc extension")

    # Restore original filename by removing ".enc"
    output_file = input_file[:-4]

    with open(input_file, "r") as f:
        encrypted_numbers = f.read().split()

    decrypted_chars = []

    for c in encrypted_numbers:
        m = pow(int(c), d, n)
        decrypted_chars.append(chr(m))

    # Write decrypted file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("".join(decrypted_chars))

    # Remove the encrypted file
    os.remove(input_file)

    print(f"[+] File decrypted successfully → {output_file}")
    print(f"[i] Encrypted file '{input_file}' has been deleted.")


if __name__ == "__main__":
    main()

