# RSA_encrypt.py — TOY RSA FILE ENCRYPTION (EDUCATIONAL ONLY)
import os
from cryptography.hazmat.primitives import serialization


def load_public_key():
    """
    Load OpenSSL-compatible PEM public key
    Returns (e, n) integers for toy RSA
    """
    with open("public.key", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    numbers = public_key.public_numbers()
    return numbers.e, numbers.n


def main():
    e, n = load_public_key()

    input_file = input("Enter plaintext file name (e.g. message.txt): ")
    output_file = input_file + ".enc"

    with open(input_file, "r", encoding="utf-8") as f:
        plaintext = f.read()

    encrypted_numbers = []

    for char in plaintext:
        m = ord(char)

        if m >= n:
            raise ValueError(
                f"Character '{char}' (ASCII {m}) is too large for modulus n={n}"
            )

        c = pow(m, e, n)
        encrypted_numbers.append(str(c))

    # Write encrypted file
    with open(output_file, "w") as f:
        f.write(" ".join(encrypted_numbers))

    # Remove original plaintext file
    os.remove(input_file)

    print(f"[+] File encrypted successfully → {output_file}")
    print(f"[i] Original file '{input_file}' has been deleted.")


if __name__ == "__main__":
    main()

