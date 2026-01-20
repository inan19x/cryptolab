# RSA_sign.py — TOY RSA DIGITAL SIGNATURE (EDUCATIONAL ONLY)
from cryptography.hazmat.primitives import serialization


def load_private_key():
    """
    Load private key
    Returns (d, n) integers for toy RSA
    """
    with open("private.key", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    numbers = private_key.private_numbers()
    return numbers.d, numbers.public_numbers.n


def toy_hash(data, n):
    """
    Very weak hash: sum of bytes modulo n
    (ONLY for educational purposes)
    """
    return sum(data) % n


def main():
    print("=== TOY RSA SIGNATURE ===")

    d, n = load_private_key()

    filename = input("Enter file to sign: ")

    with open(filename, "rb") as f:
        data = f.read()

    h = toy_hash(data, n)
    signature = pow(h, d, n)

    sig_file = filename + ".sig"
    with open(sig_file, "w") as f:
        f.write(str(signature))

    print(f"[+] File signed successfully → {sig_file}")
    print(f"[i] Hash value: {h}")


if __name__ == "__main__":
    main()

