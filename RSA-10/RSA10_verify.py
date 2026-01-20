# RSA_verify.py — TOY RSA SIGNATURE VERIFICATION (EDUCATIONAL ONLY)
from cryptography.hazmat.primitives import serialization


def load_public_key():
    """
    Load public key
    Returns (e, n) integers for toy RSA
    """
    with open("public.key", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    numbers = public_key.public_numbers()
    return numbers.e, numbers.n


def toy_hash(data, n):
    """
    Same hash used in signing
    """
    return sum(data) % n


def main():
    print("=== TOY RSA SIGNATURE VERIFICATION ===")

    e, n = load_public_key()

    filename = input("Enter file to verify: ")
    sig_file = filename + ".sig"

    with open(filename, "rb") as f:
        data = f.read()

    with open(sig_file, "r") as f:
        signature = int(f.read())

    h = toy_hash(data, n)
    recovered = pow(signature, e, n)

    print(f"[i] Computed hash: {h}")
    print(f"[i] Recovered from sig: {recovered}")

    if h == recovered:
        print("[+] Signature is VALID")
    else:
        print("[!] Signature is INVALID")


if __name__ == "__main__":
    main()

