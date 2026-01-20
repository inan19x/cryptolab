# RSA_crack.py — TOY RSA BREAKER
# EDUCATIONAL PURPOSES ONLY — INTENTIONALLY INSECURE

from math import gcd
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def load_public_key():
    with open("public.key", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    numbers = public_key.public_numbers()
    return numbers.e, numbers.n


def factor_n_verbose(n):
    print("[*] Starting naive factorization of n...")
    for i in range(2, n):
        print(f"    [-] Trying i = {i} ... ", end="")
        if n % i == 0:
            print("SUCCESS")
            return i, n // i
        else:
            print("not a factor")
    raise ValueError("Failed to factor n")


def modinv_verbose(e, phi):
    print("[*] Searching for modular inverse d such that (e * d) mod φ(n) = 1")
    for d in range(1, phi):
        print(f"    [-] Trying d = {d} ... ", end="")
        if (e * d) % phi == 1:
            print("FOUND")
            return d
        else:
            print("no")
    raise ValueError("No modular inverse found")


def decrypt_file(enc_file, d, n):
    output_file = enc_file[:-4] if enc_file.endswith(".enc") else enc_file + ".dec"

    with open(enc_file, "r") as f:
        encrypted_numbers = f.read().split()

    decrypted_chars = []

    print("[*] Decrypting file using recovered private key...")
    for c in encrypted_numbers:
        m = pow(int(c), d, n)
        decrypted_chars.append(chr(m))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("".join(decrypted_chars))

    print(f"[+] Decrypted file written to: {output_file}")


def save_cracked_private_key(p, q, e, d, n):
    print("[*] Reconstructing real PKCS#1 private key...")

    dp = d % (p - 1)
    dq = d % (q - 1)
    qi = pow(q, -1, p)

    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dp,
        dmq1=dq,
        iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )

    private_key = private_numbers.private_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open("cracked_private.key", "wb") as f:
        f.write(pem)

    print("[!] Cracked private key saved to: cracked_private.key")


def main():
    print("=== TOY RSA CRACK DEMO ===")

    e, n = load_public_key()
    print(f"[+] Loaded public key: e={e}, n={n}")

    enc_file = input("Enter encrypted file name (e.g. message.txt.enc): ")

    # Step 1: Factor n
    p, q = factor_n_verbose(n)
    print(f"[+] Found factors: p={p}, q={q}")

    # Step 2: Compute φ(n)
    phi = (p - 1) * (q - 1)
    print(f"[+] Computed φ(n) = {phi}")

    # Step 3: Recover private key
    d = modinv_verbose(e, phi)
    print(f"[+] Recovered private key exponent d={d}")

    # Step 4: Save real PEM private key
    save_cracked_private_key(p, q, e, d, n)

    # Step 5: Decrypt file
    decrypt_file(enc_file, d, n)

    print("\n[!] RSA successfully broken — small keys are insecure.")


if __name__ == "__main__":
    main()

