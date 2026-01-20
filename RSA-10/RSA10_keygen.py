# RSA_keygen.py — TOY RSA KEYGEN
# EDUCATIONAL ONLY — KEYS ARE INTENTIONALLY SMALL AND INSECURE

from math import gcd
import random

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_small_prime(start=10, end=50):
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p


def modinv(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
    raise Exception("No modular inverse found")


def main():
    print("=== TOY RSA KEY GENERATION ===")

    # Step 1: Generate toy primes
    p = generate_small_prime()
    q = generate_small_prime()
    while p == q:
        q = generate_small_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    # Step 2: Choose public exponent
    e = 3
    while gcd(e, phi) != 1:
        e += 2

    # Step 3: Compute private exponent
    d = modinv(e, phi)

    # Step 4: Compute CRT parameters (REQUIRED for PKCS#1)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qi = pow(q, -1, p)  # q inverse mod p

    # Step 5: Build REAL RSA private key object
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

    # Step 6: Serialize PRIVATE key (PKCS#1 PEM)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open("private.key", "wb") as f:
        f.write(private_pem)

    # Step 7: Serialize PUBLIC key (X.509 PEM)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open("public.key", "wb") as f:
        f.write(public_pem)

    print("[+] RSA key pair generated")
    print("[i] Public key:  public.key (PEM, X.509)")
    print("[i] Private key: private.key (PEM, PKCS#1)")
    print(f"[!] Toy parameters: p={p}, q={q}, n={n}, e={e}, d={d}")
    print("[!] KEYS ARE INTENTIONALLY INSECURE — EDUCATIONAL USE ONLY")


if __name__ == "__main__":
    main()

