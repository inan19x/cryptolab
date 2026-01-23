# RSA_crack.py — TOY RSA BREAKER
# EDUCATIONAL PURPOSES ONLY — INTENTIONALLY INSECURE

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import time

# ------------------------------------------------------------
# Step 1: Factor n = p * q
# ------------------------------------------------------------
def factor_n(n):
    """
    VERY naive factorization with visible effort.
    Pauses every iteration for teaching purposes.
    """
    print("[*] Starting naive factorization of n...")
    iterations = 0

    for i in range(2, n):
        iterations += 1
        print(f"    Attempt {iterations}: testing divisor i = {i}")
        time.sleep(0.2)

        if n % i == 0:
            print(f"\n[+] Factor found after {iterations} attempts!")
            print(f"    n % {i} == 0")
            return i, n // i

    print(f"[-] No factors found after {iterations} attempts")
    return None, None


# ------------------------------------------------------------
# Step 2: Find modular inverse d such that:
#   d * e ≡ 1 (mod φ(n))
# ------------------------------------------------------------
def modinv(e, phi):
    """
    Brute-force modular inverse with visible iteration.
    Pauses every attempt for teaching purposes.
    """
    print("[*] Searching for modular inverse d...")
    print("    Trying values of d such that (d * e) mod φ(n) == 1\n")

    for d in range(1, phi):
        result = (d * e) % phi
        print(f"    Attempt d = {d}: ({d} * {e}) mod {phi} = {result}")
        time.sleep(0.1)

        if result == 1:
            print(f"\n[+] Success! Modular inverse found.")
            print(f"    d = {d}")
            return d

    print("[-] No modular inverse found")
    return None


# ------------------------------------------------------------
# MAIN PROGRAM
# ------------------------------------------------------------
print("=== RSA-10 bit Key Cracker ===")

# ---- Load public key ----
pubkey_file = input("Enter public key file name (e.g., public.key): ")

with open(pubkey_file, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Extract RSA public numbers
numbers = public_key.public_numbers()
n = numbers.n
e = numbers.e

print("\n[+] Public key successfully loaded")
print(f"    Modulus (n)  = {n}")
print(f"    Exponent (e)= {e}")

# ---- Factor n ----
print("\n=== STEP 1: Factoring n ===")
p, q = factor_n(n)

if not p:
    print("[-] Could not factor n")
    print("    (This usually means n is too large)")
    exit(1)

print(f"[+] Prime factors recovered:")
print(f"    p = {p}")
print(f"    q = {q}")
time.sleep(1)

# ---- Compute φ(n) ----
print("\n=== STEP 2: Computing Euler's Totient φ(n) ===")
phi = (p - 1) * (q - 1)

print("φ(n) = (p - 1) * (q - 1)")
print(f"φ(n) = ({p} - 1) * ({q} - 1)")
print(f"φ(n) = {phi}")

# ---- Compute d ----
print("\n=== STEP 3: Recovering Private Exponent d ===")
print("We need d such that:")
print("    d * e ≡ 1 (mod φ(n))")

d = modinv(e, phi)

if not d:
    print("[-] Failed to compute d")
    exit(1)

print("\n[+] Private exponent successfully recovered")
print(f"    d = {d}")
time.sleep(1)

# ---- Reconstruct private key ----
print("\n=== STEP 4: Reconstructing RSA Private Key ===")

private_numbers = rsa.RSAPrivateNumbers(
    p=p,
    q=q,
    d=d,
    dmp1=d % (p - 1),
    dmq1=d % (q - 1),
    iqmp=pow(q, -1, p),
    public_numbers=rsa.RSAPublicNumbers(e, n)
)

private_key = private_numbers.private_key()
time.sleep(2)
print("[+] RSA private key object created")

# ---- Serialize and save key ----
print("\n=== STEP 5: Saving Private Key to Disk ===")

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

with open("cracked_private.key", "wb") as f:
    f.write(pem)

print("[+] Private key written to: cracked_private.key")
print("\n=== DONE ===")

