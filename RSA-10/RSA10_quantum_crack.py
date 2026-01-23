# RSA_quantum_crack.py — Educational Shor Simulation for Toy RSA Breaking
# EDUCATIONAL PURPOSES ONLY — INTENTIONALLY INSECURE

from math import gcd
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import random

# Load the small RSA public key
def load_public_key():
    # Prompt the user for the public key file path
    key_file = input("Enter the public key filename (e.g., public.key): ").strip()

    # Try to open and load the key
    try:
        with open(key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print(f"[!] File not found: {key_file}")
        return load_public_key()  # ask again
    except Exception as e:
        print(f"[!] Unable to load public key: {e}")
        return load_public_key()  # ask again

    # Extract and return (e, n)
    numbers = public_key.public_numbers()
    return numbers.e, numbers.n

# Simulated quantum period finding (classical slow fallback)
def quantum_order_finding_simulated(a, n):
    """
    In real Shor's this is the quantum step using QFT.
    Here we simulate by brute force classical order finding.
    """
    print(f"[*] Simulating quantum order finding for a = {a} mod n = {n} ...")
    r = 1
    while pow(a, r, n) != 1:
        r += 1
    print(f"[+] Simulated period r = {r}")
    return r

# Shor's step that uses order to factor n
def shors_factor(n):
    """
    Attempt to find nontrivial factors using Shor's logic.
    """
    while True:
        a = random.randrange(2, n - 1)
        if gcd(a, n) != 1:
            print(f"[!] Found trivial factor gcd({a}, {n}) = {gcd(a, n)}")
            return gcd(a, n), n // gcd(a, n)

        r = quantum_order_finding_simulated(a, n)

        if r % 2 != 0:
            print("[!] r is odd, retrying ...")
            continue

        x = pow(a, r // 2, n)
        if x == n - 1:
            print("[!] x == -1 mod n, retrying ...")
            continue

        p = gcd(x - 1, n)
        q = gcd(x + 1, n)
        if p > 1 and q > 1:
            print(f"[+] Shor simulated success: p = {p}, q = {q}")
            return p, q

# Compute private exponent once factors are known
def modinv(e, phi):
    # Extended Euclid is fine here
    def egcd(a, b):
        if b == 0:
            return (1, 0, a)
        x, y, d = egcd(b, a % b)
        return (y, x - (a // b) * y, d)

    x, y, d = egcd(e, phi)
    if d != 1:
        return None
    return x % phi

# Build and save private key
def save_private_key(p, q, e, d, n):
    dp, dq = d % (p - 1), d % (q - 1)
    qi = pow(q, -1, p)
    private_nums = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    private_key = private_nums.private_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open("shor_cracked_private.key", "wb") as f:
        f.write(pem)
    print("[+] Simulated cracked private key saved.")

# Main flow 
def main():
    print("=== SHOR QUANTUM SIM DEMO ===")
    e, n = load_public_key()
    print(f"[+] Loaded public key: e={e}, n={n}")

    # Shor simulated factorization
    p, q = shors_factor(n)
    print(f"[+] Recovered factors: p={p}, q={q}")

    phi = (p - 1) * (q - 1)
    print(f"[+] Phi(n) = {phi}")

    d = modinv(e, phi)
    print(f"[+] Computed private exponent d = {d}")

    save_private_key(p, q, e, d, n)

    print("\n[!] Simulation complete — toy RSA key broken by Shor logic.")

if __name__ == "__main__":
    main()

