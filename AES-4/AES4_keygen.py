# AES_keygen.py — TOY AES-4 KEY GENERATOR (EDUCATIONAL ONLY)

import random

def main():
    key = random.randint(0, 15)  # 4-bit key

    with open("aes.key", "w") as f:
        f.write(str(key))

    print(f"ToyAES-4 key generated: {key}")
    print("(Key size: 4 bits — 16 possible keys)")

if __name__ == "__main__":
    main()

