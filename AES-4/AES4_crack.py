# AES_crack.py — TOY AES-4 BRUTE FORCE DEMO (EDUCATIONAL ONLY)

def decrypt_byte(byte, key):
    return byte ^ key

def main():
    print("=== TOY AES-4 CRACK DEMO ===")
    print("Key space: 16 keys (0–15)\n")

    enc_file = input("Enter encrypted file name (e.g. message.txt.enc): ")

    if not enc_file.endswith(".enc"):
        raise ValueError("Encrypted file must end with .enc")

    with open(enc_file, "rb") as f:
        ciphertext = f.read()

    for key in range(16):
        plaintext = bytearray(decrypt_byte(b, key) for b in ciphertext)

        preview = plaintext.decode(errors="replace")

        print(f"[KEY {key:02d}] Preview:")
        print("--------------------------------")
        print(preview)
        print("--------------------------------")

        choice = input("Does this look correct? (y/n/q): ").lower()

        if choice == "y":
            output_file = enc_file[:-4]
            with open(output_file, "wb") as f:
                f.write(plaintext)

            print(f"\n[+] Correct key found: {key}")
            print(f"[+] File restored → {output_file}")
            print("[!] ToyAES-4 successfully broken.")
            return

        if choice == "q":
            print("[!] Cracking aborted.")
            return

    print("[!] All keys tried. Attack complete.")

if __name__ == "__main__":
    main()

