# RSA_sign.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def load_private_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def sign_file(file_path, private_key):
    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def main():
    private_key_path = input("Enter private key file path: ")
    file_path = input("Enter file to sign: ")

    private_key = load_private_key(private_key_path)
    signature = sign_file(file_path, private_key)

    sig_file = file_path + ".sig"
    with open(sig_file, "wb") as f:
        f.write(signature)

    print(f"Signature saved as: {sig_file}")

if __name__ == "__main__":
    main()

