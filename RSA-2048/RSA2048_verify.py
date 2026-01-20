# RSA_verify.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

def load_public_key(public_key_path):
    with open(public_key_path, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

def verify_signature(file_path, sig_path, public_key):
    with open(file_path, "rb") as f:
        data = f.read()

    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def main():
    public_key_path = input("Enter public key file path: ")
    file_path = input("Enter original file path: ")
    sig_path = input("Enter signature file path (.sig): ")

    public_key = load_public_key(public_key_path)
    valid = verify_signature(file_path, sig_path, public_key)

    if valid:
        print("Signature is VALID. File is authentic and unchanged.")
    else:
        print("Signature is INVALID. File was altered or signature is fake.")

if __name__ == "__main__":
    main()

