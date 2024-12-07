import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding  # Correct padding import for RSA
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import padding as sym_padding


# Function to load the server's public key
def load_public_key():
    try:
        with open("server_public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None


# Function to generate an RSA key pair
def generate_rsa_keys():
    if not os.path.exists("private_key.pem") or not os.path.exists("client_public_key.pem"):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        with open("private_key.pem", "wb") as private_key_file:
            private_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        public_key = private_key.public_key()
        with open("client_public_key.pem", "wb") as public_key_file:
            public_key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("Client public and private keys have been generated.")


# Load client's private key
def load_private_key():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key


# Function to encrypt the message using AES with PKCS7 padding
def encrypt_message(session_key, message):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # 16 bytes for AES block size

    # Apply PKCS7 padding to the message to ensure it is a multiple of the block size (16 bytes for AES)
    padder = sym_padding.PKCS7(128).padder()  # 128 bits = 16 bytes for AES block size
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()

    # Encrypt the padded message using AES in CBC mode
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Prepend the IV to the ciphertext (needed for decryption)
    return iv + ciphertext


# Client main function
def main():
    # Generate RSA keys if they don't exist
    generate_rsa_keys()

    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))

    # Load server's public key
    server_public_key = load_public_key()

    if server_public_key is None:
        print("Server public key not loaded. Exiting...")
        return

    # Load client's private key
    private_key = load_private_key()

    # Encrypt session key using server's public key
    session_key = os.urandom(32)  # Generate a random session key

    encrypted_session_key = server_public_key.encrypt(
        session_key,
        padding.OAEP(  # Correct import for RSA padding
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send the public key and encrypted session key to the server
    client_socket.send(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    client_socket.send(encrypted_session_key)
    print("Client sent encrypted session key.")

    # Encrypt a message using the session key
    message = "This is a secure message."
    encrypted_message = encrypt_message(session_key, message)

    client_socket.send(encrypted_message)
    print("Client sent encrypted message.")

    # Close the connection
    client_socket.close()


if __name__ == "__main__":
    main()
