import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# Function to generate and save RSA keys if they don't exist
def generate_rsa_keys():
    if not os.path.exists("private_key.pem") or not os.path.exists("server_public_key.pem"):
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Save the private key to a file
        with open("private_key.pem", "wb") as private_key_file:
            private_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Generate the public key from the private key
        public_key = private_key.public_key()

        # Save the public key to a file
        with open("server_public_key.pem", "wb") as public_key_file:
            public_key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("Server public and private keys have been generated.")


# Call the function to generate keys if necessary
generate_rsa_keys()


# Function to load the private key
def load_private_key():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key


# Function to decrypt the session key
def decrypt_session_key(encrypted_session_key, private_key):
    return private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# Function to handle client connections
def handle_client_connection(client_socket):
    # Load the private key for decryption
    private_key = load_private_key()

    try:
        # Receive the client's public key
        client_public_key = client_socket.recv(1024).decode('utf-8')
        print(f"Server received client public key: {client_public_key}")

        # Receive the encrypted session key
        encrypted_session_key = client_socket.recv(1024)
        print(f"Server received encrypted session key: {encrypted_session_key}")

        # Decrypt the session key using the server's private key
        session_key = decrypt_session_key(encrypted_session_key, private_key)
        print(f"Server decrypted session key: {session_key}")

        # Receive the encrypted message
        encrypted_message = client_socket.recv(1024)
        print(f"Server received encrypted message: {encrypted_message}")

        # Decrypt the message using the session key (AES)
        iv = encrypted_message[:16]  # Assuming the IV is prepended to the encrypted message
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
        print(f"Decrypted message: {decrypted_message.decode('utf-8')}")

    except Exception as e:
        print(f"Error during communication: {e}")
    finally:
        client_socket.close()


# Setting up the server
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))  # Bind to any IP address
    server_socket.listen(5)
    print("Server listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection established with {addr}")
        handle_client_connection(client_socket)


if __name__ == "__main__":
    main()
