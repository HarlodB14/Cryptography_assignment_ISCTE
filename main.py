import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def main():
    # Step 1: Gateway generates its keys and certificate
    print("Gateway: Generating keys and certificate...")
    gateway_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gateway_public_key = gateway_private_key.public_key()

    # Simulate Gateway's self-signed certificate as public key
    gateway_certificate = gateway_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Gateway: Certificate generated and ready to be sent.")

    # Step 2: Entity A generates its keys and sends encrypted data
    print("Entity A: Generating keys...")
    A_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    A_public_key = A_private_key.public_key()

    print("Entity A: Preparing data to send to Gateway...")
    ID_A = b"Entity_A"  # Entity A's identity
    nonce_A = os.urandom(16)  # Random nonce for verification
    symmetric_key = os.urandom(32)  # 256-bit AES symmetric key

    # Encrypt symmetric key with Gateway's public key
    print("Entity A: Encrypting symmetric key with Gateway's public key...")
    encrypted_symmetric_key = gateway_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encrypt remaining data (ID_A + nonce_A) using AES
    print("Entity A: Encrypting ID and nonce with the symmetric key...")
    iv = os.urandom(16)  # Generate and store the IV
    aes_cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))  # CFB mode with generated IV
    encryptor = aes_cipher.encryptor()
    encrypted_data = encryptor.update(ID_A + nonce_A) + encryptor.finalize()

    # Step 3: Gateway decrypts symmetric key and data
    print("Gateway: Decrypting symmetric key...")
    decrypted_symmetric_key = gateway_private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Gateway: Decrypting ID and nonce...")
    aes_cipher = Cipher(algorithms.AES(decrypted_symmetric_key), modes.CFB(iv))  # Reuse the same IV
    decryptor = aes_cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Parse decrypted data
    received_ID_A = decrypted_data[:len(ID_A)]
    received_nonce_A = decrypted_data[len(ID_A):]

    if received_ID_A == ID_A and received_nonce_A == nonce_A:
        print("Gateway: Identity and Nonce verified successfully!")
    else:
        print("Gateway: Verification failed!")
        return

    # Step 4: Gateway generates session key and encrypts with A's public key
    print("Gateway: Generating session key...")
    session_key = os.urandom(32)  # 256-bit symmetric session key

    print("Gateway: Encrypting session key with Entity A's public key...")
    encrypted_session_key = A_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 5: Entity A decrypts the session key
    print("Entity A: Decrypting the session key...")
    decrypted_session_key = A_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    if decrypted_session_key == session_key:
        print("Entity A: Session Key exchange successful!")
        print("Session Key:", session_key.hex())
    else:
        print("Entity A: Session Key exchange failed!")


if __name__ == "__main__":
    main()
