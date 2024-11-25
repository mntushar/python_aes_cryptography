import os
import base64
from urllib.parse import quote
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class AesCryptography:
    def encrypt(self, text, password):
        try:
            # Generate the key using SHA256
            key = self.__generate_key(password)

            # Generate a random IV for each encryption
            iv = os.urandom(16)  # AES block size is 16 bytes

            # Encrypt the text
            encrypted = self.__encrypt_string_to_bytes(text, key, iv)

            # Prepend the IV to the encrypted text and then base64 encode it for easy transfer
            encrypted_with_iv = iv + encrypted
            return quote(base64.b64encode(encrypted_with_iv).decode('utf-8'))  # Directly return the base64 string
        except Exception as ex:
            raise Exception(str(ex))

    def decrypt(self, encrypted_text, password):
        try:
            # Decode the base64-encoded string
            encrypted_with_iv = base64.b64decode(encrypted_text)

            # Extract the IV (first 16 bytes)
            iv = encrypted_with_iv[:16]

            # Extract the actual encrypted data
            encrypted_data = encrypted_with_iv[16:]

            # Generate the key using SHA256
            key = self.__generate_key(password)

            # Decrypt the text
            decrypted_text = self.__decrypt_string_from_bytes(encrypted_data, key, iv)

            return decrypted_text
        except Exception as ex:
            raise Exception(str(ex))

    def __generate_key(self, password):
        # Generate a SHA256 hash of the password to create a key
        return sha256(password.encode('utf-8')).digest()

    def __encrypt_string_to_bytes(self, plain_text, key, iv):
        if not plain_text:
            raise ValueError("plain_text cannot be null or empty.")
        if not key or len(key) <= 0:
            raise ValueError("key cannot be null or empty.")
        if not iv or len(iv) <= 0:
            raise ValueError("iv cannot be null or empty.")

        # Create AES cipher object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Apply padding to the plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()

        # Encrypt the padded plaintext
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted

    def __decrypt_string_from_bytes(self, cipher_text, key, iv):
        if not cipher_text:
            raise ValueError("cipher_text cannot be null or empty.")
        if not key or len(key) <= 0:
            raise ValueError("key cannot be null or empty.")
        if not iv or len(iv) <= 0:
            raise ValueError("iv cannot be null or empty.")

        # Create AES cipher object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_text = unpadder.update(decrypted_data) + unpadder.finalize()

        return decrypted_text.decode('utf-8')

