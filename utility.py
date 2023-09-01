# all needed function to make the two version of the Demo works properly

import base64
import hashlib
from Cryptodome.Cipher import AES  # from pycryptodomex v-3.10.4
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

HASH_NAME = "SHA512"
IV_LENGTH = 16
ITERATION_COUNT = 65535
KEY_LENGTH = 16
SALT_LENGTH = 16
TAG_LENGTH = 16


def encrypt(password, plain_message, IV):
    salt = get_random_bytes(SALT_LENGTH) 
    iv = IV

    secret = get_secret_key(password, salt)

    cipher = AES.new(secret, AES.MODE_GCM, iv)

    encrypted_message_byte, tag = cipher.encrypt_and_digest(
        plain_message.encode("utf-8")
    )
    cipher_byte = salt + iv + encrypted_message_byte + tag

    encoded_cipher_byte = base64.b64encode(cipher_byte)
    return bytes.decode(encoded_cipher_byte)


def get_secret_key(password, salt):
    return hashlib.pbkdf2_hmac(
        HASH_NAME, password.encode(), salt, ITERATION_COUNT, KEY_LENGTH
    )

def decrypt(password, cipher_message, IV):
    decoded_cipher_byte = base64.b64decode(cipher_message)

    salt = decoded_cipher_byte[:SALT_LENGTH]
    iv = IV
    encrypted_message_byte = decoded_cipher_byte[
        (IV_LENGTH + SALT_LENGTH) : -TAG_LENGTH
    ]
    tag = decoded_cipher_byte[-TAG_LENGTH:]
    secret = get_secret_key(password, salt)
    cipher = AES.new(secret, AES.MODE_GCM, iv)

    decrypted_message_byte = cipher.decrypt_and_verify(encrypted_message_byte, tag)
    return decrypted_message_byte.decode("utf-8")

