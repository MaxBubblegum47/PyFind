from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Generate a private key for use in the exchange.
private_key = ec.generate_private_key(
    ec.SECP384R1()
)
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key
# and get a public key from that.
peer_public_key = ec.generate_private_key(
    ec.SECP384R1()
).public_key()
shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)
# For the next handshake we MUST generate another private key.
private_key_2 = ec.generate_private_key(
    ec.SECP384R1()
)
peer_public_key_2 = ec.generate_private_key(
    ec.SECP384R1()
).public_key()
shared_key_2 = private_key_2.exchange(ec.ECDH(), peer_public_key_2)
derived_key_2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key_2)