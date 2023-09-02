from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Generate a private key for use in the exchange.
server_private_key = ec.generate_private_key(
    ec.SECP384R1()
)

# In a real handshake the peer is a remote client. For this
# example we'll generate another local private key though.
peer_private_key = ec.generate_private_key(
    ec.SECP384R1()
)

shared_key = server_private_key.exchange(
    ec.ECDH(), peer_private_key.public_key())

# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

# And now we can demonstrate that the handshake performed in the
# opposite direction gives the same final value
same_shared_key = peer_private_key.exchange(
    ec.ECDH(), server_private_key.public_key())

# Perform key derivation.
same_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(same_shared_key)

print(derived_key == same_derived_key)