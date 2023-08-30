###############
# LOST DEVICE #
###############

from tinyec import registry
import secrets

# STEP 1: compute ECDH

'''Forse ho capito: in questa prima fase praticamente Alice sarebbe come se fosse il telefono smarrito
e io Bob, cioe' il proprietario. Ci stiamo scambiando un segreto comune che poi mi serviera' per andare
a decifrare il contenuto cifrato di iCloud'''

# the idea is that (from Pratical Cryptography for Developers by Svetlin Nakov, seems possible to zip the two coordinates of a point in one single hex number)
def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

print("Pairing between my iPhone and Lost Device...")

# choosing the curve
curve = registry.get_curve('secp224r1')

iPhonePrivKey = secrets.randbelow(curve.field.n)
iPhonePubKey = iPhonePrivKey * curve.g
print("iPhone public key:", compress(iPhonePubKey))
print("iPhone public key without compress:", iPhonePubKey)

LostDevicePrivKey = secrets.randbelow(curve.field.n)
LostDevicePubKey = LostDevicePrivKey * curve.g
print("Lost Device public key:", compress(LostDevicePubKey))

print("Now exchange the public keys Apple *Magic* Bluethoot")

iPhoneSharedKey = iPhonePrivKey * LostDevicePubKey
print("iPhone shared key:", compress(iPhoneSharedKey))

LostDeviceSharedKey = LostDevicePrivKey * iPhonePubKey
print("Lost Device shared key:", compress(LostDeviceSharedKey))

print("Check if the iPhone and the Lost Device shared the same shared key:", iPhoneSharedKey == LostDeviceSharedKey)

# STEP 2: compute X963KDF to generate AdvKey (advertisement key to send over BLE) on the Lost Device
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

# this scheme seems really redundant but I have taken it from documentation
sharedinfo = bytes(compress(LostDeviceSharedKey), 'ISO-8859-1')

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo=sharedinfo,
)

AdvKey = xkdf.derive(bytes(compress(iPhoneSharedKey), 'ISO-8859-1'))

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo=sharedinfo,
)

xkdf.verify(bytes(compress(iPhoneSharedKey), 'ISO-8859-1'), AdvKey)

print('Advertisement key: ')

import codecs

output = AdvKey.decode('ISO-8859-1') # this is encoding is given from documentation

print(output)

##################
# FOUNDER DEVICE #
##################

print("Communication between Founder and Lost Device...")

FounderPrivKey = secrets.randbelow(curve.field.n)

""" print("PRIVATO")
print(type(AdvKey))
print(type(FounderPrivKey)) """

# froom what I have understood, basically we are using the advertisement key as a generator(?)

FounderPubKey = FounderPrivKey * int.from_bytes(AdvKey, "big")
print("Founder public key:", FounderPubKey)

LostDevicePrivKey2 = secrets.randbelow(curve.field.n)
LostDevicePubKey2 = LostDevicePrivKey2 * int.from_bytes(AdvKey, "big")
print("Lost Device public key:", LostDevicePubKey2)

print("Now exchange the public keys Apple *Magic* Bluethoot")

FounderSharedKey = FounderPrivKey * LostDevicePubKey2
print("Founder shared key:", FounderSharedKey)

LostDeviceSharedKey2 = LostDevicePrivKey2 * FounderPubKey
print("Lost Device shared key:", LostDeviceSharedKey2)
print(type(LostDeviceSharedKey2))

print("Check if the Founder and the Lost Device shared the same shared key:", FounderSharedKey == LostDeviceSharedKey2)

# this part is the on described in the paper like: Derive a symmetric key with ANSI X.963 KDF on th shared secret with the advertised public key as entropy
# and SHA-256 as the hash function. This is pretty similar to what we have done before. Maybe is time to create some functions and a proper main...


sharedinfo = AdvKey

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo=sharedinfo,
)

iCloudKey = xkdf.derive(bytes(str(LostDeviceSharedKey2), 'ISO-8859-1'))

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo=sharedinfo,
)

xkdf.verify(bytes(str(LostDeviceSharedKey2), 'ISO-8859-1'), iCloudKey)

print('iCloudKey key: ')

import codecs

output = iCloudKey.decode('ISO-8859-1') # this is encoding is given from documentation

print(output)

# a questo punto dovrei provare ad usare questa chiave per andare a cifrare qualcosa e dovrei essere in grado
# teoricamente di andarlo a decifrare

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = iCloudKey
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()

# non capisco esattamente una cosa: decryptor assume già che io stia usando la stessa chiave, ma se volessi andare a 
# fare un test a riguardo?? Forse dovrei cercare qualcosa che abbia a che fare con la key derivation
decryptor = cipher.decryptor()
print(decryptor.update(ct) + decryptor.finalize())
