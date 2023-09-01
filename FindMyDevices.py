#######################
# iPhone Activity     #
#######################

import os
import secrets
from utility import *
from tinyec import registry
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

print("Generating beacon key pair on my iPhone...")

# choosing the curve and generate beacon key
curve = registry.get_curve('secp224r1')

iPhonePrivKey = secrets.randbelow(curve.field.n)
iPhonePubKey = iPhonePrivKey * curve.g
print("iPhone public key:", compress(iPhonePubKey))
print("iPhone private key:", iPhonePrivKey)

import secrets
iPhoneSymmKey = secrets.token_hex(32)
iPhoneSymmKey = str.encode(iPhoneSymmKey)

print("iPhone symmetric key: ", iPhoneSymmKey)

########################
# LOST iPhone ACTIVITY #
########################

# SKi = KDF(SKi-1, update, 32)
xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo = b""
)

SKi = xkdf.derive(iPhoneSymmKey)

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo=b""
)

xkdf.verify(iPhoneSymmKey, SKi)

# (ui, vi) = KDF(SKi, diversify, 72)
xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=72,
    sharedinfo = b""
)

res = xkdf.derive(SKi)
Ui = res[:36]
Vi = res[36:72]

# converting to int in order to perform better operation
Ui_int_val = int.from_bytes(Ui, "big")
Vi_int_val = int.from_bytes(Vi, "big")

# di = (d0 * ui) + vi
iPhoneSymmKey_int = int.from_bytes(iPhoneSymmKey, "big")
Di = (iPhoneSymmKey_int * Ui_int_val) + Vi_int_val

# pi = di * G
Pi = Di * curve.g

print("Advertisement key of the Lost Device: " + compress(Pi))

##################
# FOUNDER DEVICE #
##################

# ECDH with lost device using the Pi as generator
curve = registry.get_curve('secp224r1')
print("-----------------------------------------------------\nPairing between my lost iPhone and Founder Device...")

FounderPrivKey = secrets.randbelow(curve.field.n)
FounderPubKey = FounderPrivKey * Pi
print("Founder public key:", compress(FounderPubKey))

iPhonePubKey2 = iPhonePrivKey * Pi
print("iPhone Device2 public key:", compress(iPhonePubKey2))

FounderSharedKey = FounderPrivKey * iPhonePubKey2
print("Founder shared key:", compress(FounderSharedKey))

iPhoneSharedKey = iPhonePrivKey * FounderPubKey
print("iPhone shared key:", compress(iPhoneSharedKey))

print("Check if the iPhone and the Lost Device shared the same shared key:", FounderSharedKey == iPhoneSharedKey)

# X963 to derive another key of 32 bytes
xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo = bytes(compress(Pi), 'ISO-8859-1')
)

# split this 32 bytes key into 16 bytes of e' and 16 bytes IV and use it with AES-GCM algorithm to cipher some metadata
AES_GCM_KEY_TO_SPLIT = xkdf.derive(bytes(compress(FounderSharedKey), 'ISO-8859-1'))
e = AES_GCM_KEY_TO_SPLIT[:16]
IV = AES_GCM_KEY_TO_SPLIT[16:32]

outputFormat = "{:<25}:{}"
secret_key = str(e)
plain_text = "Your_plain_text"

print("AES-GCM Encryption...") 
cipher_text = encrypt(secret_key, plain_text, IV)
print(outputFormat.format("Encryption input: ", plain_text))
print(outputFormat.format("Encryption output: ", cipher_text))


##########
# OWNER  #
##########
print("-----------------------------------------------------\nRetriving metadata from founder's upload on iCloud...")

final_key = FounderPubKey * iPhonePrivKey

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo = bytes(compress(Pi), 'ISO-8859-1')
)

final_key_TO_SPLIT = xkdf.derive(bytes(compress(final_key), 'ISO-8859-1'))
e2 = final_key_TO_SPLIT[:16]
IV2 = final_key_TO_SPLIT[16:32]

secret_key = str(e2)
decrypted_text = decrypt(secret_key, cipher_text, IV2)

print("AES-GCM Decryption...")
print(outputFormat.format("Decryption input: ", cipher_text))
print(outputFormat.format("Decryption output: ", decrypted_text))