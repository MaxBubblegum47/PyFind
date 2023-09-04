#######################
# iPhone Activity     #
#######################
from lib.utils import *

print("""
 ██████╗ ██╗   ██╗███████╗██╗███╗   ██╗██████╗ 
 ██╔══██╗╚██╗ ██╔╝██╔════╝██║████╗  ██║██╔══██╗
 ██████╔╝ ╚████╔╝ █████╗  ██║██╔██╗ ██║██║  ██║
 ██╔═══╝   ╚██╔╝  ██╔══╝  ██║██║╚██╗██║██║  ██║
 ██║        ██║   ██║     ██║██║ ╚████║██████╔╝
 ╚═╝        ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝      
        """)

print(" Generating beacon key with NISP P-224 curve pair on my iPhone. Here's my key:")

# choosing the curve and generate beacon key
curve = registry.get_curve('secp224r1')

iPhonePrivKey = secrets.randbelow(curve.field.n)
iPhonePubKey = iPhonePrivKey * curve.g
print("\n 1. iPhone public key:", compress(iPhonePubKey))
print(" 2. iPhone private key:", iPhonePrivKey)

import secrets
iPhoneSymmKey = secrets.token_hex(32)
iPhoneSymmKey = str.encode(iPhoneSymmKey)

print(" 3. iPhone symmetric key: ", iPhoneSymmKey)

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

print("\n Forging the first advertisment key: ", compress(Pi))

##################
# Finder DEVICE #
##################

print("\n iPhone get lost :( ...\n but someone close to my iPhone could help me!")
print(" Finder's iPhone performs ECDH with mine:")

# ECDH with lost device using the Pi as generator
curve = registry.get_curve('secp224r1')

FinderPrivKey = secrets.randbelow(curve.field.n)
FinderPubKey = FinderPrivKey * Pi
print("\n 1. Finder public key:", compress(FinderPubKey))

iPhonePubKey2 = iPhonePrivKey * Pi
print(" 2. iPhone Device2 public key:", compress(iPhonePubKey2))

FinderSharedKey = FinderPrivKey * iPhonePubKey2
print(" 3. Finder shared key:", compress(FinderSharedKey))

iPhoneSharedKey = iPhonePrivKey * FinderPubKey
print(" 4. iPhone shared key:", compress(iPhoneSharedKey))

print("\n Check both of the phones share the same shared secret:", FinderSharedKey == iPhoneSharedKey)

# X963 to derive another key of 32 bytes
xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo = bytes(compress(Pi), 'ISO-8859-1')
)

# split this 32 bytes key into 16 bytes of e' and 16 bytes IV and use it with AES-GCM algorithm to cipher some metadata
AES_GCM_KEY_TO_SPLIT = xkdf.derive(bytes(compress(FinderSharedKey), 'ISO-8859-1'))
e = AES_GCM_KEY_TO_SPLIT[:16]
IV = AES_GCM_KEY_TO_SPLIT[16:32]

outputFormat = "{:<25}:{}"
secret_key = str(e)
plain_text = "Your_plain_text"

print("\n Finder's iPhone send an ecnrypted location report to iCloud using AES-GCM Encryption") 
cipher_text = encrypt(secret_key, plain_text, IV)
print(outputFormat.format("\n Encryption input: ", plain_text))
print(outputFormat.format(" Encryption output: ", cipher_text))

import hashlib

hashed_pi_finder = hashlib.sha256(compress(Pi).encode('ISO-8859-1')).hexdigest()
print("\n The advertisement key of my iPhone is hashed for iCloud : ", hashed_pi_finder)

##########
# OWNER  #
##########
print("\n I ask iCloud if is possible to find my missing device... maybe there are some reports for me! I'm using the hash my iPhone advertisement key to look for something")
hashed_pi_cached = hashlib.sha256(compress(Pi).encode('ISO-8859-1')).hexdigest()

print(" There's something! Now it is time to download and decrypt the right report...")

final_key = FinderPubKey * iPhonePrivKey

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

print(outputFormat.format("\n Encrypted location report: ", cipher_text))
print(outputFormat.format(" Decrypted location report: ", decrypted_text))