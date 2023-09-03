#######################
# PAIRING WITH AIRTAG #
#######################

from lib.utils import *
import secrets

# STEP 1: compute ECDH with the AirTag
print("Pairing between my iPhone and Lost Device...")

# choosing the curve
curve = registry.get_curve('secp224r1')

iPhonePrivKey = secrets.randbelow(curve.field.n)
iPhonePubKey = iPhonePrivKey * curve.g
print("iPhone public key:", compress(iPhonePubKey))

LostDevicePrivKey = secrets.randbelow(curve.field.n)
LostDevicePubKey = LostDevicePrivKey * curve.g
print("Lost Device public key:", compress(LostDevicePubKey))

print("Now exchange the public keys Apple *Magic* Bluetooth")

iPhoneSharedKey = iPhonePrivKey * LostDevicePubKey
print("iPhone shared key:", compress(iPhoneSharedKey))

LostDeviceSharedKey = LostDevicePrivKey * iPhonePubKey
print("Lost Device shared key:", compress(LostDeviceSharedKey))

print("Check if the iPhone and the Lost Device shared the same shared key:", iPhoneSharedKey == LostDeviceSharedKey)

print("Lunghezza prima chiave SKi: ")
print(len(bytes(compress(LostDeviceSharedKey), 'ISO-8859-1')))

########################
# LOST DEVICE ACTIVITY #
########################
# algorithm steps
# 1. SKi = KDF(SKi-1, update, 32)
# 2. (ui, vi) = KDF(SKi, diversify, 72)
# 3. di = (d0 * ui) + vi
# 4. pi = di * G


# SKi = KDF(SKi-1, update, 32)
xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo = b""
)

SKi = xkdf.derive(bytes(compress(LostDeviceSharedKey), 'ISO-8859-1'))

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo=b""
)

xkdf.verify(bytes(compress(LostDeviceSharedKey), 'ISO-8859-1'), SKi)

# (ui, vi) = KDF(SKi, diversify, 72)

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=72,
    sharedinfo = b""
)

res = xkdf.derive(SKi)
Ui = res[:36]
Vi = res[36:72]

# converting to int
Ui_int_val = int.from_bytes(Ui, "big")
Vi_int_val = int.from_bytes(Vi, "big")

# di = (d0 * ui) + vi
Di = (LostDevicePrivKey * Ui_int_val) + Vi_int_val

# pi = di * G
Pi = Di * curve.g

print("Advertisement key of the Lost Device: " + compress(Pi))

##################
# Finder DEVICE #
##################
# ECDH with lost device using the Pi as generator
# X963 to derive another key of 32 bytes
# split this 32 bytes key into 16 bytes of e' and 16 bytes IV and use it with AES-GCM algorithm to cipher some metadata

# step 1
curve = registry.get_curve('secp224r1')

print("Pairing between my Finder and LostDevice...")

FinderPrivKey = secrets.randbelow(curve.field.n)
FinderPubKey = FinderPrivKey * Pi
print("Finder public key:", compress(FinderPubKey))

LostDevicePubKey2 = LostDevicePrivKey * Pi
print("Lost Device2 public key:", compress(LostDevicePubKey2))

FinderSharedKey = FinderPrivKey * LostDevicePubKey2
print("Finder shared key:", compress(FinderSharedKey))

LostDeviceSharedKey2 = LostDevicePrivKey * FinderPubKey
print("Lost Device2 shared key:", compress(LostDeviceSharedKey2))

print("Check if the iPhone and the Lost Device shared the same shared key:", FinderSharedKey == LostDeviceSharedKey2)

# step 2
xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo = bytes(compress(Pi), 'ISO-8859-1')
)

AES_GCM_KEY_TO_SPLIT = xkdf.derive(bytes(compress(FinderSharedKey), 'ISO-8859-1'))
e = AES_GCM_KEY_TO_SPLIT[:16]
IV = AES_GCM_KEY_TO_SPLIT[16:32]

outputFormat = "{:<25}:{}"
secret_key = str(e)
plain_text = "Your_plain_text"

print("------ AES-GCM Encryption ------")
cipher_text = encrypt(secret_key, plain_text, IV)
print(outputFormat.format("encryption input", plain_text))
print(outputFormat.format("encryption output", cipher_text))


##########
# iPhone #
##########
# suppongo gia' di sapere quale che sia la chiave Pi perche'
# magicamente sono sincronizzato con iCloud
# Domanda: se faccio l'hash di una kdf, ottengo la stessa collisione? Perhce' se si
# allora sono praticamente apposto
# devo rifare ECDH come ha fatto il Finder praticamente con il LostDevice, usando
# il medesimo generatore Pi. In questo modo dovrei essere in grado di arrivare ad un
# segreto comune tale per cui possa ritornare ad avere e' ed IV esattamente come li
# usati il Finder. In tal modo potrei decifrare il contenuto del file. 

final_key = FinderPubKey * LostDevicePrivKey

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

print("\n------ AES-GCM Decryption ------")
print(outputFormat.format("decryption input", cipher_text))
print(outputFormat.format("decryption output", decrypted_text))