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

##########
# iCloud #
##########

import hashlib

hashed_pi = hashlib.sha256(compress(Pi).encode('ISO-8859-1')).hexdigest()
print("pi hashed: ")
print(hashed_pi)
