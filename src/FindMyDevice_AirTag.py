#######################
# PAIRING WITH AIRTAG #
#######################

from lib.utils import *

print("""
 ██████╗ ██╗   ██╗███████╗██╗███╗   ██╗██████╗ 
 ██╔══██╗╚██╗ ██╔╝██╔════╝██║████╗  ██║██╔══██╗
 ██████╔╝ ╚████╔╝ █████╗  ██║██╔██╗ ██║██║  ██║
 ██╔═══╝   ╚██╔╝  ██╔══╝  ██║██║╚██╗██║██║  ██║
 ██║        ██║   ██║     ██║██║ ╚████║██████╔╝
 ╚═╝        ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝     AirTag Edition OwO 
        """)

# STEP 1: compute ECDH with the AirTag
print(" Pairing between the iPhone and my AirTag using ECDH")

# choosing the curve
curve = registry.get_curve('secp224r1')

iPhonePrivKey = secrets.randbelow(curve.field.n)
iPhonePubKey = iPhonePrivKey * curve.g
print("\n 1. iPhone public key: ", compress(iPhonePubKey))

LostDevicePrivKey = secrets.randbelow(curve.field.n)
LostDevicePubKey = LostDevicePrivKey * curve.g
print(" 2. Lost Device public key:", compress(LostDevicePubKey))

iPhoneSharedKey = iPhonePrivKey * LostDevicePubKey
print(" 3. iPhone shared key:", compress(iPhoneSharedKey))

LostDeviceSharedKey = LostDevicePrivKey * iPhonePubKey
print(" 4. Lost Device shared key:", compress(LostDeviceSharedKey))

print("\n Check if the iPhone and the Lost Device shared the same shared key:", iPhoneSharedKey == LostDeviceSharedKey)

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

print("\n Forging the first advertisment key: ", compress(Pi))

##################
# Finder DEVICE #
##################
# ECDH with lost device using the Pi as generator
# X963 to derive another key of 32 bytes
# split this 32 bytes key into 16 bytes of e' and 16 bytes IV and use it with AES-GCM algorithm to cipher some metadata
print("\n Oh no! Someone have stolen my wallet with the AirTag inside. Let's find the pickerpocket!")
print("\n *Someone with an iPhone casually pass by near the robber and spot my AirTag*")
print("\n Time for ECDH! (Between my airtag and the iPhone)")

# step 1
curve = registry.get_curve('secp224r1')

print("\nSomeone find my LostDevice. Time to exchanging some message through BLE...")

FinderPrivKey = secrets.randbelow(curve.field.n)
FinderPubKey = FinderPrivKey * Pi
print("\n 1. Finder public key:", compress(FinderPubKey))

LostDevicePubKey2 = LostDevicePrivKey * Pi
print(" 2. AirTag public key:", compress(LostDevicePubKey2))

FinderSharedKey = FinderPrivKey * LostDevicePubKey2
print(" 3. Finder shared key:", compress(FinderSharedKey))

LostDeviceSharedKey2 = LostDevicePrivKey * FinderPubKey
print(" 4. Airtag shared key:", compress(LostDeviceSharedKey2))

print(" Check if the finder's iPhone and the AirTag shared the same shared key: ", FinderSharedKey == LostDeviceSharedKey2)

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
plain_text = "via Alfieri 17, Bomporto (MO)"

print("\n Finder's iPhone send an ecnrypted location report to iCloud using AES-GCM Encryption") 
cipher_text = encrypt(secret_key, plain_text, IV)
print(outputFormat.format("encryption location report input", plain_text))
print(outputFormat.format("encryption location report output", cipher_text))

import hashlib

hashed_pi_finder = hashlib.sha256(compress(Pi).encode('ISO-8859-1')).hexdigest()
print("\n The advertisement key of my AirTag is hashed for iCloud : ", hashed_pi_finder)

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


###################
# iCloud Activity #
###################

print("\n I ask iCloud if is possible to find my missing device... maybe there are some reports for me! I'm using the hash my iPhone advertisement key to look for something")
hashed_pi_cached = hashlib.sha256(compress(Pi).encode('ISO-8859-1')).hexdigest()
print(hashed_pi_cached==hashed_pi_finder)

print(" There's something! Now it is time to download and decrypt the right report...")

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

print(outputFormat.format("\n Encrypted location report: ", cipher_text))
print(outputFormat.format(" Decrypted location report: ", decrypted_text))