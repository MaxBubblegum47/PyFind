#######################
# PAIRING WITH AIRTAG #
#######################

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
print("iPhone private key:", iPhonePrivKey)


from cryptography.fernet import Fernet
import base64
# Put this somewhere safe!
iPhoneSymmetricKey = Fernet.generate_key(32)
print(len(iPhoneSymmetricKey))