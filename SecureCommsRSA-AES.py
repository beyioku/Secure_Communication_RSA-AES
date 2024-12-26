from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC      # used for key generation using PBKDF2 algorithm
from cryptography.hazmat.primitives import hashes                     # provides access to several cryptographic functions     
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF             #used for key generation using HKDF algorithm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes    # used to create AES cipher objects
from cryptography.hazmat.primitives import serialization            # used for serializing and deserializing cryptographic keys
from cryptography.hazmat.primitives.asymmetric import rsa, padding    # used to generate RSA keys and apply padding schemes
from cryptography.hazmat.primitives import hmac                 # used to create message authentication codes
import os                               # used to generate random bytes


# Generates RSA key pair for User A for both encryption and decryption
PrivateKeyA= rsa.generate_private_key(public_exponent=65537, key_size=2048)   # Generates a private key for the user A
PublicKeyA = PrivateKeyA.public_key()             #Extracts the public key from the private key for the user A

# Generate RSA key pair for User B for both encryption and decryption
PrivateKeyB = rsa.generate_private_key(public_exponent=65537, key_size=2048)      # Generates a private key for the user B
PublicKeyB = PrivateKeyB.public_key()              #Extracts the public key from the private key for the user B

aes_key = os.urandom(24)
EncyptedAesKey = PublicKeyB.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Step 3: User B decrypts the AES key using their private RSA key
# UserB uses their private key to decrypt the AES that was encrypted by the user A
 # Masks generation function with SHA-256,it also uses SHA256 as the hashing algorithm for the OAEP padding
DecryptedAesKey = PrivateKeyB.decrypt(EncyptedAesKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# AES encryption (Cipher Block Chaining (CBC) mode)
# CBC mode uses an initialization vector to add randomness to the encryption process represented as initial_value
initial_value = os.urandom(16)  # generates a random 128-bit IV for CBC mode
cipher = Cipher(algorithms.AES(DecryptedAesKey), modes.CBC(initial_value))    # creates AES cipher object with CBC mode
encryptor = cipher.encryptor()          # creates an encryptor to encrypt the message

# Pad the message to be a multiple of 128 bits (16 bytes) using PKCS#7 padding
# AES requires the padding to be a multiple of its block size (128 bits)
message = b"Secret message from User A"        # message to be encrypted
PaddingLength = 16 - (len(message) % 16)        # calculated the required padding length
message += bytes([PaddingLength] * PaddingLength)  # adds a PKCS#7 padding to the message

# Encrypt the message
# the message is encrypted using the AES key and the CBC mde
CipherText = encryptor.update(message) + encryptor.finalize()

# Generate HMAC for the message using AES key
# HMAC ensures the integrity and authenticity of the ciphertext
h = hmac.HMAC(DecryptedAesKey, hashes.SHA256())          # creates an HMAC object with AES key and SHA-256 hash
h.update(CipherText)       # hashes the ciphertext
mac = h.finalize()         # finalizes the HMAC to get the Message Authentication Code


# Decrypt the CipherText
cipher = Cipher(algorithms.AES(DecryptedAesKey), modes.CBC(initial_value))     # Recreates the cipher objectt for decryption
decryptor = cipher.decryptor()                  # creates a decryptor object to decrypt the ciphertext
DecryptedMessage = decryptor.update(CipherText) + decryptor.finalize()

# Remove padding
# This removes the padding that was added during encryption to get the original message
PaddingLength = DecryptedMessage[-1]            # this line gets the padding length from the last byte of the deccypted message
DecryptedMessage = DecryptedMessage[:-PaddingLength]

# Verify HMAC to ensure the integrity of the ciphertext
h = hmac.HMAC(DecryptedAesKey, hashes.SHA256())        # recreates the HMAC object with the same key and hash
h.update(CipherText)               # hashes the Ciphertext
try:
    h.verify(mac)                      # verifies the HMAC matches the original MAC
    print("Authentication successful! Message integrity verified Genius.")
except Exception as e:
    print("Authentication failed!")
