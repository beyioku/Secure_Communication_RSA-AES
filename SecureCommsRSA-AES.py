from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hmac
import os


# Generates RSA key pair for User A
PrivateKeyA= rsa.generate_private_key(public_exponent=65537, key_size=2048)
PublicKeyA = PrivateKeyA.public_key()

# Generate RSA key pair for User B
PrivateKeyB = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PublicKeyB = PrivateKeyB.public_key()

aes_key = os.urandom(24)
EncyptedAesKey = PublicKeyB.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Step 3: User B decrypts the AES key
# UserB uses their private key to decrypt the AES that was encrypted by the user A
 # Masks generation function with SHA-256,it also uses SHA256 as the hashing algorithm for the OAEP padding
DecryptedAesKey = PrivateKeyB.decrypt(EncyptedAesKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# AES encryption (Cipher Block Chaining (CBC) mode)
# CBC mode uses an initialization vector to add randomness to the encryption process represented as initial_value
initial_value = os.urandom(16)  # generates a random 128-bit IV for CBC mode
cipher = Cipher(algorithms.AES(DecryptedAesKey), modes.CBC(initial_value))
encryptor = cipher.encryptor()

# Pad the message to be a multiple of 128 bits (16 bytes)
# AES requires the padding to be a multiple of its block size (128 bits)
message = b"Secret message from User A"
PaddingLength = 16 - (len(message) % 16)
message += bytes([PaddingLength] * PaddingLength)  # adds a PKCS#7 padding

# Encrypt the message
# the message is encrypted using the AES key and the CBC mde
CipherText = encryptor.update(message) + encryptor.finalize()

# Generate HMAC for the message using AES key
# HMAC ensures the integrity and authenticity of the ciphertext
h = hmac.HMAC(DecryptedAesKey, hashes.SHA256())
h.update(CipherText)
mac = h.finalize()


# Decrypt the CipherText
cipher = Cipher(algorithms.AES(DecryptedAesKey), modes.CBC(initial_value))
decryptor = cipher.decryptor()
DecryptedMessage = decryptor.update(CipherText) + decryptor.finalize()

# Remove padding
# This removes the padding that was added during encryption to get the original message
PaddingLength = DecryptedMessage[-1]
DecryptedMessage = DecryptedMessage[:-PaddingLength]

# Verify HMAC
h = hmac.HMAC(DecryptedAesKey, hashes.SHA256())
h.update(CipherText)
try:
    h.verify(mac)
    print("Authentication successful! Message integrity verified Genius.")
except Exception as e:
    print("Authentication failed!")