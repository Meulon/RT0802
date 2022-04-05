#!/usr/local/bin/python3

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate our key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Write our key to disk for safe keeping

with open("/home/toto/ssh/key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))