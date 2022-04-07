#!/usr/local/bin/python3

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend

message = b"A message I want to sign"

def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

def signMsg(message, key):
    return key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256() 
)

def load_cert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())

private_key = load_privateKey("/home/toto/crypto/key2.pem")
signature = signMsg(message, private_key)

print(base64.b64encode(signature))

aze = load_cert("/home/toto/crypto/certificate.pem")

public_key = aze.public_key()

efd = public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(efd)