#!/usr/local/bin/python3

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding

message = b"A message I want to sign"

def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

def load_publicKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_public_key(pem_data)

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

aze = load_cert("CRT.pem")

def verification(message1, signature1, certificat1):
    public_key = certificat1.public_key()
    
    verif = public_key.verify(
        signature1,
        message1,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
    ),
        hashes.SHA256()
    )
    
    if verif == None:
        print("message:", message1)
        print("signature valide")
        print("message valide")
        # VALIDER QUE CE SOIT BIEN L'UTILISATEUR DU CERTIFICAT
    else:
        print("message:", message1)
        print("attention signature invalide")
        print("message n'a pas été signé par le propriétaire du certificat")        


efd = verification(message, signature, aze)

print(efd)

uio = load_cert("/home/toto/crypto/certificate.pem")

# issuer_public_key = uio.public_key()

keye = load_publicKey("pubkey.pem")

print(keye)

issuer_public_key = load_pem_public_key(pem_issuer_public_key)

mpm = issuer_public_key.verify(
    aze.signature,
    aze.tbs_certificate_bytes,
    # Depends on the algorithm used to create the certificate
    padding.PKCS1v15(),
    aze.signature_hash_algorithm,
)

print(mpm)