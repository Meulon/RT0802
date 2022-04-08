#!/usr/local/bin/python3

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding

def load_publicKey(path):
    with open(path, 'rb') as f1:
        pem1_data = f1.read()
    return serialization.load_pem_public_key(pem1_data)

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


def verifSignMsg(message1, signature1, certificat1):
    public_key = certificat1.public_key()
    # subject = certificat1.subject()

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
        # print("provient bien de:", subject)
        # VALIDER QUE CE SOIT BIEN L'UTILISATEUR DU CERTIFICAT
    else:
        print("message:", message1)
        print("attention signature invalide")
        print("message n'a pas été signé par le propriétaire du certificat")        

def verifySignCert(cert, certCA):
    CA_publicKey = certCA.public_key()
    verif = CA_publicKey.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    if verif == None:
        print("certificat authentique")
    else:
        print("certificat non validé par le CA")

message = b"A message with 5 words"
certClient = load_cert("certClient.pem")
with open("test.sign") as s:
    sig = s.read()
    decoded_sig = base64.b64decode(sig)
CA_cert = load_cert("certCA.pem")
verifSignMsgClient = verifSignMsg(message, file, certClient)
print(verifSignMsgClient)
verifySignCert(certClient, CA_cert)