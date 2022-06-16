#!/usr/local/bin/python3

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
import os

def hash_msg(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()

def sign_msg(message, key):
    return key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() 
    )

def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

def load_cert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())

def encrypt_msg(message, certificat):
    publicKey = certificat.public_key()

    return publicKey.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )

def save_to_file(contenu, message, filename):
        with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as msg_obj:
                msg_obj.write(message)
                msg_obj.close()
        print("[+] " + contenu + " stocké dans le fichier: " + filename)

## input
message = input("Votre message à chiffre: ")
inputCert = input("Indiquez le certificat du destinataire: ")
inputPrivateKey = input("Indiquez votre clé privée: ")
inputCiphertextFilename = input("Nom de fichier du message chiffré: ")
inputSignatureFilename = input("Nom de fichier de la signature: ")

## initialisation
message64 = str.encode(message)
certC2 = load_cert(inputCert + ".pem")
privateKey = load_privateKey(inputPrivateKey + ".pem")

## chiffrement msg
ciphertext = encrypt_msg(message64, certC2)
ciphertext64 = base64.b64encode(ciphertext)

## sauvegarde message chiffré
save_to_file("message chiffré", ciphertext64, inputCiphertextFilename)

## signature empreinte msg
digest = hash_msg(message64) # empreinte message
digest64 = base64.b64encode(digest)
signMsg = sign_msg(digest, privateKey)
signMsg64 = base64.b64encode(signMsg)

## sauvegarde empreinte signé
save_to_file("empreinte signée", signMsg64, inputSignatureFilename)

