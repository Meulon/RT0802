#!/usr/local/bin/python3

import base64
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
import os

def load_ciphertext(path):
    with open(path, 'rb') as f:
        ciphertext = f.read()
        decodedCiphertext = base64.b64decode(ciphertext)
    return decodedCiphertext

def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

def load_cert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())

def verif_sign(ciphertext, signature, certificat, verifKey, privateKey):
    if verifKey == "valid key":
        plaintext = privateKey.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    ))
        public_key = certificat.public_key()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(plaintext)
        digestMessage = digest.finalize()
    
        try:
            verif = public_key.verify(
                signature,
                digestMessage,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
            ),
                hashes.SHA256()
            )

        except exceptions.InvalidSignature:
            verif = "invalid"

        if verif == None:
            print("[+] message intègre et provient bien du propriétaire du certificat")
            result = "valide"
        else:
            print("[-] message corrompu et/ou ne provient pas du propriétaire du certificat")
            result = "invalide"
    else:
        print("[-] impossible de déchiffrer le message et donc de valider la signature")
        result = "invalide"
        
    return result

def load_file(file):
    with open(file) as s:
        file = s.read()
        decoded_file = base64.b64decode(file)
    return decoded_file

def verif_private_key(ciphertext, privateKey):
    try:
        data = privateKey.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        
        verif = "valid key"

    except ValueError:
       verif = "wrong key" 

    if verif == "valid key":
        print("[+] clé valide")
        result = "valid key"
    else:
        print("[-] mauvaise clé")
        result = "wrong key"

    return result

def hash_msg(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()

def verif_cert(cert, certCA):
    publicKeyCA = certCA.public_key()

    try:
        verif = publicKeyCA.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
                )

    except exceptions.InvalidSignature:
        verif = "invalid"

    if verif == None:
        print("[+] certificat authentique : signé par le CA")
        result = "valide"
    else:
        print("[-] certificat factice : non signé par le CA")
        result = "factice"

    return result

def read_msg(verifSign, verifCert, verifKey, privateKey, ciphertext):
    if verifSign == "valide" and verifCert == "valide" and verifKey == "valid key" : 
        plaintext64 = privateKey.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                ))
        plaintext = plaintext64.decode("utf-8")
        print("[+] contenu du message: " + plaintext)
    else:
        print("[-] non affichage du contenu: signature et/ou certificat non conforme et/ou mauvaise clé")

inputSignature = input("Indiquez la signature à utiliser: ")
inputCert = input("Indiquez le certificat de l'expediteur à utiliser: ")
inputCertCA = input("Indiquez le certificat CA: ")
inputPrivateKey = input("Indiquez votre clé privée: ")
inputCiphertext = input("Indiquez le message chiffré à utiliser: ")

## initialisation
signature = load_file(inputSignature)
certC1 = load_cert(inputCert+".pem")
certCA = load_cert(inputCertCA+".pem")
privateKey = load_privateKey(inputPrivateKey+".pem")
ciphertext = load_file(inputCiphertext)

## déchiffrer message
verifKey = verif_private_key(ciphertext, privateKey)

## empreinte message

## vérification de la signature + intégrité du message
verifSign = verif_sign(ciphertext, signature, certC1, verifKey, privateKey)


## vérification de l'authenticité du certificat
verifCert = verif_cert(certC1, certCA)

## lecture du message si verifications OK
read_msg(verifSign, verifCert, verifKey, privateKey, ciphertext)
