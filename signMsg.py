#!/usr/local/bin/python3

import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

def signMsg(message, key):
    return key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() 
    )

def saveToFile(signature, filename):
	with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as crt_file_obj:
		crt_file_obj.write(signature)
		crt_file_obj.close()
	return "[+] Le certificat a été générée dans le fichier " + filename

def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

message = b"A message with 5 words"
privateKeyClient = load_privateKey("RSAClient.pem")
signatureMsg = signMsg(message, privateKeyClient)
saveToFile(signatureMsg, "test.sign")

print(aze)