#!/usr/local/bin/python3

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import datetime
from datetime import timedelta, datetime 
import os 

def signCSR(csr_cert, ca_cert, private_ca_key):
    cert = x509.CertificateBuilder().subject_name(
        csr_cert.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr_cert.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.utcnow() + timedelta(days=10)
    # Sign our certificate with our private key
    ).sign(private_ca_key, hashes.SHA256())

    # return PEM certificate
    return cert.public_bytes(serialization.Encoding.PEM)

def saveToFile(certificate, filename):
	with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as crt_file_obj:
		crt_file_obj.write(certificate)
		crt_file_obj.close()
	return "[+] Le certificat a été générée dans le fichier " + filename

def loadCSR(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_csr(pem_data, default_backend()) 

def loadCert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())

def loadPrivateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

csr = loadCSR('/home/toto/crypto/csr.pem')
certCA = loadCert('/home/toto/crypto/certificate.pem')
privateKeyCA = loadPrivateKey('RSACA.pem')

aze = signCSR(csr, certCA, privateKeyCA)

saveToFile(aze, "certClient.pem")