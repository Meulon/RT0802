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

def load_csr(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_csr(pem_data, default_backend()) 

#with open('/home/toto/crypto/csr.pem', 'rb') as f1:
#   csr_data = f1.read()

def load_cert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())

def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

# with open('/home/toto/crypto/certificate.pem', 'rb') as f2:
#        cert_data = f2.read()

# with open('/home/toto/crypto/key2.pem', 'rb') as f3:
#        keyy = f3.read()

csr = load_csr('/home/toto/crypto/csr.pem')
certCA = load_cert('/home/toto/crypto/certificate.pem')
privateCAKey = load_privateKey('/home/toto/crypto/key2.pem')

# csr = x509.load_pem_x509_csr(csr_data, default_backend())
# cert = x509.load_pem_x509_certificate(cert_data, default_backend())
# privKey = serialization.load_pem_private_key(keyy, password=None)

aze = signCSR(csr, certCA, privateCAKey)

saveToFile(aze, "test.pem")