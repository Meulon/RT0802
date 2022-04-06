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

def sign_certificate_request(csr_cert, ca_cert, private_ca_key):
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


def savecrttofile(certificate):
	crt_file="CRT.pem"

	try:
		os.umask(0)

		with open(os.open(crt_file, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as crt_file_obj:
			crt_file_obj.write(certificate)
			crt_file_obj.close()

	except:
		raise
	else:
		return "[+] Le certificat a été générée dans le fichier " + crt_file

with open('/home/toto/crypto/csr.pem', 'rb') as f1:
        csr_data = f1.read()

with open('/home/toto/crypto/certificate.pem', 'rb') as f2:
        cert_data = f2.read()

with open('/home/toto/crypto/key2.pem', 'rb') as f3:
        keyy = f3.read()

csr = x509.load_pem_x509_csr(csr_data, default_backend())
cert = x509.load_pem_x509_certificate(cert_data, default_backend())

privKey = serialization.load_pem_private_key(keyy, password=None)

aze = sign_certificate_request(csr, cert, privKey)

savecrttofile(aze)