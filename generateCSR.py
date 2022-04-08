#!/usr/local/bin/python3

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def saveCSR(csr, filename):
    with open(filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return "CSR file: " + filename

def loadPrivateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Strasbourg"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Strasss Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"strass.fr"),
])

privateKey = loadPrivateKey('RSAClient.pem')

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(privateKey, hashes.SHA256())

# Write our CSR out to disk.


saveCSR(csr, "csr.pem")