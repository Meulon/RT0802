#!/usr/local/bin/python3

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

# Generate our key


# Write our key to disk for safe keeping

def saveKeysToFile(keyRSA, filename):
    with open(filename, "wb") as f:
        f.write(keyRSA.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    return " Key file: " + filename

def saveCSR(csr, filename):
    with open(filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return "CSR file: " + filename

RSAkey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Strasbourg"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Strasss Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"strass.fr"),
])

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(RSAkey, hashes.SHA256())

# Write our CSR out to disk.

saveKeysToFile(RSAkey, "RSAClient.pem")
saveCSR(csr, "csr.pem")