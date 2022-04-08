#!/usr/local/bin/python3

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate our key
def generateKeyRSA(a, b):
    rsa.generate_private_key(
        public_exponent=a,
        key_size=b
    )
    return ("Generation Key OK")


generateKeyRSA(65537, 2048)
#key = rsa.generate_private_key(
 #   public_exponent=65537,
  #  key_size=2048,
#)

# Write our key to disk for safe keeping

def saveToFile(privateKey, filename):
	with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as crt_file_obj:
		crt_file_obj.write(privateKey)
		crt_file_obj.close()
	return " Key file: " + filename

with open("/home/toto/crypto/key4.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))


# Generate a CSR

csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"BAS RHIN"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"SXB"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company 2"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite2.com"),

])).add_extension(
    x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.DNSName(u"mysite2.com"),
        x509.DNSName(u"www.mysite2.com"),
        x509.DNSName(u"subdomain.mysite2.com"),
    ]),
    critical=False,
# Sign the CSR with our private key.
).sign(key, hashes.SHA256())
# Write our CSR out to disk.

with open("/home/toto/crypto/csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))