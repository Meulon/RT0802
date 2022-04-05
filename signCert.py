#!/usr/local/bin/python3

from email.policy import default
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

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

    # return DER certificate
    return cert.public_bytes(serialization.Encoding.DER)

csr = '''-----BEGIN CERTIFICATE REQUEST-----
MIIC8TCCAdkCAQAwWzELMAkGA1UEBhMCRlIxETAPBgNVBAgMCEJBUyBSSElOMQww
CgYDVQQHDANTWEIxFTATBgNVBAoMDE15IENvbXBhbnkgMjEUMBIGA1UEAwwLbXlz
aXRlMi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDl0nmZyR6w
Lb5fEPDYGjAgLZn38izbrVxCokP9+1h+PGV9VSA6G6QgUpIn8dmok+SAktkGJkbQ
gDZ8diDXTkqZ8XdHLSdzGwz2552Hox66SwjiEBajQnQNfdrudoCsoD0wM2sAkv7J
YRI6NptoQWWA2i7iF5Wr029Dv01CcInWtCcqfaTNmcRDS91xE9/7K8WN7jt3JKe3
G33zl9WlqdBR3tR3VA9S8itd3UTTq05KcpEeDiBTgnQX9PlED+LSpbSALAYuWUI7
v/TYJVViWvTrphZhS9aZw66sx67A7V2ELRu4zSKQ25o8CqUXM3gclf43T1occDND
PrhE5m93wPDdAgMBAAGgUTBPBgkqhkiG9w0BCQ4xQjBAMD4GA1UdEQQ3MDWCC215
c2l0ZTIuY29tgg93d3cubXlzaXRlMi5jb22CFXN1YmRvbWFpbi5teXNpdGUyLmNv
bTANBgkqhkiG9w0BAQsFAAOCAQEAzcXRtj2iILAeZClylNG/0yjytkRJzthVbLpq
FX4Dz8dNNf16WrNFMGH4N+4LRsdfSTug/pyB9wPFiXwjgN9sxdxtGv87CVcVXAT6
G9mYuHmBWMEdwbtk12Jp/2d+1eilDRFtA9x9dqO7NbAtrI9n71J1cypl0dgfydJM
Ihw4XK4QWxCCgT5UMFR3UGgb01Gh0Yyjzk5b2ThIIZg3BQKxSUOCYyGZFclJxB7S
T+suiqLJJRD0r729+uEpR1Q2P/YqRBPPaQkBB3R3GqbEigPXQ5ZMHW82vbTyCbO1
OtokrtbTYkCu7NnuTvEcFkgM8c9kREibGgi7WGLTznL9/+USjw==
-----END CERTIFICATE REQUEST-----'''

csr1 = x509.load_pem_x509_csr(csr)
cert = x509.load_pem_x509_certificate('/home/toto/crypto/certificate.pem')

privKey = serialization.load_pem_private_key('/home/toto/crypto/key.pem')

sign_certificate_request(csr1, cert, privKey)