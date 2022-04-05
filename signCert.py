#!/usr/local/bin/python3

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

sign_certificate_request('/home/toto/crypto/csr.pem', '/home/toto/crypto/certificate.pem', '/home/toto/crypto/key.pem')