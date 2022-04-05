#!/usr/local/bin/python3

serialnumber = random.getrandbits(64)
ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, "/home/toto/crypto/certificate.pem")
ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, "/home/toto/crypto/key2.pem")
certs = crypto.X509()
csr_req = crypto.load_certificate_request(crypto.FILETYPE_PEM, "/home/toto/crypto/csr.pem")
certs.set_serial_number(serialnumber)
certs.gmtime_adj_notBefore(0)
certs.gmtime_adj_notAfter(31536000)
certs.set_subject(csr_req.get_subject())
certs.set_issuer(ca_cert.get_subject())
certs.set_pubkey(k)
certs.sign(ca_key, ‘sha512’)certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certs)

