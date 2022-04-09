# RT0802

- On dispose d’objets (véhicules) qui envoient deux types de messages CAM et DENM.
- On souhaite garantir l’authentification des objets.
- La passerelle recevait les messages et les renvoyait au centralisateur des événements.
- La passerelle contient une CA (un thread qui tourne par exemple) qui génère des certificats des clés publiques qui lui sont envoyées par les objets.
- Chaque objet possède le certificat autosigné du CA.
- Les objets envoient leurs message à la passerelle et s’arrangent pour que ceux ci soient authentifiés.
- 172.19.129.1

## Schéma de principe

## Code

### Initialisation du CA

On initialise l'autorité en lui générant une paire de clés RSA puis lui créer un certificat auto-signé.

#### Génération de la paire de clés RSA

```python
RSAkey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
```

#### Génération d'un certificat auto-signé

```python
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    RSAkey.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(RSAkey, hashes.SHA256())
```

#### Sauvegarde de la clé dans un fichier

```python
def saveKeysToFile(keyRSA, filename):
    with open(filename, "wb") as f:
        f.write(keyRSA.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            #passphrase de la clé = passphrase
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    return " Key file: " + filename
```

#### Sauvegarde du certificat

```python
def saveCert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return "Cert file: " + filename
```

#### Appel des fonctions

```python
saveCert(cert, "certCA.pem")
saveKeysToFile(RSAkey, "RSACA.pem")
```

### Initialisation du client

On initialise le client en lui générant une paire de clés RSA

#### Génération de la paire de clés

```python
RSAkey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
```

#### Sauvegarde de la paire de clés dans un fichier

```python
def saveKeysToFile(keyRSA, filename):
    with open(filename, "wb") as f:
        f.write(keyRSA.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    return " Key file: " + filename
```

#### Appel de la fonction

```python
saveKeysToFile(RSAkey, "RSAClient.pem")
```

### Génération d'un CSR sur le client

Le demandeur d'un certificat doit au préalable générer une CSR pour ensuite le transmettre à la CA qui va l'utiliser pour générer le certifcat au client.

#### Charger la clé privée du client

```python
def loadPrivateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase"
```

#### Génération du CSR

Info qui va être renseigné dans le certificat :

```python
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Strasbourg"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Strasss Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"strass.fr"),
])

privateKey = loadPrivateKey('RSAClient.pem')

csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(privateKey, hashes.SHA256())
```

#### Sauvegarder le CSR dans un fichier

```python
def saveCSR(csr, filename):
    with open(filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return "CSR file: " + filename
```

#### Appel fonction

```python
saveCSR(csr, "csr.pem")
```

### CA signe le CSR

Une fois que le CA a recu le CSR, il va pouvoir générer le certificat pour le demandeur.

#### Charger le CSR

```python
def loadCSR(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_csr(pem_data, default_backend()) 
```

#### Charger certificat CA pour valider le CSR

```python
def loadCert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())
```

#### Charger clé privée du CA pour valider le CSR

```python
def loadPrivateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")
```

#### Génération du certificat

```python
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
        datetime.utcnow() + timedelta(days=10)
    ).sign(private_ca_key, hashes.SHA256())
```

#### Sauvegarde du certificat dans un fichier

```python
def saveToFile(certificate, filename):
	with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as crt_file_obj:
	    crt_file_obj.write(certificate)
		crt_file_obj.close()
	return "[+] Le certificat a été générée dans le fichier " + filename
```

#### Appel des fonctions

```python
csr = loadCSR('csr.pem')
certCA = loadCert('certCA.pem')
privateKeyCA = loadPrivateKey('RSACA.pem')
aze = signCSR(csr, certCA, privateKeyCA)
saveToFile(aze, "certClient.pem")
```

### Signer ses messages

Le client pour authentifier ses messages va envoyer son message accompagné d'une signature du message (message chiffré avec sa clé privée) et son certificat signé par le CA

#### Charger sa clé privée

```python
def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")
```

#### Signer le message

```python
def signMsg(message, key):
    return key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() 
    )
```

#### Sauvegarder la signature dans un fichier

```python
def saveToFile(signature, filename):
	with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as crt_file_obj:
		crt_file_obj.write(signature)
		crt_file_obj.close()
	return "[+] Le certificat a été générée dans le fichier " + filename
```

#### Appel des fonctions

```python
message = b"A message with 5 words"
privateKeyClient = load_privateKey("RSAClient.pem")
signatureMsg = signMsg(message, privateKeyClient)
sig = base64.b64encode(signatureMsg)
saveToFile(sig, "sig")
```

### Vérification

Pour garantir l'authenfication des échanges:

- on verifie que la clé publique renseigné dans le certificat déchiffre bien la signature, on a ainsi confirmation que c'est bien l'entité renseigné dans le certificat qui a signé le message.

- on vérifie que le certificat est bien dans le domaine de confiance du CA en vérifiant le signature du certicat avec la clé publique du CA

#### Charger certificat du CA

```python
def load_cert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())
```

#### Charger la signature

```python
def loadSig(sig):
    with open("sig") as s:
        sig = s.read()
        decoded_sig = base64.b64decode(sig)
    return decoded_sig
```

#### Vérifier la signature du message

```python
def verifSignMsg(message1, signature1, certificat1):
    public_key = certificat1.public_key()

    verif = public_key.verify(
        signature1,
        message1,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
    ),
        hashes.SHA256()
    )
    
    if verif == None:
        print("message:", message1)
        print("signature valide")
        print("message valide")
    else:
        print("message:", message1)
        print("attention signature invalide")
        print("message n'a pas été signé par le propriétaire du certificat")     
```

#### Vérifier la signature du certificat

```python
def verifySignCert(cert, certCA):
    CA_publicKey = certCA.public_key()
    verif = CA_publicKey.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    if verif == None:
        print("certificat authentique")
    else:
        print("certificat non validé par le CA")
```

#### appel des fonctions

```python
message = b"A message with 5 words"
certClient = load_cert("certClient.pem")
CA_cert = load_cert("certCA.pem")
decodedSig = loadSig("sig")
verifSignMsgClient = verifSignMsg(message, decodedSig, certClient)
print(verifSignMsgClient)
verifySignCert(certClient, CA_cert)
```