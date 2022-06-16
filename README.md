# RT0802

- On dispose d’objets (véhicules) qui envoient deux types de messages CAM et DENM.
- On souhaite garantir l’authentification des objets.
- La passerelle recevait les messages et les renvoyait au centralisateur des événements.
- La passerelle contient une CA (un thread qui tourne par exemple) qui génère des certificats des clés publiques qui lui sont envoyées par les objets.
- Chaque objet possède le certificat autosigné du CA.
- Les objets envoient leurs message à la passerelle et s’arrangent pour que ceux ci soient authentifiés.
- 172.19.129.1

## Schéma de principe

![RT0801_schema](https://user-images.githubusercontent.com/16819980/162580936-0322edf3-25b6-4b67-b268-78900a739bf9.svg)

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

### Envoie des messages

Lorsqu'un équipement souhaite envoyé un message il effectue les étapes suivantes:

- hash le message
- chiffre l'empreinte avec sa clé privée
- chiffre le message avec la clé publique de l'expediteur
  
#### Charger sa clé privée

```python
def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")
```

#### Charger certificat

```python
def load_cert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())
```

#### Signer l'empreinte

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

#### Chiffrer le message ou l'empreinte 

```python
def encrypt_msg(message, certificat):
    publicKey = certificat.public_key()

    return publicKey.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
```

#### Sauvegarder le message ou la signature

```python
def save_to_file(contenu, message, filename):
        with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o1600), 'wb+') as msg_obj:
                msg_obj.write(message)
                msg_obj.close()
        print("[+] " + contenu + " stocké dans le fichier: " + filename)
```

#### Appel des fonctions

##### input

```python
message = input("Votre message à chiffre: ")
inputCert = input("Indiquez le certificat du destinataire: ")
inputPrivateKey = input("Indiquez votre clé privée: ")
inputCiphertextFilename = input("Nom de fichier du message chiffré: ")
inputSignatureFilename = input("Nom de fichier de la signature: ")
```

##### initialisation

```python
message64 = str.encode(message)
certC2 = load_cert(inputCert + ".pem")
privateKey = load_privateKey(inputPrivateKey + ".pem")
```

##### chiffrement msg

```python
ciphertext = encrypt_msg(message64, certC2)
ciphertext64 = base64.b64encode(ciphertext)
```

##### sauvegarde message chiffré

```python
save_to_file("message chiffré", ciphertext64, inputCiphertextFilename)
```

##### signature empreinte msg

```python
digest = hash_msg(message64) # empreinte message
digest64 = base64.b64encode(digest)
signMsg = sign_msg(digest, privateKey)
signMsg64 = base64.b64encode(signMsg)
```

##### sauvegarde empreinte signé

```python
save_to_file("empreinte signée", signMsg64, inputSignatureFilename)
```

### Reception de message

Dès reception d'un message, le destinataire va effectuer les vérifications suivantes:

- déchiffrer le message (confidentialité)
- déchiffrer la signature avec clé publique du destinataire (authentifie l'expediteur)
- hasher le message et comparer le résultat avec celle fourni avec la signature déchiffré (intégrité)
- verifie l'authenticité du certificat envoyé avec avec le message en utilisant le certificat de l'autorité (authenticité du certificat)

#### Charger les certificats

```python
def load_cert(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())
```

#### Charger message/empreinte chiffré

```python
def load_ciphertext(path):
    with open(path, 'rb') as f:
        ciphertext = f.read()
        decodedCiphertext = base64.b64decode(ciphertext)
    return decodedCiphertext
```

#### Charger clé privée

```python
def load_privateKey(path):
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=b"passphrase")
```

#### Charger signature

```python
def load_file(file):
    with open(file) as s:
        file = s.read()
        decoded_file = base64.b64decode(file)
    return decoded_file
```

#### Vérifier que la clé privée peut déchiffrer le message/empreinte chiffré

```python
def verif_private_key(ciphertext, privateKey):
    try:
        data = privateKey.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        
        verif = "valid key"

    except ValueError:
       verif = "wrong key" 

    if verif == "valid key":
        print("[+] clé valide")
        result = "valid key"
    else:
        print("[-] mauvaise clé")
        result = "wrong key"

    return result
```

#### Verifier la signature

```python
def verif_sign(ciphertext, signature, certificat, verifKey, privateKey):
    if verifKey == "valid key":
        plaintext = privateKey.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    ))
        public_key = certificat.public_key()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(plaintext)
        digestMessage = digest.finalize()
    
        try:
            verif = public_key.verify(
                signature,
                digestMessage,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
            ),
                hashes.SHA256()
            )

        except exceptions.InvalidSignature:
            verif = "invalid"

        if verif == None:
            print("[+] message intègre et provient bien du propriétaire du certificat")
            result = "valide"
        else:
            print("[-] message corrompu et/ou ne provient pas du propriétaire du certificat")
            result = "invalide"
    else:
        print("[-] impossible de dechiffrer l'empreinte")
        result = "invalide"
        
    return result
```

#### Vérifier l'authenticité du certificat

```python
def verif_cert(cert, certCA):
    publicKeyCA = certCA.public_key()

    try:
        verif = publicKeyCA.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
                )

    except exceptions.InvalidSignature:
        verif = "invalid"

    if verif == None:
        print("[+] certificat authentique : signé par le CA")
        result = "valide"
    else:
        print("[-] certificat factice : non signé par le CA")
        result = "factice"

    return result
```

#### Lecture du fichier si toutes les conditions sont remplies

```python
def read_msg(verifSign, verifCert, verifKey, privateKey, ciphertext):
    if verifSign == "valide" and verifCert == "valide" and verifKey == "valid key" : 
        plaintext64 = privateKey.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                ))
        plaintext = plaintext64.decode("utf-8")
        print("[+] contenu du message: " + plaintext)
    else:
        print("[-] non affichage du contenu: signature et/ou certificat non conforme et/ou mauvaise clé")
```

#### Appel des fonctions

##### Input

```python
inputSignature = input("Indiquez la signature à utiliser: ")
inputCert = input("Indiquez le certificat de l'expediteur à utiliser: ")
inputCertCA = input("Indiquez le certificat CA: ")
inputPrivateKey = input("Indiquez votre clé privée: ")
inputCiphertext = input("Indiquez le message chiffré à utiliser: ")
```

##### Initialisation

```python
signature = load_file(inputSignature)
certC1 = load_cert(inputCert+".pem")
certCA = load_cert(inputCertCA+".pem")
privateKey = load_privateKey(inputPrivateKey+".pem")
ciphertext = load_file(inputCiphertext)
```

##### Déchiffrer message

```python
verifKey = verif_private_key(ciphertext, privateKey)
```

##### Vérification de la signature + intégrité du message

```python
verifSign = verif_sign(ciphertext, signature, certC1, verifKey, privateKey)
```

##### Vérification de l'authenticité du certificat

```python
verifCert = verif_cert(certC1, certCA)
```

##### Lecture du message si verifications OK

```python
read_msg(verifSign, verifCert, verifKey, privateKey, ciphertext)
```
