#!/usr/local/bin/python3

from cryptography.fernet import Fernet

def signMsg(message, privKey):
    fernet = Fernet(privKey)
    encMessage = fernet.encrypt(message.encode())
    return encMessage

aze = signMsg("azeaze", "/home/toto/crypto/key2.pem")

print(aze)