import rsa
import secrets

def load_key_from_file(path: str, private: bool) -> rsa.PrivateKey | rsa.PublicKey:
    keyString = b''
    with open(path,'rb') as keyFile:
        keyString = keyFile.read()
    return rsa.PrivateKey.load_pkcs1(keyString) if private else rsa.PublicKey.load_pkcs1(keyString)

def encrypt(message: bytes, key: rsa.PublicKey) -> bytes:
    return rsa.encrypt(message, key)

def decrypt(data: bytes, key: rsa.PrivateKey) -> bytes:
    return rsa.decrypt(data, key)

def get_nonce() -> bytes:
    return secrets.token_bytes()