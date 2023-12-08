import rsa
import secrets
import hashlib
from cryptography.fernet import Fernet
import base64

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

def hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def session_encrypt(key: bytes,message):
    key=base64.urlsafe_b64encode(key)
    msg_encrypt=Fernet(key)
    
    return msg_encrypt.encrypt(message)
    
def session_encrypt(key: bytes,message):
    key=base64.urlsafe_b64encode(key)
    msg_decrypt=Fernet(key)
    
    return msg_decrypt.decrypt(message)
    


if __name__ == "__main__":
    # main for testing
    data = b"Who AM I?"
    print(hash(data))
