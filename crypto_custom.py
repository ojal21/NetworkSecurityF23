import rsa
import secrets
import hashlib
import base64
import random
from math import gcd
from cryptography.fernet import Fernet

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

def hash(data: bytes, string: bool = True) -> str | bytes:
    return hashlib.sha256(data).hexdigest() if string else hashlib.sha256(data).digest()

#secure prime
visited=[]


def isPrime(num):
    if num<1:
        return False
    elif num>1:
        if num==2:
            return True
        for i in range(2,num):
            if num%i==0:
                return False
        return True

def generate_prime():
    # TODO increase
    num=random.randint(1,100)
    while isPrime(num)!=True and num not in visited:
        num=random.randint(1,100)
    visited.append(num)
    # print(visited)
    return num

def generate_privitive_root(num):
    result=1
    for i in range(2, num):
        if (gcd(i, num) == 1):
            print(i)

def primRoots(modulo):
    roots = []
    required_set = set(num for num in range (1, modulo) if gcd(num, modulo) == 1)

    for g in range(1, modulo):
        actual_set = set(pow(g, powers) % modulo for powers in range (1, modulo))
        if required_set == actual_set:
            roots.append(g)
    idx=random.randint(0,len(roots)-1)
    return roots[idx]

def generate_client_DH(p, g, x, A, B):
    print("--B---",B)
    session_key=hash((pow(int(B),x)%p).to_bytes(32,'big'), False)
    return Fernet(base64.urlsafe_b64encode(session_key))

def generate_server_DH(val):
    p,g,A=val.split()
    y=random.randint(1, 1024)
    session_key=hash((pow(int(A),y)%int(p)).to_bytes(32,'big'), False)
    B=(pow(int(g),y)%int(p))
    return Fernet(base64.urlsafe_b64encode(session_key)), str(B)

def generate_DH_params():
    x=random.randint(1, 1024)
    p=generate_prime()
    g=primRoots(p)
    A=pow(g,x)%p
    msg=str(p)+" "+str(g)+" "+str(A)
    return p,g,x,A,msg


if __name__ == "__main__":
    # main for testing
    data = b"Who AM I?"
    print(hash(data))
