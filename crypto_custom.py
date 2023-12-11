import rsa
import secrets
import hashlib
import hmac
import random
from math import gcd
from Crypto.Cipher import AES

def load_key_from_file(path: str, private: bool) -> rsa.PrivateKey | rsa.PublicKey:
    keyString = b''
    with open(path,'rb') as keyFile:
        keyString = keyFile.read()
    return rsa.PrivateKey.load_pkcs1(keyString) if private else rsa.PublicKey.load_pkcs1(keyString)

def rsa_encrypt(message: bytes, key: rsa.PublicKey) -> bytes:
    return rsa.encrypt(message, key)

def rsa_decrypt(data: bytes, key: rsa.PrivateKey) -> bytes:
    return rsa.decrypt(data, key)

def get_nonce(nbytes: int | None = None) -> bytes:
    return secrets.token_bytes(nbytes)

def hash(data: bytes, string: bool = True) -> str | bytes:
    return hashlib.sha256(data).hexdigest() if string else hashlib.sha256(data).digest()

def get_cipher(key: bytes, iv: bytes):
    return AES.new(key, AES.MODE_CFB, iv)

def keyed_hash(key: bytes, msg: bytes):
    return hmac.new(key, msg, hashlib.sha256).digest()

def hash_file_content(file_content: bytes) -> bytes:
    # ignore padding
    data = bytes(file_content)
    if b"\0" in data:
        data = data[: data.index(b"\0")]
    return hash(data, False)

def verify_file_hash(file_content_with_hash: bytes) -> bool:
    data = bytes(file_content_with_hash[:-32])
    recv_hash = file_content_with_hash[-32:]
    if b"\0" in data:
        data = data[: data.index(b"\0")]
    calc_hash = hash(data, False)
    return calc_hash == recv_hash

def aes_encrypt(key: tuple[bytes, bytes], data: bytes):
    iv = get_nonce(16)
    encrypted_data = get_cipher(key[0], iv).encrypt(data)
    # print('iv=', iv)
    # print('encr=', encrypted_data)
    # print('hash=', keyed_hash(key[1], iv + encrypted_data))
    return iv + encrypted_data + keyed_hash(key[1], iv + encrypted_data)

def aes_decrypt(key: tuple[bytes, bytes], data: bytes):
    iv = data[:16]
    encryted_data = data[16:-32]
    rcvd_hash = data[-32:]
    calc_hash = keyed_hash(key[1], data[:-32])
    # print('iv=', iv, 'encr=', encryted_data, 'hash=', rcvd_hash, 'calc=', calc_hash)
    if rcvd_hash != calc_hash:
        print('MESSAGE INTEGRITY FAILED!')
        return None
    return get_cipher(key[0], iv).decrypt(encryted_data)

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

def generate_client_DH(p, g, x1, x2, A1, A2, B1, B2):
    encryption_key=hash((pow(int(B1),x1)%p).to_bytes(32,'big'), False)
    mac_key=hash((pow(int(B2),x2)%p).to_bytes(32,'big'), False)
    return encryption_key, mac_key

def generate_server_DH(val):
    p,g,A1,A2=val.split()
    y1=random.randint(1, 1024)
    y2=random.randint(1, 1024)
    encryption_key=hash((pow(int(A1),y1)%int(p)).to_bytes(32,'big'), False)
    mac_key=hash((pow(int(A2),y2)%int(p)).to_bytes(32,'big'), False)
    B1=(pow(int(g),y1)%int(p))
    B2=(pow(int(g),y2)%int(p))
    return (encryption_key, mac_key),  str(B1)+" "+str(B2)

def generate_DH_params():
    x1=random.randint(1, 1024)
    x2=random.randint(1, 1024)
    p=generate_prime()
    g=primRoots(p)
    A1=pow(g,x1)%p
    A2=pow(g,x2)%p
    msg=str(p)+" "+str(g)+" "+str(A1)+" "+str(A2)
    return p,g,x1,x2,A1,A2,msg

if __name__ == "__main__":
    # main for testing
    data = b"Who AM I?"
    print(hash(data))

    key = hashlib.sha256().digest()
    data = b'WHAT AM I DOING HERE? WE NEED TO FINISH THIS ASAP. BUT is it possible to go on with just caffine?'

    encrypted = aes_encrypt(key, data)
    print(encrypted)
    print(aes_decrypt(key, encrypted))
