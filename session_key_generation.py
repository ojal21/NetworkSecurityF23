import random
from math import gcd
import socket
from cryptography.fernet import Fernet
from crypto_custom import *

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
#if else check for rsa 
#pass only when needed for merchant case
def generate_client_DH(server:socket.socket,rsa_pubk, rsa_priv_k): #hold them as return values
    x=random.randint(1, 1024)
    p=generate_prime()
    g=primRoots(p)
    A=pow(g,x)%p
 
    msg=""
    msg+=(str(p)+" ")
    msg+=(str(g)+" ")
    msg+=(str(A))
    
    server.send(encrypt(msg.encode(),rsa_pubk))
    
    if rsa_priv_k==None:
        B=server.recv(1024).decode()
        print("case3333----",B)
    else:
        B=decrypt(server.recv(1024),rsa_priv_k).decode()
    print("--B---",B)
    # # # sessionk="{0:016b}".format((pow(int(B),x)%p))
    session_key=hash((pow(int(B),x)%p).to_bytes(32,'big'), False)
    # # print("client session_gen_client---",sessionk)
    return Fernet(base64.urlsafe_b64encode(session_key))

def generate_server_DH(val,rsa_pubk,rsa_privk):
    #g, p, A decrypt
    val=decrypt(val,rsa_privk)
    val=val.decode()
    p,g,A=val.split()
    
        
    y=random.randint(1, 1024)
    session_key=hash((pow(int(A),y)%int(p)).to_bytes(32,'big'), False)
    
    B=(pow(int(g),y)%int(p))
    # ="{0:016b}".format(sessionk)
    
    return Fernet(base64.urlsafe_b64encode(session_key)), str(B)
   
#convert session k into hexadecimal 
    
# generate_client_DH(None)


    
           