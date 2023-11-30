import random
from math import gcd
import socket

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
    num=random.randint(1,2048)
    while isPrime(num)!=True and num not in visited:
        num=random.randint(1,2048)
    visited.append(num)
    print(visited)
    return num

def generate_privitive_root(num):
    # for g in range(2, num):
    #     if g ** (num - 1) % num == 1:
    #         return g
    result=1
    for i in range(2, num):
        if (gcd(i, num) == 1):
            print(i)
 
# def gcd(a,b):
#     while b != 0:
#         a, b = b, a % b
#     return a

def primRoots(modulo):
    roots = []
    required_set = set(num for num in range (1, modulo) if gcd(num, modulo) == 1)

    for g in range(1, modulo):
        actual_set = set(pow(g, powers) % modulo for powers in range (1, modulo))
        if required_set == actual_set:
            roots.append(g)     
    idx=random.randint(0,len(roots))      
    return roots[idx]

def generate_client_DH(server:socket.socket()):
    x=random.randint(1, 1024)
    p=generate_prime()
    g=primRoots(p)
    A=pow(g,x)%p

    
    # print(p,x,g,A)
    
    msg=""
    msg+=(str(p)+" ")
    msg+=(str(g)+" ")
    msg+=(str(A))
    # print("mmsssggg",msg)
    server.send(msg.encode()[:1024])
    B=(server.recv(1024).decode())
    
    sessionk=pow(int(B),x)%p
    # print(sessionk)
    with open(f"session_key/s{len(visited)}_DH_key","w") as f:
        f.write(str(sessionk))
        f.write("\n")       
    ("visited---",visited)
def generate_server_DH(p,g):
   y=random.randint(1, 1024)
   B=pow(g,y)%p
#    print("server-----",B)
   return B
   
    
# generate_client_DH(None)


    
           