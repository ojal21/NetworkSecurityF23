import os
import socket

from Crypto.Cipher import AES
import rsa
#16 bytes
# key=b"TheNeuralNineKey"
# nonce=b"TheNeuralNineNcn"

# with open("broker_public.pen","rb") as f:
#     public_key=rsa.PublicKey.load_pkcs1(f.read())
# cipher=AES.new(key,AES.MODE_EAX,nonce) 

client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect(('localhost',9999))

file_size=os.path.getsize("file.txt") 

if file_size<30:
    with open("file.txt","a")  as f: 
        f.write('<DONE>')
        for i in range(30-6-file_size):
            f.write('*')
   

with open("file.txt","rb")  as f:
    data=f.read()
    
# encrypted=cipher.encrypt(data)
# encrypted= rsa.encrypt(data,public_key
client.send("file_recv.txt".encode())
print("ffiiilllleeee ssiiizzeee------------",file_size)
# client.send(str(file_size).encode())
client.sendall(data)
client.send(b"<END>")

client.close()


