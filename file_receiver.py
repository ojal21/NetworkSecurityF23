import socket
import tqdm
import rsa

from Crypto.Cipher import AES

#16 bytes
# key=b"TheNeuralNineKey"
# nonce=b"TheNeuralNineNcn"


# cipher=AES.new(key,AES.MODE_EAX,nonce) 

server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(('localhost',9999))
server.listen()
# with open("broker_private.pen","rb") as f:
#     private_key=rsa.PrivateKey.load_pkcs1(f.read())
    
client,addr=server.accept()

file_name=client.recv(1024).decode()
print(file_name)
# file_size=client.recv(1024).decode()
# print(file_size)

file=open(file_name,"wb")

done=False
file_bytes=b""

# progress=tqdm.tqdm(unit="B",unit_scale=True,unit_divisor=1000,total=int(file_size))

while not done:
    data=client.recv(1024)
   
    if file_bytes[-5:]==b"<END>":
        done=True 
    else:
        file_bytes+=data
    # progress.update(1024)
i=0
while i<30:
    print(file_bytes[i:i+5])
    if file_bytes[i:i+6]==b"<DONE>":
        print("done")
        break
    i+=1
    
# file.write(rsa.decrypt(file_bytes,private_key))
file.write(file_bytes[:i])
file.close()
client.close()
server.close()
