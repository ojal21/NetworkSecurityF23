import rsa

pubkey, privkey = rsa.newkeys(2048)

message = b"my top secret, but can i make very very long? let's test it out!"
path = input("Enter path upto filename: (public/private prefix will be added): ")

saver1 = pubkey.save_pkcs1()
print(saver1)
with open(path + "-public", "wb") as keyfile:
    keyfile.write(saver1)
saver2 = privkey.save_pkcs1()
print(saver2)
with open(path + "-private", "wb") as keyfile:
    keyfile.write(saver2)

crypto = rsa.encrypt(message, pubkey)
decrypt = rsa.decrypt(crypto, privkey)

print(crypto)
print(decrypt)
