from crypto_custom import hash
from json_util import *
import rsa

file_path = "broker/passwords.json"
key_path = "client/keys"

password_list = load_json_file(file_path)
username = input("Enter username: ")

if password_list.get(username, None):
    print("Username already exists")
    exit(1)

password = input("Enter password: ")
pwd_hash = hash(password.encode())

password_list[username] = pwd_hash
write_json_file(password_list, file_path)

print("------ADDED BELOW ENTRY-------")
print("USERNAME:", username)
print("HASH: ", pwd_hash)

public_key_c1, private_key_c1 = rsa.newkeys(2048)

with open(f"{key_path}/{username}-public", "wb") as f:
    f.write(public_key_c1.save_pkcs1("PEM"))

with open(f"{key_path}/{username}-private", "wb") as f:
    f.write(private_key_c1.save_pkcs1("PEM"))
