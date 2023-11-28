from crypto_custom import hash

password = input("Enter password: ")
print("HASH: ", hash(password.encode()))
