import socket
from threading import Thread
from crypto_custom import *
from file_utils import *
from json_util import *
import run_util
import uuid

def send_user_auth(config: dict, broker: socket.socket) -> bool:
    username = input('Enter username: ')
    password = input('Enter password: ')
    random = get_nonce()

    broker_pub_key = load_key_from_file('broker/keys/broker-public', False)
    cust_prv_key = load_key_from_file('client/keys/client1-private', True)

    message = b'::'.join([username.encode(), hash(password.encode()).encode(), random])
    print('Auth message: ', message)
    message = b'client1' + encrypt(message, broker_pub_key)
    # TODO: how is the client ID going to be picked up, cmdline args?

    '''
    client ID is to identify the whitelisted system and its key at broker's end
    (Alternative: try parsing at broker: all registered client public keys, which ever matches is good)

    Situation: A user can have multiple devices, each having different RSA key pairs. We should be able to communicate with any system the user chooses and eventually authenticate the user by username and password
    '''

    broker.send(message)

    auth_reply = decrypt(broker.recv(1024), cust_prv_key)
    random_reply = auth_reply[:32]
    verify_reply = auth_reply[32:]

    print(f'random_reply: {random_reply} verify_response: {verify_reply}')

    if random == random_reply and verify_reply == b'SUCCESS':
        print('Random challenge verified; Username and password verified')
        return True
    else:
        if random != random_reply:
            print(f'Incorrect challenge reply, Expected: {random} but Received: {random_reply}')
        else:
            print('Received verification result from broker:', verify_reply)
        return False

def verify_username_password(file_path: str, username: str, password: str) -> bool:
    passwords = load_json_file(file_path)
    return passwords.get(username, None) == password

def process_client_messages(local_config: dict, broker: socket.socket) -> None:
    # Requesting to get product list from merchantA
    msg = jsonify("getProductList", {"merchantId": "merchantA"})
    print('===>Requesting products from merchantA', msg)
    broker.send(msg)

    # Receive product list
    op, products = decode_message(broker.recv(1024))
    assert op == "getProductList"   # expected message?
    print("<===Received products:", products)

    total_products = len(products)
    print("\nPlease select product to purchase: ")
    for i in range(total_products):
        print(f'{i+1:<2} {products[i]}')    # TODO: need to split product neatly to name, price, description?

    choice = int(input('\nEnter choice:'))    # ERROR handling for non number
    if choice <= 0 or choice > total_products:
        print('Invalid choice')     # ERROR handling
        # TODO: exit?

    selected_product = products[choice-1]   # -1 for indexing
    print('You have chosen product:', selected_product)
    print('Please wait------------')

    # checkout selected product
    customer_account_number = input('\nEnter account number:')
    msg = jsonify("checkoutProduct", {"product": selected_product, "quantity": 1, "accountNumber": customer_account_number })
    
    print('===>Sending product checkout', msg)
    broker.send(msg)
    
    # Receive purchase info for product checked out
    op, checkout_info = decode_message(broker.recv(1024))
    assert op == "checkoutProduct"   # expected message?
    print("<===Received checkout_info:", checkout_info)

    
    msg = jsonify("transId", { "transaction_Id": current_transaction_id })
    print('===>Sending t_id', msg)
    broker.send(msg)
   
    # Receive tid info for product checked out
    op, rec_t_id = decode_message(broker.recv(1024))
    assert op == "transId"  
   
    print("<===Received t_id:", rec_t_id)
    
    # Simulated payment amount for the selected product
    payment_amount = 100 

    # Simulate payment process
    broker_instance = Broker() 
    # Process payment
    payment_processed = broker_instance.process_payment(customer_account_number, payment_amount)

    if payment_processed:
        print("Payment successful!")
        # Proceed with other actions after successful payment, if needed
    else:
        print("Payment failed due to insufficient balance or invalid account number.")
        # Handle the failure scenario
    
    while True:
        # input message and send it to the server
        msg = input("Enter message: ")
        broker_socket.send(msg.encode()[:1024])

        # receive message from the server
        response = broker_socket.recv(1024)
        response = response.decode()

        print(f"Received: {response}")

        # if server sent us "closed" in the payload, we break out of the loop and close our socket
        if response.lower() == "closed":
            break

    # close client socket (connection to the server)
    broker.close()
    print("Connection to broker closed")

def handle_merchant_server(local_config: dict, broker:socket.socket, broker_addr:tuple) -> None:
    print(f"\nAccepted broker connection from {broker_addr}")

    # AUTH
    broker_pub_key = load_key_from_file('broker/keys/broker-public', False)
    merchant_private_key = load_key_from_file('merchant/keys/merchant-private', True)
    random_value = get_nonce()
    auth_bytes = broker.recv(1024)
    auth_msg = decrypt(auth_bytes, merchant_private_key)
    print('Auth message:', auth_msg)
    id = auth_msg[:7]
    challenge = auth_msg[7:]
    random_value = get_nonce()
    print('Random:', random_value, 'Length:', len(random_value))
    auth_reply = b'MerchantA' + challenge + random_value
    broker.send(encrypt(auth_reply, broker_pub_key))

    auth_final_msg = broker.recv(1024)
    auth_final_msg = decrypt(auth_final_msg, merchant_private_key)
    print('Auth final message:', auth_final_msg)

    if auth_final_msg == random_value:
        print(f'AUTH SUCCESS for broker: {broker_addr} as ID: {id}')
        broker.send(b'OK')
    else:
        print(f'AUTH FAILED for broker: {broker_addr}')
        broker.send(b'NO')

    while True:
        request = broker.recv(1024)
        # TODO check if we still need "close" and "closed" pairs
        if request == b"close":
            broker.send(b"closed")
        if request == b"":
            break

        op, data = decode_message(request)
        response = handle_msg_merchant(op, data)

        broker.send(jsonify(op, response))

    # close connection socket with the socket client
    broker.close()
    print(f"Connection to BROKER {broker_addr} closed")

current_transaction_id = None
def generate_transaction_id():          # Generate a unique transaction ID using UUID4
    ts_id = uuid.uuid4()
    return str(ts_id)          # Convert UUID to string if needed

def create_transaction_id_file():
    global current_transaction_id
    t_id = generate_transaction_id()
    file_name = f"{t_id}.txt"
    file_path = os.path.join('merchant/transactions', file_name)
    with open(file_path, 'w') as file:
        # Write something into the file if needed
        file.write(f"Transaction ID: {t_id}\n")
    current_transaction_id = t_id
    return t_id 



def handle_msg_merchant(operation: str, data: object) -> bytes:
    global current_transaction_id
    create_transaction_id_file()
    print('====>Received request for operation:', operation)
    response = None
    match operation:
        case "getProductList":
            path = "merchant/products"
            products = getFilesInDirectory(path)
            print('Current product list:', products)
            response = products
        case "checkoutProduct":
            product = data["product"]
            path = "merchant/products/" + product
            response = getFileContents(path)
        case "transId":
            if current_transaction_id is not None:
                path = f"merchant/transactions/{current_transaction_id}.txt"
                response = getFilename(path)
            else:
                response = "No transaction ID available"           
    if not response:
        print('WARNING: Sending empty response')
    print('<====Sending response for operation:', operation)
    
    return response

def getFilename(path):
    path_components = path.split('/')
    file_name_and_extension = path_components[-1].rsplit('.', 1)
    return file_name_and_extension[0]

 

def handle_broker_server(local_config: dict, client:socket.socket, client_addr:tuple, merchant:socket.socket) -> None:
    print(f"\nAccepted CLIENT connection from {client_addr}")

    # auth handling
    broker_prv_key = load_key_from_file('broker/keys/broker-private', True)
    cust_pub_key = load_key_from_file('client/keys/client1-public', False)
    auth_bytes = client.recv(1024)
    id = auth_bytes[:7]
    auth_msg = decrypt(auth_bytes[7:], broker_prv_key)

    auth_details = auth_msg.split(b'::')
    username = auth_details[0].decode()
    password = auth_details[1].decode()
    challenge = auth_details[2] if len(auth_details) == 3 else b''.join(auth_details[3:])
    print(f'id: {id}, username: {username}, password: {password}, challenge: {challenge}')

    verified = verify_username_password(local_config["passwords_file"], username, password)
    if verified:
        print('Verified username and password')
        reply = challenge + b'SUCCESS'
        client.send(encrypt(reply, cust_pub_key))
    else:
        print('Did not find a matching username and password')
        reply = challenge + b'FAILED'
        client.send(encrypt(reply, cust_pub_key))
        # close connection socket with the client
        client.close()
        print(f"Connection to CLIENT {client_addr} closed")
        return  #end processing this thread

    # getProductList
    op1, productListReq = decode_message(client.recv(1024))
    # identify merchant:
    merchantId = productListReq["merchantId"]
    print('===>Contacting:', merchantId)

    # get from merchant
    merchant.send(jsonify("getProductList", ""))
    op2, productList = decode_message(merchant.recv(1024))
    assert op2 == "getProductList"

    # send list to client
    print('<===Sending product list to client')
    client.send(jsonify(op1, productList))

    # productCheckout
    op1, checkoutReq = decode_message(client.recv(1024))
    # TODO how to know which merchant it wants to connect to?
    print('===>Contacting:', merchantId)
    
    # get from merchant
    merchant.send(jsonify(op1, checkoutReq))
    op2, checkoutResp = decode_message(merchant.recv(1024))
    assert op2 == op1

    # send list to client   
    print('<===Sending checkout response to client')
    client.send(jsonify(op1, checkoutResp))

   # TransactionId
    op1, transactionIdReq = decode_message(client.recv(1024))
    # TODO how to know which merchant it wants to connect to?
    print('===>Contacting:', merchantId)
    
    # get from merchant
    merchant.send(jsonify(op1, transactionIdReq))
    op2, transId = decode_message(merchant.recv(1024))
    assert op2 == op1

    # send list to client   
    print('<===Sending transactionId to client')
    client.send(jsonify(op1, transId))

    while True:
        request_bytes = client.recv(1024)    # TODO: Max length????
        request = request_bytes.decode()

        # if we receive "close" from the client, then we break
        # out of the loop and close the conneciton
        # TODO: only for test
        if request.lower() == "close":
            # send response to the client which acknowledges that the
            # connection should be closed and break out of the loop
            client.send("closed".encode())

        if request == "":
            break

        print(f"Received: {request}")
        # input message and send it to the server
        msg = input("Enter message: ")

        response = msg.encode()
        client.send(response)

    # close connection socket with the client
    client.close()
    print(f"Connection to CLIENT {client_addr} closed")

def authenticate_merchant(config: dict, merchant: socket.socket) -> None:
    broker_prv_key = load_key_from_file('broker/keys/broker-private', True)
    merch_pub_key = load_key_from_file('merchant/keys/merchant-public', False)
    random_value = get_nonce()
    print('Random:', random_value, 'Length:', len(random_value))
    merchant.send(encrypt(b'brokerA' + random_value, merch_pub_key))
    auth_resp = merchant.recv(1024) #TODO: verify
    
    # ID + mychallenge + newchallenge
    auth_resp = decrypt(auth_resp, broker_prv_key)
    print('Auth Received: ', auth_resp)
    id = auth_resp[:9]
    print('id:', id)
    challenge_recv = auth_resp[9:32+9]
    if(random_value == challenge_recv):
        print('Received correct challege back')
    else:
        print('incorrect challenge', 'expected:', random_value, 'received:', challenge_recv)
    challenge = auth_resp[32+9:]

    merchant.send(encrypt(challenge, merch_pub_key))
    auth_reply = merchant.recv(10)

    if auth_reply == b'OK':
        print('AUTH SUCCESS')
    else:
        print('AUTH FAILED')

class Broker:
    def __init__(self):
        # Broker's and Merchant's shares in the transaction (in percentages)
        self.broker_share_percentage = 20  
        self.merchant_share_percentage = 80  

        # Define file names for broker and merchant accounts
        self.broker_file_name = '000.txt'
        self.merchant_file_name = '333.txt'

        # Define base path for file locations
        self.base_path = 'broker/accounts/'
      
        # File locations for broker and merchant accounts
        self.broker_file_location = self.base_path + self.broker_file_name
        self.merchant_file_location = self.base_path + self.merchant_file_name

    def validate_account_and_balance(self, account_number, total_amount):
        # Check if account file exists and has sufficient balance
        filename = f"{self.base_path}{account_number}.txt"
        try:
            with open(filename, 'r') as file:
                balance = float(file.read().strip())
                if balance >= total_amount:
                    return True
                else:
                    return False
        except FileNotFoundError:
            return False

    def update_balance_in_file(self, filename, new_balance):
        with open(filename, 'w') as file:
            file.write(str(new_balance))

    def process_payment(self, account_number, total_amount):
        filename = f"{self.base_path}{account_number}.txt"
        if self.validate_account_and_balance(account_number, total_amount):
            try:
                # Subtract total amount from customer's account
                with open(filename, 'r+') as file:
                    balance = float(file.read().strip())
                    file.seek(0)
                    file.truncate()
                    file.write(str(balance - total_amount))

                # Calculate shares for broker and merchant
                broker_share = (self.broker_share_percentage / 100) * total_amount
                merchant_share = (self.merchant_share_percentage / 100) * total_amount

                # Update broker's balance
                with open(self.broker_file_location, 'r+') as broker_file:
                    broker_balance = float(broker_file.read().strip())
                    broker_file.seek(0)
                    broker_file.truncate()
                    broker_file.write(str(broker_balance + broker_share))

                # Update merchant's balance
                with open(self.merchant_file_location, 'r+') as merchant_file:
                    merchant_balance = float(merchant_file.read().strip())
                    merchant_file.seek(0)
                    merchant_file.truncate()
                    merchant_file.write(str(merchant_balance + merchant_share))

                return True  # Payment processed successfully
            except FileNotFoundError:
                return False  # File not found or unable to update balances
        else:
            return False  # Insufficient balance or invalid account number


if __name__ == '__main__':
    try:
        config = run_util.load_config()
        args = run_util.load_args()

        mode = args.mode
        ip_addr = args.ip if args.ip else config[mode]['ip_addr']
        port = args.port if args.port else config[mode]['port']

        print(f'---------ATTEMPTING TO RUN AS {mode} -----------')

        merchant_socket = None
        broker_socket = None
        threads = None

        match mode:
            case 'broker':
                '''
                =====================BROKER===================
                '''
                print(mode, 'IP:', ip_addr, 'Port:', port, '\n')
                
                local_config = config['broker']
                merchant_addr = local_config['merchant.ip']
                merchant_port = local_config['merchant.port']

                merchant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                merchant_socket.connect((merchant_addr, int(merchant_port)))
                print(f"Connected to merchant at: {merchant_addr}:{merchant_port}")

                authenticate_merchant(local_config, merchant_socket)

                broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                broker_socket.bind((ip_addr, int(port)))
                broker_socket.listen(5)    # 5 connections possible to this port

                while True:
                    client_socket, client_address = broker_socket.accept()
                    # Handle Parallel connections
                    threads = Thread(target=handle_broker_server, args=(local_config, client_socket, client_address, merchant_socket), daemon=True)
                    threads.start()

            case 'client':
                '''
                ===================CLIENT==================
                '''
                print(mode, 'IP:', ip_addr, 'Port:', port, '\n')

                # read config to get broker address
                local_config = config['client']
                broker_addr = local_config['broker.ip']
                broker_port = local_config['broker.port']

                # connect to broker
                broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                broker_socket.connect((broker_addr, int(broker_port)))
                print(f"Connected to broker at {broker_addr}:{broker_port}")

                success = send_user_auth(local_config, broker_socket)
                if success:
                    process_client_messages(local_config, broker_socket)
                else:
                    print("ERROR: Incorrect username or password")

            case 'merchant':
                '''
                ===================MERCHANT================
                '''
                print(mode, 'IP:', ip_addr, 'Port:', port, '\n')

                # listen refers to a socket object
                merchant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                merchant_socket.bind((ip_addr, int(port)))
                merchant_socket.listen(5)    # 5 connections possible to this port

                # get connections
                while True:
                    broker_socket, broker_address = merchant_socket.accept()
                    handle_merchant_server(config['merchant'], broker_socket, broker_address)

    except KeyboardInterrupt:
        print("\nClosing due to CTRL+C from user")
        if mode == 'client' and broker_socket != None:
            broker_socket.close()
            print("Closed Client connection to Broker")

    finally:
        # connection clean-up
        if mode == 'merchant' and merchant_socket:
            merchant_socket.close()
            print("Closed Merchant Listening Socket")
        if mode == 'broker' and broker_socket:
            broker_socket.close()
            print("Closed Broker Listening Socket")
            if threads:
                threads.join()
