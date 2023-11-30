import socket
from threading import Thread
from crypto_custom import *
from file_utils import *
from json_util import *
from session_key_generation import *
import run_util

def send_user_auth(config: dict, broker: socket.socket) -> bool:
    username = input('Enter username: ')
    password = input('Enter password: ')
    random = get_nonce()

    broker_pub_key = load_key_from_file('broker/keys/broker-public', False)
    cust_prv_key = load_key_from_file(f'client/keys/{username}-private', True)

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
    msg = jsonify("checkoutProduct", {"product": selected_product, "quantity": 1})
    print('===>Sending product checkout', msg)
    broker.send(msg)

    # Receive purchase info for product checked out
    op, checkout_info = decode_message(broker.recv(1024))
    assert op == "checkoutProduct"   # expected message?
    print("<===Received checkout_info:", checkout_info)

    '''
    checkout_info will contain:
    1. Unique Txn ID?
    2. Product Info?   (required again?)
    3. Purchase amount for product
    x. do we need to double check selected product? usually client generates a txn ID so that itself verifies the product
    '''

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

def handle_msg_merchant(operation: str, data: object) -> bytes:
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
    if not response:
        print('WARNING: Sending empty response')
    print('<====Sending response for operation:', operation)
    return response



def handle_broker_server(local_config: dict, client:socket.socket, client_addr:tuple, merchant:socket.socket) -> None:
    print(f"\nAccepted CLIENT connection from {client_addr}")

    # auth handling
    broker_prv_key = load_key_from_file('broker/keys/broker-private', True)
    
    auth_bytes = client.recv(1024)
    id = auth_bytes[:7]
    auth_msg = decrypt(auth_bytes[7:], broker_prv_key)

    auth_details = auth_msg.split(b'::')
    username = auth_details[0].decode()
    password = auth_details[1].decode()
    cust_pub_key = load_key_from_file(f'client/keys/{username}-public', False)
  
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
#broker DH
        
    val= client.recv(1024).decode() 
    print("vallll",val)
    p,g,A=val.split()
    B=generate_server_DH(int(p),int(g))
    print("p,g,A",p,g,A,B)
    client.send(f"{B}".encode())
    
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
                    #dh
                    generate_client_DH(broker_socket)
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
