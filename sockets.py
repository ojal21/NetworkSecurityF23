import socket
from threading import Thread, Lock
from crypto_custom import *
from file_utils import *
from json_util import *
from session_key_generation import *
import run_util
import uuid

MSG_SIZE = 1024

def send_user_auth(config: dict, broker: socket.socket, username, password) -> bool:
    # username = input('Enter username: ')
    # password = input('Enter password: ')
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

    auth_reply = decrypt(broker.recv(MSG_SIZE), cust_prv_key)
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

def process_client_messages(local_config: dict, broker: socket.socket, skey1:Fernet, skey3: Fernet) -> None:
    
    # Requesting to get product list from merchantA
    msg = jsonify("getProductList", {"merchantId": "merchantA"})
    print('===>Requesting products from merchantA', msg)
    broker.send(skey1.encrypt(msg))
    # Receive product list
    op, products = decode_message(skey1.decrypt(broker.recv(MSG_SIZE)))
    assert op == "getProductList"   # expected message?
    print("<===Received products:", products)

    # decrypt merchant encryption skey3
    products = session_decode_object(products, skey3)

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
    msg_encrypted = session_encode_object({"product": selected_product, "quantity": 1}, skey3)
    msg = jsonify("checkoutProduct", msg_encrypted)
    print('===>Sending product checkout', msg)
    broker.send(skey1.encrypt(msg))

    # Receive purchase info for product checked out
    op, checkout_info_encrypted = decode_message(skey1.decrypt(broker.recv(MSG_SIZE)))
    assert op == "checkoutProduct"

    # decrypt merchant encryption skey3
    order = session_decode_object(checkout_info_encrypted, skey3)
    print("<===Received checkout_info:", order)

    print("==========ORDER DETAILS==========")
    print(f'{"ORDER ID: ":20} {order["orderId"]}')
    print(f'{"PRODUCT: ":20} {order["product"]}')
    print(f'{"AMOUNT: ":20} {order["amount"]}')

    choice = input('\nConfirm purchase? y/N: ')
    if choice.lower().strip() != 'y':
        print('You have decline this order. Thank you.')
        # TODO send message and close connection

    acc_no = input('Please enter your account number: ').strip()
    acc_name = input('Please enter account holder name: ').strip()

    # send payment info to broker for processing
    msg = jsonify("processPayment", {"orderId": order['orderId'], "accountNo": acc_no, "accountHolderName": acc_name})
    print('===>Sending payment information', msg)
    broker.send(skey1.encrypt(msg))

    # Receive purchase info for product checked out
    op, payment_response = decode_message(skey1.decrypt(broker.recv(MSG_SIZE)))
    assert op == "processPayment"

    # response can be 'Success' or 'Failed'
    if payment_response == 'Failed':
        print('PAYMENT FAILED')
        print('Please check your account for sufficient balance')

        broker.close()
        print("Connection to broker closed")
        return

    # error handling if neither 'Success' or 'Failed'
    if payment_response != 'Success':
        print('Something went wrong while processing payment; Please contact broker with your orderId')

        broker.close()
        print("Connection to broker closed")
        return

    # Success case
    # request for product file
    msg = jsonify("processDelivery", session_encode_object(order['orderId'], skey3))
    print('===>Requesting confirmation and product delivery', msg)
    broker.send(skey1.encrypt(msg))

    # Receive product
    op, delivery_response = decode_message(skey1.decrypt(broker.recv(MSG_SIZE)))
    product = session_decode_object(delivery_response, skey3)

    print('======Received product======')
    print(product)
    path = f'client/purchased/{username}/{order["orderId"]}_{order["product"]}'
    save_text_file(path, product)
    print('File has been saved to path:', path)

    # close client socket (connection to the server)
    broker.close()
    print("Connection to broker closed")

def handle_merchant_server(local_config: dict, broker:socket.socket, broker_addr:tuple) -> None:
    print(f"\nAccepted broker connection from {broker_addr}")

    # AUTH
    broker_pub_key = load_key_from_file('broker/keys/broker-public', False)
    merchant_private_key = load_key_from_file('merchant/keys/merchant-private', True)
    random_value = get_nonce()
    auth_bytes = broker.recv(MSG_SIZE)
    auth_msg = decrypt(auth_bytes, merchant_private_key)
    print('Auth message:', auth_msg)
    id = auth_msg[:7]
    challenge = auth_msg[7:]
    random_value = get_nonce()
    print('Random:', random_value, 'Length:', len(random_value))
    auth_reply = b'MerchantA' + challenge + random_value
    broker.send(encrypt(auth_reply, broker_pub_key))

    auth_final_msg = broker.recv(MSG_SIZE)
    auth_final_msg = decrypt(auth_final_msg, merchant_private_key)
    print('Auth final message:', auth_final_msg)

    if auth_final_msg == random_value:
        print(f'AUTH SUCCESS for broker: {broker_addr} as ID: {id}')
        broker.send(b'OK')     
    else:
        print(f'AUTH FAILED for broker: {broker_addr}')
        broker.send(b'NO')

    #MERCHANT- BROKER SESSION KEY        
    val= broker.recv(MSG_SIZE)

    session_key2,B=generate_server_DH(val,broker_pub_key,merchant_private_key)
    
    # #1 more msg to client B 
    broker.send(encrypt(B.encode(),broker_pub_key))
    print("sessionkkk---2---- server----",session_key2)
    
    #MERCHANT - CLIENT
    # print("merchant key recv--1--",broker.recv(MSG_SIZE).decode())
    vals=broker.recv(MSG_SIZE)

    session_key3,Bm=generate_server_DH(vals,None,merchant_private_key)
    print("k--3--- server----",session_key3)
    broker.send(Bm.encode())

    while True:
        request_bytes = broker.recv(MSG_SIZE)
        if request_bytes == b"":
            break
        request = session_key2.decrypt(request_bytes)

        print('------------------', request)
        op, data = decode_message(request)
        response = handle_msg_merchant(op, data, session_key3)

        broker.send(session_key2.encrypt(jsonify(op, response)))

    # close connection socket with the socket client
    broker.close()
    print(f"Connection to BROKER {broker_addr} closed")

def handle_msg_merchant(operation: str, data: object, skey3: Fernet) -> bytes:
    print('====>Received request for operation:', operation)
    response = None
    match operation:
        case "getProductList":
            path = "merchant/products"
            products = get_files_in_directory(path)
            print('Current product list:', products)
            response = session_encode_object(products, skey3)
        case "checkoutProduct":
            data = session_decode_object(data, skey3)
            product = data["product"]
            # TODO verify if payment exists?
            broker_msg, client_msg = create_order(product)
            client_msg = session_encode_object(client_msg, skey3)
            # informing both in one message
            response = {"broker": broker_msg, "client": client_msg}
        case "processPayment":
            order_id = data["orderId"]
            status = data["status"]
            print(f'Received payment status as {status} for order {order_id}')
            update_order_status(order_id, status)
            response = "OK"
        case "processDelivery":
            data = session_decode_object(data, skey3)
            product_data = get_product_data_by_order(data)
            # TODO padding for content
            response = session_encode_object(product_data, skey3)

    if not response:
        print('WARNING: Sending empty response')
    print('<====Sending response for operation:', operation)
    return response

def get_product_data_by_order(order_id: str) -> str:
    # read order info
    # TODO validate order info
    order_path = 'merchant/orders/' + order_id
    order = load_json_file(order_path)
    product = get_file_contents('merchant/products/' + order['product'])
    # update order as delivered
    order['status'] = "DELIVERED"
    write_json_file(order, order_path)
    return product

# CREATE ORDER AT MERCHANT
def create_order(product: str):
    # TODO fix amount from broker config
    order_id = str(uuid.uuid4())
    orderForBroker = {"orderId": order_id, "amount": 200, "status": "PAYMENT_PENDING"}
    orderForClient = {"orderId": order_id, "product": product, "amount": 200, "status": "PAYMENT_PENDING"}
    # Store order info
    write_json_file(orderForClient, "merchant/orders/" + order_id)
    return orderForBroker, orderForClient

# SAVE ORDER AT BROKER
def save_order(order: dict) -> None:
    write_json_file(order, "broker/orders/" + order["orderId"])

# UPDATE ORDER AT MERCHANT
def update_order_status(order_id: str, status:str) -> None:
    path = "merchant/orders/" + order_id
    account_info = load_json_file(path)
    account_info['status'] = status
    write_json_file(account_info, path)

def handle_broker_server(local_config: dict, client:socket.socket, client_addr:tuple, merchant:socket.socket, skey2: Fernet) -> None:
    print(f"\nAccepted CLIENT connection from {client_addr}")

    # auth handling
    broker_prv_key = load_key_from_file('broker/keys/broker-private', True)
    auth_bytes = client.recv(MSG_SIZE)
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

    #CLIENT- BROKER SESSION KEY        
    val=client.recv(MSG_SIZE)
    print("vallll",val)
    session_key1,B=generate_server_DH(val,cust_pub_key,broker_prv_key)
    
    # #1 more msg to client B 
    client.send(encrypt(B.encode(),cust_pub_key))
    
    print("sessionkkk--1-- server----",session_key1)
    
    #CLIENT - MERCHANT SESSION KEY => RELAY
    merchant.send(client.recv(MSG_SIZE))
    client.send(merchant.recv(MSG_SIZE))

    op1, product_list_req = decode_message(session_key1.decrypt(client.recv(MSG_SIZE)))
    # identify merchant:
    merchantId = product_list_req["merchantId"]
    print('===>Contacting:', merchantId)

    # get from merchant
    merchant.send(skey2.encrypt(jsonify("getProductList", "")))
    op2, product_list = decode_message(skey2.decrypt(merchant.recv(MSG_SIZE)))
    assert op2 == "getProductList"

    # send list to client
    print('<===Sending product list to client')
    client.send(session_key1.encrypt(jsonify(op1, product_list)))

    # productCheckout
    op1, checkout_req = decode_message(session_key1.decrypt(client.recv(MSG_SIZE)))
    # TODO how to know which merchant it wants to connect to?
    print('===>Contacting:', merchantId)

    # get ORDER INFO from merchant
    merchant.send(skey2.encrypt(jsonify(op1, checkout_req)))
    op2, checkout_resp = decode_message(skey2.decrypt(merchant.recv(MSG_SIZE)))
    orderInfo = checkout_resp["broker"]
    save_order(orderInfo)
    client_msg = checkout_resp["client"]
    assert op2 == op1

    # send list to client
    print('<===Sending checkout response to client')
    client.send(session_key1.encrypt(jsonify(op1, client_msg)))

    # processPayment
    op1, payment_req = decode_message(session_key1.decrypt(client.recv(MSG_SIZE)))
    success = process_payment(local_config, payment_req, orderInfo)

    if not success:
        # TODO inform merchant payment failed
        # TODO update order file
        print('PAYMENT FAILED')
        client.send(session_key1.encrypt(jsonify(op1, 'Success')))
        client.close()
        print(f"Connection to CLIENT {client_addr} closed")

    # success case
    orderInfo['status'] = "PAYMENT_SUCCESS"
    # TODO update orderinfo file
    merchant.send(skey2.encrypt(jsonify(op1, orderInfo)))
    op2, merchant_resp = decode_message(skey2.decrypt(merchant.recv(MSG_SIZE)))
    assert op1 == op2

    if merchant_resp == 'OK':
        print('Payment acknowledged by merchant')

    client.send(session_key1.encrypt(jsonify(op1, 'Success')))

    # processDelivery
    op1, delivery_req = decode_message(session_key1.decrypt(client.recv(MSG_SIZE)))
    merchant.send(skey2.encrypt(jsonify(op1, delivery_req)))
    op2, delivery_resp = decode_message(skey2.decrypt(merchant.recv(MSG_SIZE)))
    client.send(session_key1.encrypt(jsonify(op1, delivery_resp)))

    # close connection socket with the client
    client.close()
    print(f"Connection to CLIENT {client_addr} closed")

# Broker checks for sufficient balance and processes payment
def process_payment(config: dict, request: dict, order: dict) -> bool:
    broker_account_no = config['account']
    merchant_account_no = config['merchant.account']
    client_account_no = request['accountNo']
    account_path = 'broker/accounts/'
    try:
        with (lock):
            # read account information
            broker_acc = load_json_file(account_path + broker_account_no)
            merchant_acc = load_json_file(account_path + merchant_account_no)
            client_acc = load_json_file(account_path + client_account_no)

            # verify balance
            amount = order['amount']
            if client_acc['balance'] < amount:
                print('Insufficient Balance')
                return False

            # success processing
            # update account balances
            broker_share = int(config['share'])/100
            merchant_share = 1 - broker_share
            broker_acc['balance'] = broker_acc['balance'] + broker_share * amount
            merchant_acc['balance'] = merchant_acc['balance'] + merchant_share * amount
            client_acc['balance'] = client_acc['balance'] - amount

            # write updated account info
            write_json_file(broker_acc, account_path + broker_account_no)
            write_json_file(merchant_acc, account_path + merchant_account_no)
            write_json_file(client_acc, account_path + client_account_no)

    except FileNotFoundError:
        print('Account not found!')
        return False

    print('Payment Success for order:', order['orderId'])
    return True


def authenticate_merchant(config: dict, merchant: socket.socket) -> None:
    broker_prv_key = load_key_from_file('broker/keys/broker-private', True)
    merch_pub_key = load_key_from_file('merchant/keys/merchant-public', False)
    random_value = get_nonce()
    print('Random:', random_value, 'Length:', len(random_value))
    merchant.send(encrypt(b'brokerA' + random_value, merch_pub_key))
    auth_resp = merchant.recv(MSG_SIZE)
    
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
        return generate_client_DH(merchant,merch_pub_key,broker_prv_key)
    else:
        print('AUTH FAILED')
        return None
    

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

                skey_2=authenticate_merchant(local_config, merchant_socket)
                print("session--2---",skey_2)
                broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                broker_socket.bind((ip_addr, int(port)))
                broker_socket.listen(5)    # 5 connections possible to this port
                lock = Lock()

                while True:
                    client_socket, client_address = broker_socket.accept()
                    # Handle Parallel connections
                    threads = Thread(target=handle_broker_server, args=(local_config, client_socket, client_address, merchant_socket, skey_2), daemon=True)
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

                username = input('Enter username: ')
                password = input('Enter password: ')
                success = send_user_auth(local_config, broker_socket,username,password)
                if success:
                    #dh
                    broker_pub_key = load_key_from_file('broker/keys/broker-public', False)
                    cust_prv_key = load_key_from_file(f'client/keys/{username}-private', True)
                    merch_pub_key = load_key_from_file('merchant/keys/merchant-public', False)     
                    
                    sk_broker=generate_client_DH(broker_socket,broker_pub_key,cust_prv_key)#return as session - client end
                    sk_merchant = None
                    if sk_broker:
                        sk_merchant=generate_client_DH(broker_socket,merch_pub_key,None)
                    # TODO: what if key1 and key3 are not proper? Exception?

                    #pass key to process
                    process_client_messages(local_config, broker_socket,sk_broker, sk_merchant)
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
