import socket
from threading import Thread, Lock
from crypto_custom import *
from file_util import *
from json_util import *
import run_util
import uuid

MSG_SIZE = 2048

# CLIENT APP: Authenticate user with broker; return session keys if success
def authenticate_user(config: dict[str, str], broker: socket.socket) -> tuple:
    username = input('Enter username: ')
    password = input('Enter password: ')
    random = get_nonce()

    broker_pub_key = load_key_from_file(config['broker.pubkey'], False)
    merch_pub_key = load_key_from_file('merchant/keys/merchant-public', False)
    cust_prv_key = load_key_from_file(config['prvkey'].format(user = username), True)

    message = b'::'.join([username.encode(), hash(password.encode()).encode(), random])
    broker.send(rsa_encrypt(message, broker_pub_key))

    auth_reply = rsa_decrypt(broker.recv(MSG_SIZE), cust_prv_key)
    random_reply = auth_reply[:32]
    verify_reply = auth_reply[32:]

    # print(f'random_reply: {random_reply} verify_response: {verify_reply}')

    if random == random_reply and verify_reply == b'SUCCESS':
        print('Random challenge verified; Username and password verified')
    else:
        if random != random_reply:
            print(f'Incorrect challenge reply, Expected: {random} but Received: {random_reply}')
        else:
            print('Received verification result from broker:', verify_reply)
        return None, None, None

    # success
    # create DH session keys
    # DH session key 1 (Client-Broker)
    p, g, x1, x2, A1, A2, msg = generate_DH_params()
    broker_socket.send(rsa_encrypt(msg.encode(), broker_pub_key))
    B1, B2 = rsa_decrypt(broker_socket.recv(MSG_SIZE), cust_prv_key).decode().split()
    sk_broker = generate_client_DH(p, g, x1, x2, A1, A2, B1, B2)

    # DH session key 3 (Client-Merchant)
    p, g, x1, x2, A1, A2, msg = generate_DH_params()
    msg_enc = base64.b64encode(rsa_encrypt(msg.encode(), merch_pub_key)).decode()
    msg_dh3 = jsonify("getUserSession", {"broker": "merchantA", "merchant": msg_enc})
    broker_socket.send(aes_encrypt(sk_broker, msg_dh3))
    _, B, _ = decode_message(aes_decrypt(sk_broker, broker_socket.recv(MSG_SIZE)))
    B1, B2 = B.split()
    sk_merchant = generate_client_DH(p, g, x1, x2, A1, A2, B1, B2)

    return sk_broker, sk_merchant, username

def verify_username_password(file_path: str, username: str, password: str) -> bool:
    passwords = load_json_file(file_path)
    return passwords.get(username, None) == password

# SIMULATE A CLIENT APP
def process_client_messages(local_config: dict, broker: socket.socket, skey1: bytes, skey3: bytes, username: str) -> None:

    # Requesting to get product list from merchantA
    msg = jsonify("getProductList", {"merchantId": "merchantA"})
    print('===>Requesting products from merchant')
    broker.send(aes_encrypt(skey1, msg))
    # Receive product list
    op, products, _ = decode_message(aes_decrypt(skey1, broker.recv(MSG_SIZE)))
    assert op == "getProductList"
    print("<===Received product list")     #, products)

    # decrypt merchant encryption skey3
    products = session_decode_object(products, skey3)

    total_products = len(products)
    print("\nPlease select product to purchase: ")
    for i in range(total_products):
        print(f'{i+1:<2} {products[i]}')

    # user gets one retry to select a valid product
    try:
        choice = int(input('\nEnter choice:'))
    except:
        choice = None
    if choice is None or choice <= 0 or choice > total_products:
        print('Invalid choice')
        # below gives user one more chance to enter a valid choice
        try:
            choice = int(input('\nEnter choice:'))
        except:
            choice = None
        if choice is None or choice <= 0 or choice > total_products:
            print('Invalid choice; Exiting session')
            broker.close()
            print("Connection to broker closed")
            return

    selected_product = products[choice-1]   # -1 for indexing
    print('\nYou have chosen product:', selected_product)

    # checkout selected product
    msg_encrypted = session_encode_object({"product": selected_product, "quantity": 1}, skey3)
    msg = jsonify("checkoutProduct", msg_encrypted)
    print('Placing order; Please wait -------')
    broker.send(aes_encrypt(skey1, msg))

    # Receive purchase info for product checked out
    op, checkout_info_encrypted, _ = decode_message(aes_decrypt(skey1, broker.recv(MSG_SIZE)))
    assert op == "checkoutProduct"

    # decrypt merchant encryption skey3
    order = session_decode_object(checkout_info_encrypted, skey3)

    print("==========ORDER DETAILS==========")
    print(f'{"ORDER ID: ":20} {order["orderId"]}')
    print(f'{"PRODUCT: ":20} {order["product"]}')
    print(f'{"AMOUNT: ":20} {order["amount"]}')

    choice = input('\nConfirm purchase? y/N: ')
    if choice.lower().strip() != 'y':
        print('You have declined this order. Thank you.')
        # inform broker about this
        msg = jsonify("processPayment", {"orderId": 'cancelled'})
        broker.send(aes_encrypt(skey1, msg))
        broker.close()
        print("Connection to broker closed")
        return

    acc_no = input('Please enter your account number: ').strip()
    acc_name = input('Please enter account holder name: ').strip()

    # send payment info to broker for processing
    msg = jsonify("processPayment", {"orderId": order['orderId'], "accountNo": acc_no, "accountHolderName": acc_name})
    print('===>Processing payment; Please wait-------')
    broker.send(aes_encrypt(skey1, msg))

    # Receive purchase info for product checked out
    op, payment_response, _ = decode_message(aes_decrypt(skey1, broker.recv(MSG_SIZE)))
    assert op == "processPayment"

    # response can be 'Success' or 'Failed'
    if payment_response == 'Failed':
        print('PAYMENT FAILED')
        print('Please check your account credentials and/or balance')

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
    print('<===Payment successful')
    msg = jsonify("processDelivery", session_encode_object(order['orderId'], skey3))
    print('===>Requesting confirmation and product delivery')
    broker.send(aes_encrypt(skey1, msg))

    # Receive product
    op, delivery_response, _ = decode_message(aes_decrypt(skey1, broker.recv(MSG_SIZE)))
    product = base64.b64decode(session_decode_object(delivery_response, skey3))

    print('<======Received product======')
    success = verify_file_hash(product)
    print('File integrity verification:', success)

    if success:
        path = f'client/{username}/{order["orderId"]}_{order["product"]}'
        save_text_file(path, product)
        print('Product has been saved to path:', path)
    else:
        print('Product is corrupted')

    # close client socket (connection to the server)
    broker.close()
    print("Connection to broker closed")

# Runs merchant server processing with incoming broker connection
def handle_merchant_server(config: dict[str, str], broker:socket.socket, broker_addr:tuple) -> None:
    print(f"\nAccepted broker connection from {broker_addr}")

    # LOAD KEYS
    broker_pub_key = load_key_from_file(config['broker.pubkey'], False)
    merchant_private_key = load_key_from_file(config['prvkey'], True)

    # AUTH
    random_value = get_nonce()
    auth_bytes = broker.recv(MSG_SIZE)
    auth_msg = rsa_decrypt(auth_bytes, merchant_private_key)
    print('Auth message:', auth_msg)
    id = auth_msg[:7]
    challenge = auth_msg[7:]
    random_value = get_nonce()
    # print('Random:', random_value, 'Length:', len(random_value))
    auth_reply = b'MerchantA' + challenge + random_value
    broker.send(rsa_encrypt(auth_reply, broker_pub_key))

    auth_final_msg = broker.recv(MSG_SIZE)
    auth_final_msg = rsa_decrypt(auth_final_msg, merchant_private_key)
    print('Auth final message:', auth_final_msg)

    if auth_final_msg == random_value:
        print(f'AUTH SUCCESS for broker: {broker_addr} as ID: {id}')
        broker.send(rsa_encrypt(b'OK', broker_pub_key))
    else:
        print(f'AUTH FAILED for broker: {broker_addr}')
        broker.send(rsa_encrypt(b'NO', broker_pub_key))
        broker.close()
        print(f"Connection to BROKER {broker_addr} closed")

    # MERCHANT- BROKER SESSION KEY
    val=rsa_decrypt(broker.recv(MSG_SIZE), merchant_private_key).decode()
    skey2,B=generate_server_DH(val)

    # #1 more msg to client B
    broker.send(rsa_encrypt(B.encode(),broker_pub_key))
    # print("sessionkkk---2---- server----",skey2)
    B = None

    while True:
        request_bytes = broker.recv(MSG_SIZE)
        if request_bytes == b"":
            break
        request = aes_decrypt(skey2, request_bytes)

        # print('------------------', request)
        op, data, ref = decode_message(request)
        response = handle_msg_merchant(config, op, data, ref, merchant_private_key)
        # print('Length:', len(aes_encrypt(skey2, jsonify(op, response))))
        broker.send(aes_encrypt(skey2, jsonify(op, response)))


    # close connection socket with the socket client
    broker.close()
    print(f"Connection to BROKER {broker_addr} closed")

merchant_sessions = {"ref": "session-key"}

def handle_msg_merchant(config: dict, operation: str, data: object, ref:str, merchant_private_key) -> bytes:
    print('====>Received request for operation:', operation)
    response = None
    match operation:
        case "getUserSession":
            # MERCHANT - CLIENT SESSION KEY
            # ref = data["ref"]
            # enc_data = data["client"]
            val=rsa_decrypt(base64.b64decode(data), merchant_private_key).decode()
            session_key3, response = generate_server_DH(val)
            # store ref - session key mapping
            merchant_sessions[ref] = session_key3
        case "getProductList":
            # data contains ref
            skey3 = merchant_sessions[ref]
            path = "merchant/products"
            products = get_files_in_directory(path)
            print('Current product list:', products)
            response = session_encode_object(products, skey3)
        case "checkoutProduct":
            skey3 = merchant_sessions[ref]
            data = session_decode_object(data, skey3)
            product = data["product"]
            broker_msg, client_msg = create_order(product, int(config["amount"]))
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
            skey3 = merchant_sessions[ref]
            data = session_decode_object(data, skey3)
            product_data = get_product_data_by_order(data, int(config["padding"]))
            response = session_encode_object(base64.b64encode(product_data).decode(), skey3)

    if not response:
        print('WARNING: Sending empty response')
    print('<====Sending response for operation:', operation)
    return response

def get_product_data_by_order(order_id: str, padding: int) -> bytes:
    # read order info
    order_path = 'merchant/orders/' + order_id
    order = load_json_file(order_path)
    product = get_file_contents('merchant/products/' + order['product'], padding)
    product_hash = hash_file_content(product)
    # update order as delivered
    order['status'] = "DELIVERED"
    write_json_file(order, order_path)
    return product + product_hash

# CREATE ORDER AT MERCHANT
def create_order(product: str, amount: int):
    order_id = str(uuid.uuid4())
    orderForBroker = {"orderId": order_id, "amount": amount, "status": "PAYMENT_PENDING"}
    orderForClient = {"orderId": order_id, "product": product, "amount": amount, "status": "PAYMENT_PENDING"}
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

# Runs Broker server for incoming client connection with existing broker connection
def handle_broker_server(config: dict[str, str], client:socket.socket, client_addr:tuple, merchant:socket.socket, skey2: bytes) -> None:
    print(f"\nAccepted CLIENT connection from {client_addr}")

    # auth handling
    broker_prv_key = load_key_from_file(config['prvkey'], True)
    auth_bytes = client.recv(MSG_SIZE)
    auth_msg = rsa_decrypt(auth_bytes, broker_prv_key)

    auth_details = auth_msg.split(b'::')
    username = auth_details[0].decode()
    password = auth_details[1].decode()
    cust_pub_key = load_key_from_file(config['client.pubkey'].format(user=username), False)

    challenge = auth_details[2] if len(auth_details) == 3 else b''.join(auth_details[3:])
    print(f'username: {username}, password: {password}, challenge: {challenge}')

    verified = verify_username_password(local_config["passwords_file"], username, password)
    if verified:
        print('Verified username and password')
        reply = challenge + b'SUCCESS'
        client.send(rsa_encrypt(reply, cust_pub_key))
    else:
        print('Did not find a matching username and password')
        reply = challenge + b'FAILED'
        client.send(rsa_encrypt(reply, cust_pub_key))
        client.close()
        print(f"Connection to CLIENT {client_addr} closed")
        return

    #CLIENT- BROKER SESSION KEY
    val=rsa_decrypt(client.recv(MSG_SIZE), broker_prv_key).decode()
    skey1,B=generate_server_DH(val)
    client.send(rsa_encrypt(B.encode(),cust_pub_key))

    # print("sessionkkk--1-- server----",skey1)
    B = None

    #CLIENT - MERCHANT SESSION KEY => RELAY
    # session ref to hide client's identity - valid only for this session
    ref = str(uuid.uuid4())
    op1, relay, _ = decode_message(aes_decrypt(skey1, client.recv(MSG_SIZE)))
    merchant_id = relay["broker"]        # message part meant for broker
    merchant_msg = relay["merchant"]    # encrypted part for merchant
    merchant.send(aes_encrypt(skey2, jsonify(op1, merchant_msg, ref)))
    client.send(aes_encrypt(skey1, aes_decrypt(skey2, merchant.recv(MSG_SIZE))))

    op1, product_list_req, _ = decode_message(aes_decrypt(skey1, client.recv(MSG_SIZE)))
    # identify merchant:
    merchant_id = product_list_req["merchantId"]
    print('===>Contacting:', merchant_id)

    # get product list from merchant
    merchant.send(aes_encrypt(skey2, jsonify("getProductList", ref=ref)))
    op2, product_list, _ = decode_message(aes_decrypt(skey2, merchant.recv(MSG_SIZE)))
    assert op2 == "getProductList"

    # send list to client
    print('<===Sending product list to client')
    client.send(aes_encrypt(skey1, jsonify(op1, product_list)))

    # productCheckout
    op1, checkout_req, _ = decode_message(aes_decrypt(skey1, client.recv(MSG_SIZE)))
    print('===>productCheckout')

    # get ORDER INFO from merchant
    merchant.send(aes_encrypt(skey2, jsonify(op1, checkout_req, ref)))
    op2, checkout_resp, _ = decode_message(aes_decrypt(skey2, merchant.recv(MSG_SIZE)))
    orderInfo = checkout_resp["broker"]
    save_order(orderInfo)
    client_msg = checkout_resp["client"]
    assert op2 == op1

    # send list to client
    print('<===Sending checkout response to client')
    client.send(aes_encrypt(skey1, jsonify(op1, client_msg)))

    # processPayment
    op1, payment_req, _ = decode_message(aes_decrypt(skey1, client.recv(MSG_SIZE)))

    if payment_req['orderId'] == 'cancelled':
        # user has cancelled the payment
        print('CANCELLED')
        orderInfo['status'] = "CANCELLED"
        save_order(orderInfo)
        client.close()
        merchant.send(aes_encrypt(skey2, jsonify(op1, orderInfo, ref)))
        merchant.recv(MSG_SIZE)
        print(f"Connection to CLIENT {client_addr} closed")
        return

    success = process_payment(local_config, payment_req, orderInfo)

    if not success:
        print('PAYMENT FAILED')
        orderInfo['status'] = "PAYMENT_FAILED"
        save_order(orderInfo)
        merchant.send(aes_encrypt(skey2, jsonify(op1, orderInfo, ref)))
        merchant.recv(MSG_SIZE)
        client.send(aes_encrypt(skey1, jsonify(op1, 'Failed')))
        client.close()
        print(f"Connection to CLIENT {client_addr} closed")
        return

    # success case
    orderInfo['status'] = "PAYMENT_SUCCESS"
    save_order(orderInfo)
    merchant.send(aes_encrypt(skey2, jsonify(op1, orderInfo, ref)))
    op2, merchant_resp, _ = decode_message(aes_decrypt(skey2, merchant.recv(MSG_SIZE)))
    assert op1 == op2

    if merchant_resp == 'OK':
        print('Payment acknowledged by merchant')

    client.send(aes_encrypt(skey1, jsonify(op1, 'Success')))

    # processDelivery
    op1, delivery_req, _ = decode_message(aes_decrypt(skey1, client.recv(MSG_SIZE)))
    merchant.send(aes_encrypt(skey2, jsonify(op1, delivery_req, ref)))
    op2, delivery_resp, _ = decode_message(aes_decrypt(skey2, merchant.recv(MSG_SIZE)))
    client.send(aes_encrypt(skey1, jsonify(op1, delivery_resp)))

    # close connection socket with the client
    client.close()
    print(f"Connection to CLIENT {client_addr} closed")

# Broker checks for sufficient balance and processes payment; Return true if success
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

            # verify name
            name = request['accountHolderName']
            if client_acc['accountHolderName'] != name:
                print('Invalid credentials')
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

# Used by broker to authenticate merchant
def authenticate_merchant(config: dict, merchant: socket.socket) -> bytes | None:
    broker_prv_key = load_key_from_file(config['prvkey'], True)
    merch_pub_key = load_key_from_file(config['merchant.pubkey'], False)
    random_value = get_nonce()
    # print('Random:', random_value, 'Length:', len(random_value))
    merchant.send(rsa_encrypt(b'brokerA' + random_value, merch_pub_key))
    auth_resp = merchant.recv(MSG_SIZE)

    # ID + mychallenge + newchallenge
    auth_resp = rsa_decrypt(auth_resp, broker_prv_key)
    print('Auth Received: ', auth_resp)
    id = auth_resp[:9]
    print('id:', id)
    challenge_recv = auth_resp[9:32+9]
    if(random_value == challenge_recv):
        print('Received correct challenge back')
    else:
        print('incorrect challenge', 'expected:', random_value, 'received:', challenge_recv)
    challenge = auth_resp[32+9:]

    merchant.send(rsa_encrypt(challenge, merch_pub_key))
    auth_reply = rsa_decrypt(merchant.recv(MSG_SIZE), broker_prv_key)

    if auth_reply == b'OK':
        print('AUTH SUCCESS')
        p, g, x1, x2, A1, A2, msg = generate_DH_params()
        merchant.send(rsa_encrypt(msg.encode(), merch_pub_key))
        B1, B2 = rsa_decrypt(merchant.recv(MSG_SIZE), broker_prv_key).decode().split()
        return generate_client_DH(p, g, x1, x2, A1, A2, B1, B2)
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

                broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                broker_socket.bind((ip_addr, int(port)))
                broker_socket.listen(5)    # 5 connections possible to this port

                merchant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                merchant_socket.connect((merchant_addr, int(merchant_port)))
                print(f"Connected to merchant at: {merchant_addr}:{merchant_port}")

                skey_2=authenticate_merchant(local_config, merchant_socket)

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

                # read config to get broker address
                local_config = config['client']
                broker_addr = local_config['broker.ip']
                broker_port = local_config['broker.port']

                # connect to broker
                broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                broker_socket.connect((broker_addr, int(broker_port)))
                print(f"Connected to broker at {broker_addr}:{broker_port}")

                sk_broker, sk_merchant, username = authenticate_user(local_config, broker_socket)

                if username == None:
                    # auth failed
                    print('Authentication Failed. Please check username and/or password.')
                else:
                    # throw error if invalid
                    assert sk_broker != None
                    assert sk_merchant != None

                    # pass session keys to process
                    process_client_messages(local_config, broker_socket, sk_broker, sk_merchant, username)

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

    except AssertionError:
        print("\nClosing due to invalid session key")
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
