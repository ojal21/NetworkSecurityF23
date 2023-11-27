import argparse
import socket
import configparser
from threading import Thread
from crypto_custom import *

def load_config() -> configparser.ConfigParser:
    # config and setup related
    config = configparser.ConfigParser()
    config.read('config')   # filename: 'config'
    return config

def load_args() -> list:
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-m", "--mode", help="select mode: 'client', 'broker', 'merchant'", choices=['client', 'broker', 'merchant'], required=True)
    argParser.add_argument("-i", "--ip", help="IP address", required=False)
    argParser.add_argument("-p", "--port", help="Port for socket", required=False)

    args = argParser.parse_args()
    print('Args:', args)
    return args

def process_client_messages(local_config: dict, broker: socket.socket) -> None:
    while True:
        # input message and send it to the server
        msg = input("Enter message: ")
        broker_socket.send(msg.encode("utf-8")[:1024])

        # receive message from the server
        response = broker_socket.recv(1024)
        response = response.decode("utf-8")

        print(f"Received: {response}")

        # if server sent us "closed" in the payload, we break out of the loop and close our socket
        if response.lower() == "closed":
            break

    # close client socket (connection to the server)
    broker_socket.close()
    print("Connection to broker closed")

def handle_merchant_server(local_config: dict, broker:socket.socket, broker_addr:tuple) -> None:
    print(f"Accepted broker connection from {broker_addr}")
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
        request_bytes = broker.recv(1024)    # TODO: Max length????
        request = request_bytes.decode("utf-8") # convert bytes to string

        # TODO: only for test
        if request.lower() == "close":
            broker.send("closed".encode("utf-8"))

        if request == "":
            break

        print(f"Received: {request}")
        # input message and send it to the server
        msg = input("Enter message: ")

        response = msg.encode("utf-8") # convert string to bytes
        # convert and send accept response to the socket client
        broker.send(response)

    # close connection socket with the socket client
    broker.close()
    print(f"Connection to BROKER {broker_addr} closed")

def handle_broker_server(local_config: dict, client:socket.socket, client_addr:tuple, merchant:socket.socket) -> None:
    print(f"Accepted CLIENT connection from {client_addr}")
    while True:
        request_bytes = client.recv(1024)    # TODO: Max length????
        request = request_bytes.decode("utf-8") # convert bytes to string

        # if we receive "close" from the client, then we break
        # out of the loop and close the conneciton
        # TODO: only for test
        if request.lower() == "close":
            # send response to the client which acknowledges that the
            # connection should be closed and break out of the loop
            client.send("closed".encode("utf-8"))

        if request == "":
            break

        print(f"Received: {request}")
        # input message and send it to the server
        msg = input("Enter message: ")

        response = msg.encode("utf-8") # convert string to bytes
        # convert and send accept response to the client
        client.send(response)

    # close connection socket with the client
    client.close()
    print(f"Connection to CLIENT {client_addr} closed")

def authenticate_merchant(merchant: socket.socket) -> None:
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
        config = load_config()
        args = load_args()

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

                authenticate_merchant(merchant_socket)

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

                process_client_messages(config['client'], broker_socket)

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
