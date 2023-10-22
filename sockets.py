import argparse
import socket
import configparser

# config and setup related
config = configparser.ConfigParser()
config.read('config')

argParser = argparse.ArgumentParser()
argParser.add_argument("-m", "--mode", help="select mode: 'client', 'broker', 'merchant'", choices=['client', 'broker', 'merchant'], required=True)
argParser.add_argument("-i", "--ip", help="IP address", required=False)
argParser.add_argument("-p", "--port", help="Port for socket", required=False)

args = argParser.parse_args()
print('args:', args)

mode = args.mode
ip_addr = args.ip if args.ip else config[mode]['ip_addr']
port = args.port if args.port else config[mode]['port']

print(f'---------ATTEMPTING TO RUN AS {mode} -----------')

match mode:
    case 'broker':
        '''
        ===================BROKER=============
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

        # for client
        client_socket, client_address = broker_socket.accept() # external just refers to entity!=mode
        print(f"Accepted connection from {client_address[0]}:{client_address[1]}")

            # receive data from the client
        while True:
            request_bytes = client_socket.recv(1024)    # TODO: Max length????
            request = request_bytes.decode("utf-8") # convert bytes to string
                
            # if we receive "close" from the client, then we break
            # out of the loop and close the conneciton
            if request.lower() == "close":
                # send response to the client which acknowledges that the
                # connection should be closed and break out of the loop
                client_socket.send("closed".encode("utf-8"))
                break

            print(f"Received: {request}")
            # input message and send it to the server
            msg = input("Enter message: ")

            response = msg.encode("utf-8") # convert string to bytes
            # convert and send accept response to the client
            client_socket.send(response)
            merchant_socket.send(response)

            # close connection socket with the client
        client_socket.close()
        print("Connection to client closed")
        merchant_socket.close()
        print("Connection to merchant closed")
            # close server socket
        broker_socket.close()

    case 'client':
        '''
        ===================CLIENT=============
        '''
        print(mode, 'IP:', ip_addr, 'Port:', port, '\n')
        local_config = config['client']
        broker_addr = local_config['broker.ip']
        broker_port = local_config['broker.port']

        # connect to broker
        broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        broker_socket.connect((broker_addr, int(broker_port)))

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

    case 'merchant':
        '''
        ===================MERCHANT=============
        '''
        print(mode, 'IP:', ip_addr, 'Port:', port, '\n')

        # listen refers to a socket object
        merchant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        merchant_socket.bind((ip_addr, int(port)))
        merchant_socket.listen(5)    # 5 connections possible to this port

        broker_socket, broker_address = merchant_socket.accept() # external just refers to entity!=mode
        print(f"Accepted broker connection from {broker_address[0]}:{broker_address[1]}")

        # receive data from the broker
        while True:
            request_bytes = broker_socket.recv(1024)    # TODO: Max length????
            request = request_bytes.decode("utf-8") # convert bytes to string
                
            # if we receive "close" from the client, then we break
            # out of the loop and close the conneciton
            if request.lower() == "close":
                # send response to the client which acknowledges that the
                # connection should be closed and break out of the loop
                broker_socket.send("closed".encode("utf-8"))
                break

            print(f"Received: {request}")
            # input message and send it to the server
            msg = input("Enter message: ")

            response = msg.encode("utf-8") # convert string to bytes
            # convert and send accept response to the client
            broker_socket.send(response)

        # close connection socket with the client
        broker_socket.close()
        print("Connection to client closed")
            # close server socket
        broker_socket.close()
