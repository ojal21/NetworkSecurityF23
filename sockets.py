import argparse
import socket
import configparser

# config and setup related
config = configparser.ConfigParser()
config.read('config')

argParser = argparse.ArgumentParser()
argParser.add_argument("-m", "--mode", help="select mode: 'client', 'broker', 'merchant'", required=True)
argParser.add_argument("-i", "--ip", help="IP address", required=False)
argParser.add_argument("-lp", "--listening-port", help="Listening port for socket", required=False)
argParser.add_argument("-sp", "--sending-port", help="Sending port for socket", required=False)

args = argParser.parse_args()

print('args:', args)

mode = args.mode
ip_addr = args.ip if args.ip else config[mode]['ip_addr']
listening_port = args.listening_port if args.listening_port else config[mode]['listening_port']
sending_port = args.sending_port if args.sending_port else config[mode]['sending_port']

print(f'---------ATTEMPTING TO RUN AS {mode} -----------')

match mode:
    case 'broker':
        '''
        ===================BROKER=============
        '''
        print('IP:', ip_addr, 'Listening Port:', listening_port, 'Sending Port:', sending_port, '\n')

        # listen refers to a socket object
        listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen.bind((ip_addr, int(listening_port)))
        listen.listen(5)    # 5 connections possible to this port

        external_socket, external_address = listen.accept() # external just refers to entity!=mode
        print(f"Accepted connection from {external_address[0]}:{external_address[1]}")

            # receive data from the client
        while True:
            request_bytes = external_socket.recv(1024)    # TODO: Max length????
            request = request_bytes.decode("utf-8") # convert bytes to string
                
            # if we receive "close" from the client, then we break
            # out of the loop and close the conneciton
            if request.lower() == "close":
                # send response to the client which acknowledges that the
                # connection should be closed and break out of the loop
                external_socket.send("closed".encode("utf-8"))
                break

            print(f"Received: {request}")
            # input message and send it to the server
            msg = input("Enter message: ")

            response = msg.encode("utf-8") # convert string to bytes
            # convert and send accept response to the client
            external_socket.send(response)

            # close connection socket with the client
        external_socket.close()
        print("Connection to client closed")
            # close server socket
        listen.close()

    case 'client':
        '''
        ===================CLIENT=============
        '''
        print('IP:', ip_addr, 'Listening Port:', listening_port, 'Sending Port:', sending_port, '\n')
        broker_info = config['broker']

        # connect to broker
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((broker_info['ip_addr'], int(broker_info['listening_port'])))

        while True:
            # input message and send it to the server
            msg = input("Enter message: ")
            client.send(msg.encode("utf-8")[:1024])

            # receive message from the server
            response = client.recv(1024)
            response = response.decode("utf-8")

            print(f"Received: {response}")

            # if server sent us "closed" in the payload, we break out of the loop and close our socket
            if response.lower() == "closed":
                break

    # close client socket (connection to the server)
        client.close()
        print("Connection to broker closed")

