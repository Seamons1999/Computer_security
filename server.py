import socket
import json
import time
import re
import threading
import logging

def handle_client(clients, client_socket, addr):
    logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info(f'Connected to {addr}')
    # print(f"Got a connection from {addr}")

    # Receive client registration data
    client_msg = json.loads(client_socket.recv(1024).decode('ascii'))

    # Register client
    client_id = client_msg['id']
    password = client_msg['password']
    if client_id in clients:
        if password != clients[client_id]['password']:
            response = {'status': 'error', 'message': 'Invalid password'}
            client_socket.send(json.dumps(response).encode('ascii'))
            logging.error(f'ID {client_id}: Invalid password')
            return
        else:
            logging.error(f'ID {client_id}: Client already registered')
            response = {'status': 'error', 'message': 'Client already registered'}
    else:
        # Register client
        clients[client_id] = {'password': password, 'counter': 0}
        logging.info(f'ID {client_id}: New client registered')
        response = {'status': 'ok', 'message': 'Registration successful'}

    # Send response to client
    client_socket.send(json.dumps(response).encode('ascii'))

    for step in client_msg['actions']['steps']:
        step = re.split(r'\s+', step)
        if step[0] == 'INCREASE':
            clients[client_id]['counter'] += float(step[1])
            response = f'ID {client_id}: New counter value of id {client_id} is: {clients[client_id]['counter']}'
        elif step[0] == 'DECREASE':
            clients[client_id]['counter'] -= float(step[1])
            response = f'ID {client_id}: New counter value of id {client_id} is: {clients[client_id]['counter']}'
        else:
            response = f'ID {client_id}: Invalid action'
        logging.info(response)
        time.sleep(client_msg['actions']['delay'])

    client_socket.close()

def main():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 9999
    server_socket.bind((host, port))
    server_socket.listen(5)

    # Dictionary to store client data
    clients = {}

    while True:
        client_socket, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(clients, client_socket, addr))
        client_thread.start()


if __name__ == '__main__':
    main()

