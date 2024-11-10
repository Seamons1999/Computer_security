import socket
import json
import time
import re
import threading
import logging

def handle_client(clients, client_socket, addr, max_conn_limiter, max_threads_per_client, active_clients, lock):
    max_conn_limiter.acquire()
    logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info(f'Connected to {addr}')

    # Receive client registration data
    client_msg = json.loads(client_socket.recv(1024).decode('ascii'))

    # Get account data
    client_id = client_msg['id']
    password = client_msg['password']

    # Try-finally block to ensure resource clean-up even if code raises error
    try:
        # Use lock to prevent that execution is halted halfway the block
        with lock:
            if client_id not in active_clients:
                active_clients[client_id] = 1
            elif active_clients[client_id] + 1 > max_threads_per_client:
                logging.info(f"ID {client_id} already has {max_threads_per_client} active connections.")
                return
            else:
                active_clients[client_id] += 1

        if client_id in clients:
            if password != clients[client_id]['password']:
                logging.error(f'ID {client_id}: Invalid password')

                # Send error to client and abort connection
                response = {'status': 'error', 'message': 'Invalid password'}
                client_socket.send(json.dumps(response).encode('ascii'))
                return
            else:
                logging.info(f'ID {client_id}: Client already registered')

                # Send error to client
                response = {'status': 'info', 'message': 'Client already registered'}
                client_socket.send(json.dumps(response).encode('ascii'))
        else:
            logging.info(f'ID {client_id}: New client registered')

            # Send acknowledgment to client
            response = {'status': 'ok', 'message': 'Registration successful'}
            client_socket.send(json.dumps(response).encode('ascii'))

            # Register client password and initialise counter
            clients[client_id] = {'password': password, 'counter': 0}

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

        with lock:
            active_clients[client_id] -= 1
            if active_clients[client_id] == 0:
                del active_clients[client_id]
                del clients[client_id]
                logging.info(f'ID {client_id}: Account deleted because no active clients')

    finally:
        # End connection and free up resources
        client_socket.close()
        max_conn_limiter.release()


def main():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 9999
    server_socket.bind((host, port))

    # Create objects for handling multi-threading
    max_clients_per_server = 5
    max_threads_per_client = 2

    max_conn_limiter = threading.BoundedSemaphore(max_clients_per_server) # Allow only 5 clients at a time (prevent overload attack)
    server_socket.listen(5) # Only additional 5 clients can be queued
    clients = {} # Dictionary to store client data
    active_clients = {} # Dictionary to store semaphores for restricting number of concurrent clients per userid
    lock = threading.Lock() # Lock to prevent two processes to simultaneously access semaphores of active_clients

    while True:
        client_socket, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(clients, client_socket, addr, max_conn_limiter,
                                                                     max_threads_per_client, active_clients, lock))
        client_thread.start()


if __name__ == '__main__':
    main()

