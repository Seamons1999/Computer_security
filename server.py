import socket
import json
import time
import re
import threading
import logging
import bcrypt
import ssl

from jsonschema import validate, ValidationError\


def is_strong_password(password):
    # Make sure password is at least 12 characters long
    if len(password) < 12:
        return False

    # Check quality of password
    if (not re.search(r'[A-Z]', password) or        # Password contains at least one uppercase letter
        not re.search(r'[a-z]', password) or        # Password contains at least one lowercase letter
        not re.search(r'[0-9]', password) or        # Password contains at least one number
        not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):    # Password contains at least one special character
        return False

    # Ensure password is not a common password
    common_passwords = ['password1234', 'wachtwoord123', '123456789101', 'qwertyuiopas']
    if password in common_passwords:
        return False

    return True

def hash_password(client_input, salt):
    plain_password = client_input + '2425-KEN2560' # password with pepper
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed_password


def validate_json(message, addr):
    invalid_return_values = 'InvalidJSON', 0, []

    schema = {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'password': {'type': 'string'},
            'server': {
                'type': 'object',
                'properties': {
                    'ip': {'type': 'string'},
                    'port': {'type': 'number'}
                }, 'required': ['ip', 'port']

            },
            'actions': {
                'type': 'object',
                'properties': {
                    'delay': {'type': 'number'},
                    'steps': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1, 'maxItems': 10}
                }, 'required': ['delay', 'steps']

            }
        }, 'required': ['id', 'password', 'server', 'actions']
    }

    try:
        validate(instance=message, schema=schema)
    except ValidationError as e:
        logging.error(f"Invalid JSON data from connection {addr}: {e.message}")
        return invalid_return_values

    client_id = message['id']
    logging.info(f'ID {client_id}- Connection from {addr}')

    # Validate delay value
    try:
        delay = float(message['actions']['delay'])
    except ValueError:
        logging.error(f'ID {client_id}- Invalid delay value: {delay}')
        return invalid_return_values

    if delay > 10:
        logging.error(f'ID {client_id}- Delay value too high: {delay}')
        return invalid_return_values

    if delay < 0.5:
        logging.error(f'ID {client_id}- Delay too low: {delay}')
        return invalid_return_values

    # Validate actions
    numeric_changes = []
    for step in message['actions']['steps']:
        step = re.split(r'\s+', step)
        if step[0] not in ['INCREASE', 'DECREASE']:
            logging.error(f'ID {client_id}- Invalid step: {step[0]}')
            return invalid_return_values

        try:
            number = float(step[1])
        except ValueError:
            logging.error(f'ID {client_id}- User input for action is not a number: {step}')
            return invalid_return_values

        if number > 1000:
            print(f'ID {client_id}: User input is too high')
            return invalid_return_values

        if number < 0:
            print(f'ID {client_id}: User input is negative')
            return invalid_return_values

        if step[0] == 'INCREASE':
            numeric_changes.append(number)
        elif step[0] == 'DECREASE':
            numeric_changes.append(- number)

    return client_id, delay, numeric_changes


def handle_client(clients, client_socket, addr, max_conn_limiter, max_threads_per_client, active_clients, lock):
    max_conn_limiter.acquire()
    logging.info(f'Connected to {addr}')

    # Try-finally block to ensure resource clean-up even if code raises error
    try:
        # Check if JSON message is okay
        client_msg = json.loads(client_socket.recv(1024).decode('ascii'))
        client_id, delay, numeric_changes = validate_json(client_msg, addr)

        if client_id == 'InvalidJSON' and delay == 0 and numeric_changes == []: # JSON-file incorrect
            logging.info(f'Connection to {addr} aborted due to false json file')
            return

        # Lockout mechanism
        if clients[client_id]['failed_logins'] >= 3:
            logging.info(f'ID {client_id}: Too many failed logins. Access denied')
            return

        # Use lock to prevent that execution is halted halfway the block
        with lock:
            if client_id not in active_clients:
                active_clients[client_id] = 1
            elif active_clients[client_id] + 1 > max_threads_per_client:
                logging.info(f"ID {client_id} already has {max_threads_per_client} active connections.")
                return
            else:
                active_clients[client_id] += 1

        # Check if client is already registerd
        if client_id in clients:
            if hash_password(client_msg['password'], clients[client_id]['salt']) != clients[client_id]['password']:
                logging.error(f'ID {client_id}: Invalid password')

                # Send error to client and abort connection
                response = {'status': 'error', 'message': 'Something went wrong, please try again'}
                client_socket.send(json.dumps(response).encode('ascii'))
                clients[client_id]['failed_logins'] += 1
                return

            logging.info(f'ID {client_id} - Client already registered')
        else:
            # Check if password is strong enough
            if not is_strong_password(client_msg['password']):
                logging.error(f'ID {client_id} - Not registered due to weak password password')
                response = {'status': 'error', 'message': 'Password to weak'}
                client_socket.send(json.dumps(response).encode('ascii'))
                return

            # Register new client
            salt = bcrypt.gensalt()
            clients[client_id] = {'password': hash_password(client_msg['password'], salt), 'counter': 0, 'salt': salt,
                                  'failed_logins': 0}
            logging.info(f'ID {client_id}: New client registered')

        for step in numeric_changes:
            clients[client_id]['counter']+= step
            logging.info(f'ID {client_id} - Counter value updated to {clients[client_id]['counter']}')
            time.sleep(delay)

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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="certificate.crt", keyfile='private.key')


    # Create objects for handling multi-threading
    max_clients_per_server = 5
    max_threads_per_client = 2

    max_conn_limiter = threading.BoundedSemaphore(max_clients_per_server) # Allow only 5 clients at a time (prevent overload attack)
    server_socket.listen(5) # Only additional 5 clients can be queued
    clients = {} # Dictionary to store client data
    active_clients = {} # Dictionary to store semaphores for restricting number of concurrent clients per userid
    lock = threading.Lock() # Lock to prevent two processes to simultaneously access semaphores of active_clients

    logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info('Server starting')

    while True:
        client_socket, addr = server_socket.accept()
        ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
        client_thread = threading.Thread(target=handle_client, args=(clients, ssl_client_socket, addr, max_conn_limiter,
                                                                     max_threads_per_client, active_clients, lock))
        client_thread.start()


if __name__ == '__main__':
    main()

