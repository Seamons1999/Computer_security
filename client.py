import json
import socket
import argparse
import ssl

def main():
    # Get commandline parameters
    parser = argparse.ArgumentParser(description='Get client id number')
    parser.add_argument("client_id", type=int)
    args = parser.parse_args()
    c_id = args.client_id
    print(args.client_id)

    # Load json file
    with open(f'client{c_id}.json', 'r') as f:
        config = json.load(f)

    # Extract data from json file
    client_id = config['id']
    password = config['password']
    server_ip = config['server']['ip']
    server_port = config['server']['port']
    delay = config['actions']['delay']
    steps = config['actions']['steps']

    # Establish connection to the server
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations('certificate.pem')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_ssl_socket = ssl_context.wrap_socket(client_socket, server_hostname='2425-KEN2560')
    client_ssl_socket.connect((server_ip, server_port))

    # Send client registration data to server
    client_message = client_ssl_socket.send(json.dumps(config).encode('ascii'))
    server_answer = client_ssl_socket.recv(1024).decode('ascii')

    print(server_answer)

    client_ssl_socket.close()


if __name__ == '__main__':
    main()
