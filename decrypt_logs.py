from cryptography.fernet import Fernet

def load_key():
    return open("secret.key", "rb").read()

def decrypt_message(encrypted_message, cipher_suite):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

def main():
    key = load_key()
    cipher_suite = Fernet(key)

    with open("app.log", "r") as log_file:
        lines = log_file.readlines()

    for line in lines:
        try:
            decrypted_message = decrypt_message(line.strip(), cipher_suite)
            print(decrypted_message)
        except Exception as e:
            print(line.strip())

if __name__ == '__main__':
    main()
