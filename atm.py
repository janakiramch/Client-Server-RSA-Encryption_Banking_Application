from builtins import int
import socket
import os
import sys
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    with open("atm_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open("atm_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def encrypt_asymmetric(data, public_key):
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def encrypt_symmetric(data, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return ciphertext

def send_data(socket, data):
    # print(data)
    socket.sendall(data)


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 atm.py <bank_address> <bank_port>")
        sys.exit(1)

    bank_address = sys.argv[1]
    bank_port = int(sys.argv[2])
    bank_server_address = (bank_address, bank_port)

    atm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    atm_socket.connect(bank_server_address)

    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    socket_close = False
    while True:
        user_id = input("Enter your ID: ")
        password = input("Enter your password: ")

        symmetric_key = os.urandom(32)  # Generate a random symmetric kencryey
        #encrypted_symmetric_key = encrypt_asymmetric(symmetric_key.decode(), public_key)
        encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)

        encrypted_credentials = encrypt_symmetric(f"{user_id}||{password}", symmetric_key)
        # atm_socket.send()
        send_data(atm_socket, encrypted_symmetric_key)
        responseee = atm_socket.recv(1024).decode()
        send_data(atm_socket, encrypted_credentials)
        # response_size = int.from_bytes(atm_socket.recv(4), byteorder='big')
        response = atm_socket.recv(1024).decode()
        print(response)
        if "ID and password are correct" in response:
            while True:
                print("Please select one of the following actions (enter 1, 2, or 3):")
                print("1. Transfer money")
                print("2. Check account balance")
                print("3. Exit")

                choice = input("Enter your choice:")
                if choice == "1":
                    atm_socket.send("1".encode())
                    while True:
                        print("Please select an account (enter 1 or 2):")
                        print("1. Savings")
                        print("2. Checking")

                        account_choice = input("Enter your choice:")

                        # if account_choice in 
                        atm_socket.send(account_choice.encode())
                        ack = atm_socket.recv(1024).decode()
                        if 'incorrect' in ack:
                            continue


                        # print("Enter recipient's ID:", end=" ")
                        recipient_id = input("Enter recipient's ID: ")
                        atm_socket.send(recipient_id.encode())
                        #print("Enter the amount to be transferred:", end=" ")
                        amount = input("Enter the amount to be transferred: ")
                        atm_socket.send(amount.encode())

                        # send_data(atm_socket, "1".encode())
                        # send_data(atm_socket, account_choice.encode())
                        # send_data(atm_socket, recipient_id.encode())
                        # time.sleep(1)
                        # send_data(atm_socket, str(amount).encode())
                        # response_size = int.from_bytes(atm_socket.recv(4), byteorder='big')
                        response = atm_socket.recv(1024).decode()
                        print(response)
                        break

                elif choice == "2":
                    send_data(atm_socket, "2".encode())

                    print(atm_socket.recv(1024).decode())
                        # savings_balance = float(atm_socket.recv(1024).decode())
                        # checking_balance = float(atm_socket.recv(1024).decode())
                        # print(f"Your savings account balance: {savings_balance}")
                        # print(f"Your checking account balance: {checking_balance}")

                elif choice == "3":
                    send_data(atm_socket, "3".encode())
                    print(atm_socket.recv(1024).decode())
                    socket_close = True
                    # atm_socket.close()
                    break

                else:
                    print("Incorrect input")
        if socket_close:
            atm_socket.close() 
            break   


if __name__ == "__main__":
    main()
