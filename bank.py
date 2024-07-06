from builtins import int
import socket
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

host = socket.gethostname()+".cs.binghamton.edu"
account_balances = {}

def load_initial_balance():
    with open("balance", "r") as f:
        for line in f:
            user_id, savings, checking = line.strip().split()
            account_balances[user_id] = {"savings": int(savings), "checking": int(checking)}

def debit_funds(user_id, account_type, amount):
    account_balances[user_id][account_type] -= int(amount)
    #print(account_balances[user_id][account_type])

def credit_funds(recipient_id, account_type, amount):
    account_balances[recipient_id][account_type] += int(amount)
    #print(account_balances[recipient_id][account_type])

def send_data(socket, data):
    data_size = len(data).to_bytes(4, byteorder='big')
    socket.send(data)



def decrypt_asymmetric(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def get_balance(user_id):
    with open("balance", "r") as f:
        for line in f:
            current_user_id, savings, checking = line.strip().split()
            if current_user_id == user_id:
                savings_balance = float(savings)
                checking_balance = float(checking)
                return f"Your savings account balance: {savings_balance}\nYour checking account balance: {checking_balance}"

def load_user_credentials():
    credentials = {}
    with open("password", "r") as file:
        for line in file:
            user_id, password = line.strip().split()
            credentials[user_id] = password
    return credentials

def authenticate_user(user_id, password, credentials):
    #print(str(user_id),str(password))
    if str(user_id) in credentials and credentials[str(user_id)] == str(password):
        return True
    else:
        return False
    
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 bank.py <bank_port>")
        sys.exit(1)

    bank_port = int(sys.argv[1])
    load_initial_balance()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, bank_port))
    server_socket.listen()

    print("Bank server is listening for connections...")

    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        while True:
            try:
            # encrypted_symmetric_key_size = int.from_bytes(client_socket.recv(4), byteorder='big')
                encrypted_symmetric_key = client_socket.recv(1024)
                # encrypted_credentials_size = int.from_bytes(client_socket.recv(4), byteorder='big')
                client_socket.send("acknowledge".encode())
                encrypted_credentials = client_socket.recv(1024)


                symmetric_key = decrypt_asymmetric(encrypted_symmetric_key, private_key)

                cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(b'\0' * 16), backend=default_backend())
                decryptor = cipher.decryptor()
                credentials = decryptor.update(encrypted_credentials) + decryptor.finalize()
                #print(credentials)
                user_id, password = credentials.decode().split("||")
                
                credentials = load_user_credentials()
                #print(credentials)
                if authenticate_user(user_id, password, credentials):
                    response="ID and password are correct"
                else:
                    response="ID and password is incorrect"

                client_socket.send(response.encode())

                if "ID and password are correct" in response:
                    while True:
                        choice = client_socket.recv(1024).decode()

                        if choice == "1":
                            while True:
                                account_choice = client_socket.recv(1024).decode()
                                #print("account",account_choice,"2\n")
                                if account_choice == '2':
                                    account_choice = 'checking'
                                    client_socket.send("ack input".encode())
                                elif account_choice == '1':
                                    account_choice = 'savings'
                                    client_socket.send("ack input".encode())
                                else:
                                    client_socket.send("incorrect input".encode())
                                recipient_id = client_socket.recv(1024).decode()
                                amount = client_socket.recv(1024).decode()
                                #print("amount",amount,"3\n")
                                
                                if recipient_id not in account_balances:
                                    response = "The recipient's ID does not exist"
                                else:
                                    #print(account_choice)
                                    if int(amount) > account_balances[user_id][account_choice]:
                                        response = "Your account does not have enough funds"
                                    else:
                                        debit_funds(user_id, account_choice, amount)
                                        credit_funds(recipient_id, account_choice, amount)

                                        with open("balance", "w") as f:
                                            for uid, balances in account_balances.items():
                                                f.write(f"{uid} {balances['savings']} {balances['checking']}\n")

                                        response = "Your transaction is successful"

                                #print(response)
                                client_socket.send(response.encode())
                                break

                        elif choice == "2":
                            result=get_balance(user_id)
                            send_data(client_socket,result.encode())

                        elif choice == "3":
                            send_data(client_socket, "Connection closed!!".encode())
                            client_socket.close()
                            break

                        else:
                            response = "Incorrect input"
                            send_data(client_socket, response)
            except Exception as e:
                print(f"Exception occured: client disconnected")
                break

if __name__ == "__main__":
    main()
