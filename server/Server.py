import json
import socket
import os,glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

menu = "\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nChoice:"

def binary_to_string(bin_str):
    return bin_str.decode('utf-8')

def string_to_binary(string):
    return string.encode('utf-8')

# Purpose: creates cipher from public or private key file
# USE FOR PUBLIC AND PRIVATE KEY CIPHERS
# Parameters: file name of key
# Return: generated cipher
def create_assymetric_cipher(fileName):
    with open(fileName, "rb") as key_file:
        key_data = key_file.read()
    key = RSA.import_key(key_data)
    cipher = PKCS1_OAEP.new(key)
    return cipher

# Purpose: pad and encrypt message to be sent
# Parameters: message string, AES or RSA cipher, required pad bytes
# Return: encrypted and padded message
def encrypt_message(message, cipher):
    # encrypt message padded with 256 bits/32 bytes
    encryptedMessage = cipher.encrypt(message)
    return encryptedMessage

# Purpose: decrypt message and remove padding
# Parameters: encrypted message, AES or RSA cipher and amount of pad bytes to be removed
# Return: decoded and unpadded message
def decrypt_message(encryptedMessage, cipher):
    return cipher.decrypt(encryptedMessage)

def encrypt_symmetric_message(message, cipher):
	padBytes = int(256/8)
	encryptedMessage = encryptedMessage = cipher.encrypt(pad(message.encode('ascii'), padBytes))
	return encryptedMessage

def decrypt_symmetric_message(encryptedMessage, cipher):
	padBytes = int(256/8)
	padded_message = cipher.decrypt(encryptedMessage)
	unpadded_message = unpad(padded_message, padBytes)
	decoded_message = unpadded_message.decode('ascii')
	return decoded_message

# Purpose: send message to specified socket
# Parameters: message, socket to send to
def sendMessage(message, socketType):
    socketType.send(message)
    return

# Purpose: receive message from specified socket
# Parameters: socket
# Return: received message
def receiveMessage(socketType):
    message = socketType.recv(2048)
    return message
    


# Purpose: returns a dictionary of usernames and
# passwords from user_pass.json
# Return: dictionary of client usernames and passwords (clients)
def read_user_pass():
    user_json = open("user_pass.json", "r")
    clients = json.load(user_json)
    user_json.close()
    return clients

# Purpose: make directory for client if they do not exist already.
# These folders need to exist in order to store emails for respective clients.
# Parameters: client (username)
def make_client_directory(username):
    # check if path exists before making directory
    if os.path.exists(username) == False:
        os.mkdir(username)
    return

# Purpose: check formatted username and password (user;pass) with json file to check credentials
# Parameters: formatted credentials (in format user;pass)
# Return: return the username and True if authenticated, False if incorrect
def check_user_pass(formatted_credentials):
    username_pass = formatted_credentials.split(";")
    with open("user_pass.json", "r") as jsonFile:
        clients = json.load(jsonFile)
    for username in clients:
        if username == username_pass[0]:
            if clients[username] == username_pass[1]:
                return username_pass[0], True
    return username_pass[0], False


def read_inbox(username):
    with open(f'{username}/inbox.json', 'r') as jsonFile:
            mail_List = json.load(jsonFile)
    inbox_chart = "\n{:<16}{:<24}{:<34}{:<24}".format("Index","From","DateTime","Title")
    for key in mail_List:
        newLine = "\n{:<16}{:<24}{:<34}{:<24}".format(key, mail_List[key]['sender'], mail_List[key]['datetime'], mail_List[key]['title'])
        inbox_chart += newLine
    inbox_chart += menu
    return inbox_chart




def main():
    # define server socket on port 13000
    port = 13000
    try:
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        print("Error in server socket creation:", err)
        sys.exit(1)

    # server attempts to open server socket on port 13000
    try:
        serversocket.bind(('', port))
    except socket.error as err:
        print("Error in server socket:", err)
        sys.exit()
    # server prepares to accept incoming connection
    serversocket.listen(5)
    print("The server is ready to accept connections")
    while True:
        # accepts connection
        # nested loops so when previous user disconnects, the server begins to listen for a new user to connect
        connectionSocket, address = serversocket.accept()
        
        # call fork to allow mutliple simultaneous connections
        pid = os.fork()
        if pid == 0:
            encrypted_credentials = receiveMessage(connectionSocket)
            server_Private_cipher = create_assymetric_cipher("server_private.pem")
            decrypted_credentials = binary_to_string(decrypt_message(encrypted_credentials, server_Private_cipher))
            # username is FALSE if credentials are not correct
            # print(decrypted_credentials)
            username, is_valid = check_user_pass(decrypted_credentials)
            
            if is_valid == False:
                # send user the Invalid username or password.\n Terminating
                print(f'The received client information: {username} is invalid. (Connection Terminated).')
                sendMessage((f"Invalid username or password.\nTerminating.").encode("ascii"), connectionSocket)
                connectionSocket.close()
                return
            else:
                # generate random 256 bit key
                symmetric_key = get_random_bytes(int(256/8))
                symmetric_cipher = AES.new(symmetric_key, AES.MODE_ECB)
                public_key_name = f'{username}_public.pem'
                # encrypt sym key with client public key
                client_publicKey_cipher = create_assymetric_cipher(public_key_name)
                encrypted_symmetric_key = encrypt_message(symmetric_key, client_publicKey_cipher)
                sendMessage(encrypted_symmetric_key, connectionSocket)
                print(f'Connection Accepted and Symmetric Key Generated for client: {username}')
                # receive OK ack
                acknowledgement = decrypt_symmetric_message(receiveMessage(connectionSocket), symmetric_cipher)
                print(acknowledgement)
                sendMessage(encrypt_symmetric_message(menu, symmetric_cipher), connectionSocket)
                while True:
                    received_input = decrypt_symmetric_message(receiveMessage(connectionSocket), symmetric_cipher)
                    if received_input == '2':
                        formatted_chart = read_inbox(username)
                        sendMessage(encrypt_symmetric_message(formatted_chart, symmetric_cipher), connectionSocket)
                    
                    if received_input == '4':
                        sendMessage(encrypt_symmetric_message("Connection Terminated", symmetric_cipher), connectionSocket)
                        connectionSocket.close()
                        return
                    else:
                        sendMessage(encrypt_symmetric_message(menu, symmetric_cipher), connectionSocket)

                

    return

main()