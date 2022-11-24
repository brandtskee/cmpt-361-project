import json
import socket
import os,glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

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
def encrypt_message(message, cipher, padBytes):
    # encrypt message padded with 256 bits/32 bytes
    encryptedMessage = cipher.encrypt(message)
    return encryptedMessage

# Purpose: decrypt message and remove padding
# Parameters: encrypted message, AES or RSA cipher and amount of pad bytes to be removed
# Return: decoded and unpadded message
def decrypt_message(encryptedMessage, cipher, padBytes):
    return cipher.decrypt(encryptedMessage)

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

def client():
    serverName = input("Enter the server IP or name: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    formatted_credentials = f'{username};{password}'
    # port is set to 13000
    port = 13000
    try: 
        # AF_NET = IPv4, SOCK_DGRAM = TCP
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        print("Error creating connection socket:", err)
        sys.exit()
    
    # MAIN INTERFACE LOOP FOR CLIENT
    try:
        # attempt to connect to server with specified IP and port
        clientSocket.connect((serverName, port))
        # main client interface loop
        server_PublicKey_cipher = create_assymetric_cipher("server_public.pem")
        encrypted_credentials = encrypt_message(string_to_binary(formatted_credentials), server_PublicKey_cipher, 256)
        sendMessage(encrypted_credentials, clientSocket)
        
        
        # either client receives Terminating message or the menu
        msg = receiveMessage(clientSocket)
        
        msg.decode("ascii")
        print(binary_to_string(msg))
        
        
    except socket.error as err:
            print("Error:", err)
            sys.exit(1)

client()