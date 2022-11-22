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
	encryptedMessage = cipher.encrypt(pad(message.encode('ascii'), padBytes))
	return encryptedMessage

# Purpose: decrypt message and remove padding
# Parameters: encrypted message, AES or RSA cipher and amount of pad bytes to be removed
# Return: decoded and unpadded message
def decrypt_message(encryptedMessage, cipher, padBytes):
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

def main():
	clients = read_user_pass()
	client_names = []
	for username in clients:
		client_names.append(username)
	# create folders for client emails
	return

main()