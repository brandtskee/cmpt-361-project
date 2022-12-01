import json
import socket
import os,glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
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
def encrypt_message(message, cipher):
	# encrypt message padded with 256 bits/32 bytes
	encryptedMessage = cipher.encrypt(message)
	return encryptedMessage

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

# Purpose: decrypt message and remove padding
# Parameters: encrypted message, AES or RSA cipher and amount of pad bytes to be removed
# Return: decoded and unpadded message
def decrypt_message(encryptedMessage, cipher):
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
		encrypted_credentials = encrypt_message(string_to_binary(formatted_credentials), server_PublicKey_cipher)
		sendMessage(encrypted_credentials, clientSocket)
		try:
			# retrieve symmetric encrypted with client public key and decrypt
			encrypted_symmetric_key = receiveMessage(clientSocket)
			private_key_name = f'{username}_private.pem'
			# decrypt symmetric key with client private key
			client_privatekey_cipher = create_assymetric_cipher(private_key_name)
			symmetric_key = decrypt_message(encrypted_symmetric_key, client_privatekey_cipher)
			symmetric_cipher = AES.new(symmetric_key, AES.MODE_ECB)
			print("SYM KEY: ", symmetric_key)
			# send OK ack encrypted with symmetric key
			acknowledgement = encrypt_symmetric_message("OK", symmetric_cipher)
			sendMessage(acknowledgement, clientSocket)
		except:
			# decode termination error message
			message = encrypted_symmetric_key
			print(message.decode('ascii'))
			clientSocket.close()
			sys.exit()
		
		# interface loop
		while True:
			message = decrypt_symmetric_message(receiveMessage(clientSocket), symmetric_cipher)
			print(message, end=' ')
			# or statement to check to ensure string is not empty
			input_message = input() or " "
			sendMessage(encrypt_symmetric_message(input_message, symmetric_cipher), clientSocket)
			print(input_message, type(input_message))
			if input_message == '1':
				pass
			elif input_message == '2':
				pass
			elif input_message == '3':
				pass
			elif input_message == '4':
				encrypted_terminate = receiveMessage(clientSocket)
				print(encrypted_terminate)
				terminate = decrypt_symmetric_message(encrypted_terminate,symmetric_cipher)
				print(terminate)
				clientSocket.close()
			else:
				pass
	except socket.error as err:
			print("Error:", err)
			sys.exit(1)

client()