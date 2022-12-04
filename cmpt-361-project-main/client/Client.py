import json
import socket
import os,glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

'''
Purpose: converts binary strings to regular strings
Parameter: a binary string
Returns: the decode string'''
def binary_to_string(bin_str):
    return bin_str.decode('utf-8')
'''
Purpose: convers regular string to binary string
Parameter: regular string
Returns: string into binary string
'''
def string_to_binary(string):
    return string.encode('utf-8')
'''
# Purpose: creates cipher from public or private key file
# USE FOR PUBLIC AND PRIVATE KEY CIPHERS
# Parameters: file name of key
# Return: generated cipher
'''
def create_assymetric_cipher(fileName):
	with open(fileName, "rb") as key_file:
		key_data = key_file.read()
	key = RSA.import_key(key_data)
	cipher = PKCS1_OAEP.new(key)
	return cipher
'''
# Purpose: pad and encrypt message to be sent
# Parameters: message string, AES or RSA cipher, required pad bytes
# Return: encrypted and padded message
'''
def encrypt_message(message, cipher):
	# encrypt message padded with 256 bits/32 bytes
	encryptedMessage = cipher.encrypt(message)
	return encryptedMessage
'''
Purpose: encryptes a message given witha chipher and pads , cipher: a cipher used to encrypt the message
Parameter: message: a string message to be sent
Return: the encrypted message
'''
def encrypt_symmetric_message(message, cipher):
	padBytes = int(256/8)
	encryptedMessage = encryptedMessage = cipher.encrypt(pad(message.encode('ascii'), padBytes))
	return encryptedMessage
	
'''
Purpose: decrypts an encrypted message with a given cipher
Parameters: encrypted string message and cipher used in encrypt/decryption
Return: the decrypted string message
'''
def decrypt_symmetric_message(encryptedMessage, cipher):
	padBytes = int(256/8)
	padded_message = cipher.decrypt(encryptedMessage)
	unpadded_message = unpad(padded_message, padBytes)
	decoded_message = unpadded_message.decode('ascii')
	return decoded_message
'''
# Purpose: decrypt message and remove padding
# Parameters: encrypted message, AES or RSA cipher and amount of pad bytes to be removed
# Return: decoded and unpadded message
'''
def decrypt_message(encryptedMessage, cipher):
	return cipher.decrypt(encryptedMessage)
'''
# Purpose: send message to specified socket
# Parameters: message, socket to send to
'''
def sendMessage(message, socketType):
	socketType.send(message)
	return

'''
# Purpose: receive message from specified socket
# Parameters: socket
# Return: received message
'''
def receiveMessage(socketType):
	message = socketType.recv(2048)
	return message

'''
Purpose: Constructs an email of the proper format with user inputed values
Parameters:
   sender - client who wants to send the message
   reciever - clients who are to recieve the message
   title - title of the email
   content - the message content
Returns:
   email - string containing the formatted string for the email
'''
def construct_email(sender, reciever, title, content): 
    content_length = str(len(content)) #gets the content length

	#creates a list of strings to join together
    msg_list = ["From: ", sender, "\n", 
                "To: ", reciever, "\n",
                "Title: ", title, "\n",
                "Content Length: ", content_length, "\n",
                "Content: \n", content]

	#takes the list of strings and creates one string for the whole email
    email = "".join(msg_list)

    return email

'''
Purpose: Verifies that the content and the title are within the character limit
Parameters:
   title - string containing the email title
   content - string containing the email message contents
Returns:
   boolean - True if the variables are within the limit, false if not
'''
def verify_email(title, content): 
    if len(title) > 100: #Checking the title limit
        print("Title length exceeded 100")
        return False
    if len(content)> 1000000: #Checking the content limit
        print("Content length exceeded 1,000,000")
        return False
    return True

'''
Purpose: Send the email subprotocol
Parameters:
   socket - contains the socket to send through
   cipher - to encrypt/decrypt messages
Returns:
   None
'''
def send_email(socket, user, cipher): 
	#get user input
    send_to = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")
    load_file = input("Would you like to load contents from a file? (Y/N) ")

	#checks if the user wants to load in a message
    if load_file.upper() == "Y":
        filename = input("Enter filename: ")
        f = open(filename, "r")
        message = f.read()
        f.close()
    else:
        message = input("Enter message contents: ")

	#verifies the title and the content lengths
    if verify_email(title, message) == False:
        return

	#builds the email
    email = construct_email(user, send_to, title, message)
    len_email = str(len(email))
    sendMessage(encrypt_symmetric_message(len_email, cipher), socket)
    message = decrypt_symmetric_message(receiveMessage(socket), cipher)
	
    
    #send the email to server
    sendMessage(encrypt_symmetric_message(email, cipher), socket)

	#prints message to client 
    print("The message is sent to the server.")
    message = decrypt_symmetric_message(receiveMessage(socket), cipher)
    if "Corrupted" in message:
        print("The message corrupted. Try again\n")
        send_email(socket, user, cipher)
    return


'''
Parameters: None
Purpose: Serves the client side of the programming allowing them to acces the the email protocols
and login into a email system
Returns: None
'''
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
			if "Connection Terminated" in message:
				print("The connection is terminated with the server.")
				clientSocket.close()
				return
			elif "Send the email" == message:
				send_email(clientSocket, username, symmetric_cipher)
			else:
				print(message, end=' ')
				# or statement to check to ensure string is not empty
				input_message = input() or " "
				sendMessage(encrypt_symmetric_message(input_message, symmetric_cipher), clientSocket)
		
	except socket.error as err:
			print("Error:", err)
			sys.exit(1)

client()