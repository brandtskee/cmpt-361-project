import json
import socket
import os,glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

menu = "\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nChoice:"
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
# Purpose: decrypt message and remove padding
# Parameters: encrypted message, AES or RSA cipher and amount of pad bytes to be removed
# Return: decoded and unpadded message
'''
def decrypt_message(encryptedMessage, cipher):
    return cipher.decrypt(encryptedMessage)
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
# Purpose: returns a dictionary of usernames and
# passwords from user_pass.json
# Return: dictionary of client usernames and passwords (clients)
'''
def read_user_pass():
    user_json = open("user_pass.json", "r")
    clients = json.load(user_json)
    user_json.close()
    return clients
'''
# Purpose: make directory for client if they do not exist already.
# These folders need to exist in order to store emails for respective clients.
# Parameters: client (username)
'''
def make_client_directory(username):
    # check if path exists before making directory
    if os.path.exists(username) == False:
        os.mkdir(username)
    return
'''
# Purpose: check formatted username and password (user;pass) with json file to check credentials
# Parameters: formatted credentials (in format user;pass)
# Return: return the username and True if authenticated, False if incorrect
'''
def check_user_pass(formatted_credentials):
    username_pass = formatted_credentials.split(";")
    with open("user_pass.json", "r") as jsonFile:
        clients = json.load(jsonFile)
    for username in clients:
        if username == username_pass[0]:
            if clients[username] == username_pass[1]:
                return username_pass[0], True
    return username_pass[0], False


'''
Purpose: Takes a username and reads the inbox associated with the client username 
Parameters: Username of the client
Returns: the inbox chart of all emails in the inbox
'''
def read_inbox(username):
    if os.path.exists(f'{username}/inbox.json') == False:
        return "The inbox is empty.\n" + menu
    with open(f'{username}/inbox.json', 'r') as jsonFile:
            mail_List = json.load(jsonFile)
    inbox_chart = "\n{:<16}{:<24}{:<34}{:<24}".format("Index","From","DateTime","Title")
    for key in mail_List:
        newLine = "\n{:<16}{:<24}{:<34}{:<24}".format(key, mail_List[key]['sender'], mail_List[key]['datetime'], mail_List[key]['title'])
        inbox_chart += newLine
    inbox_chart += "\n" + menu
    return inbox_chart
'''
Purpose:Takes a client name and gets their dictionary from the jason file
Parameters: clients name in the jason file
Returns: the data and wether its true or false 
'''
def get_dict(cli_nme):
    if os.path.exists(f'{cli_nme}/inbox.json') == False:
        return ' ', False
    f = open(f'{cli_nme}/inbox.json','r')
    data = json.load(f)
    return data, True
'''
Purpose: Uses the inbox and the index to find all info on a specific indexed email
Parameters: the inbox and index of the inbox that the email we want is at
Returns: the file with the email or false if it doesnt exist
'''
def get_email(inbox, index):
    email_exists = False
    for key in inbox:
        if index == key:
            email_exists = True
            cli = inbox[key]['sender']
            title = inbox[key]['title']
    if email_exists == False:
        file = False
    else:
        file = ""+cli+"_"+title+".txt"
    return file

'''
Purpose: Takes a filename and loads the email from it
Parameters: the string filename
Returns: the email
'''
def load_email(filename):
    f = open(filename)
    email = f.read()
    email += "\n"
    return email

'''
Purpose: Takes user input and creates an email string in the correct format
Parameters:
   sender - client who wants to send the message
   reciever - clients who are to recieve the message
   title - title of the email
   content - the message content
   date_time - the date and time as a string
Returns:
   email - string containing the formatted string for the email
'''
def construct_email(sender, reciever, title, content, date_time): 
    content_length = str(len(content)) #gets the length of the message content

    #creates a list of strings to join together
    msg_list = ["From: ", sender, "\n", 
                "To: ", reciever, "\n",
                "Time and Date: ", date_time, "\n",
                "Title: ", title, "\n",
                "Content Length: ", content_length, "\n",
                "Content: \n", content]
    
    #takes the list of strings and creates one string for the whole email
    email = "".join(msg_list)

    return email

'''
Purpose: Takes a formatted email string and seperates it into its components
Parameters:
   email - string containing the email message
Returns:
   sender - client who wants to send the message
   reciever - clients who are to recieve the message
   title - title of the email
   content_length - string of the number of characters in the content
   content - the message content of the email
'''
def deconstruct_email(email):
    section_list = email.split("\n")#split up the email string by newline

    #getting the individual values for each variable
    sender = section_list[0][6:]
    reciever = section_list[1][4:]
    title = section_list[2][7:]
    content_length = section_list[3][16:]
    content = section_list[5]
    
    return sender, reciever, title, content_length, content

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
Purpose: Saves the email into the appropriate clients folders with the correct filenames
Parameters:
   reciever_list - a list of the clients that the email is to be sent to
   sender - string of who sent the email
   title - title of the email
   email - string of the entire email string
Returns:
   None
'''
def save_email(reciever_list, sender, title, date_time, email):
    for reciever in reciever_list: #goes through the clients to recieve the email
        try:
            make_client_directory(reciever)
            filename = reciever + "/" + sender + "_" + title + ".txt" #gets the correct filename for the email
            text_file = open(filename, "w")
            text_file.write(email)
            text_file.close()
            update_json(reciever, {'title': title, 'datetime': date_time, 'sender': sender})
        except:
            continue
    return


'''
Purpose: Updates the inbox.json file to include the metadata for the inbox emails
Parameters:
   client - the name of the reciever
   data - a dictionary with the data
Returns:
   None
'''
def update_json(client, data):
    #checks if the json file exists
    if os.path.exists(f"{client}/inbox.json") == False: 
        file = open(f"{client}/inbox.json", 'w')
        file.close()

    #opens and updates the data in the json file
    with open(f"{client}/inbox.json", 'r+') as inbox:
        if os.path.getsize(f"{client}/inbox.json") == 0:
            index_data = {1:data}
            json.dump(index_data, inbox)
        else:
            inbox_data = json.load(inbox)
            index_data = {len(inbox_data)+1: data}
            inbox_data.update(index_data)
            inbox.seek(0)
            json.dump(inbox_data, inbox)
    return

'''
Purpose: Send the email subprotocol
Parameters:
   socket - contains the socket to send through
   cipher - to encrypt/decrypt messages
Returns:
   None
'''
def send_email(socket, cipher): 
    #send the start message for the sending email subprotocol
    start_msg = "Send the email"
    sendMessage(encrypt_symmetric_message(start_msg, cipher), socket)

    #recieve the email from the user
    email_len = decrypt_symmetric_message(receiveMessage(socket), cipher)
    if email_len != "Too Long":
        len_ack = "Email Length OK"
        sendMessage(encrypt_symmetric_message(len_ack, cipher), socket)
        sent_mail = decrypt_symmetric_message(receiveMessage(socket), cipher) 

        if (int(email_len) == int(len(sent_mail))):
            sendMessage(encrypt_symmetric_message(f"Email OK\n", cipher), socket)
        #get the date and time for the recieved email
            date_time = str(datetime.datetime.now())

            #deconstruct the email to get the individual values
            sender, reciever, title, content_length, content = deconstruct_email(sent_mail)

            #checks the validity of the title and the contents
            if verify_email(title, content) == False:
                return
            
            #print email message to the server
            print("An email from", sender, "is sent to", reciever, 
                "has a content length of", content_length, '.')

            #Reconstruct the email with the date and time added
            email = construct_email(sender, reciever, title, content, date_time)

            #save the email to the appropriate client files
            save_email(reciever.split(";"), sender, title, date_time, email)
            sendMessage(encrypt_symmetric_message(f"Email OK\n", cipher), socket)
        else:
            sendMessage(encrypt_symmetric_message(f"Corrupted Email\n", cipher), socket)
            send_email(socket, cipher)
    return
'''
Purpose: This is the server side where the server can handle up to five clients at a time with
a email server allowing them to write, read and view emails
Parameters: None
Returns: None
'''
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
                #print(acknowledgement)

                # create nonce bytes
                nonce_bytes = get_random_bytes(int(256/8))
                # send bytes encrypted with client public key
                sendMessage(encrypt_message(nonce_bytes, client_publicKey_cipher), connectionSocket)
                # receive nonce encrypted with symmetric key
                received_nonce = receiveMessage(connectionSocket)
                decrypted_nonce = symmetric_cipher.decrypt(received_nonce)

                # check to ensure that decrypted noce matches
                if decrypted_nonce != nonce_bytes:
                    print("Nonce not verified. Terminating")
                    connectionSocket.close()
                    return




                sendMessage(encrypt_symmetric_message(menu, symmetric_cipher), connectionSocket)
                while True:
                    received_input = decrypt_symmetric_message(receiveMessage(connectionSocket), symmetric_cipher)
                    if received_input == '1':
                        send_email(connectionSocket, symmetric_cipher)
                        sendMessage(encrypt_symmetric_message(menu, symmetric_cipher), connectionSocket)
                    elif received_input == '2':
                        formatted_chart = read_inbox(username)
                        sendMessage(encrypt_symmetric_message(formatted_chart, symmetric_cipher), connectionSocket)
                    elif received_input == '3':
                        jsonFile, has_data = get_dict(username)
                        if has_data == False:
                            sendMessage(encrypt_symmetric_message("The inbox is empty.\n\n" + menu, symmetric_cipher), connectionSocket)
                        else:
                            sendMessage(encrypt_symmetric_message("Enter the email index you wish to view: ", symmetric_cipher), connectionSocket)
                            email_index = decrypt_symmetric_message(receiveMessage(connectionSocket), symmetric_cipher)
                            email_file = get_email(jsonFile, email_index)
                            # check if email index exists
                            if email_file == False:
                                sendMessage(encrypt_symmetric_message(f"Email index does not exist.\n{menu}", symmetric_cipher), connectionSocket)
                            else:
                                email_string = "\n" + load_email(f'{username}/{email_file}')
                                email_string += menu
                                sendMessage(encrypt_symmetric_message(email_string, symmetric_cipher), connectionSocket)
                    elif received_input == '4':
                        sendMessage(encrypt_symmetric_message("Connection Terminated", symmetric_cipher), connectionSocket)
                        print(f'Terminating connection with {username}')
                        connectionSocket.close()
                        return
                    else:
                        sendMessage(encrypt_symmetric_message(menu, symmetric_cipher), connectionSocket)
                    
                

    return

main()