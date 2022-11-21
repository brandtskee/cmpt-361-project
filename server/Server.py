import json
import socket
import os,glob, datetime
import sys

# Purpose: returns a dictionary of usernames and
# passwords from user_pass.json
# Return: dictionary of client usernames and passwords (clients)
def read_user_pass():
	user_json = open("user_pass.json", "r")
	clients = json.load(user_json)
	user_json.close()
	return clients

# Purpose: make directories for clients if they do not exist already.
# These folders need to exist in order to store emails for respective clients.
# Parameters: list of client usernames (usernames)
def make_client_directories(usernames):
	for username in usernames:
		if os.path.exists(username) == False:
			os.mkdir(username)
	return

def main():
	clients = read_user_pass()
	client_names = []
	for username in clients:
		client_names.append(username)
	# create folders for client emails
	make_client_directories(client_names)
	return

main()