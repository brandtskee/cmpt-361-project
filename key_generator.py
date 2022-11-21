import json
import socket
import os,glob, datetime
import sys
from Crypto.PublicKey import RSA


# Purpose: generate public and private keys for clients
# Parameters: public key name, private key name
def keyGenClient(public_name, private_name):
	# generate 2048 bit key
	key = RSA.generate(2048)
	private_key = key.export_key()
	# change directory to client
	os.chdir("client")
	file_out = open(private_name, "wb")
	file_out.write(private_key)
	file_out.close()

	# export public key
	public_key = key.public_key().export_key()
	file_out = open(public_name, "wb")
	file_out.write(public_key)
	file_out.close()
	# change to server directory
	os.chdir("..")
	os.chdir("server")
	# export client public key to server directory
	public_key = key.public_key().export_key()
	file_out = open(public_name, "wb")
	file_out.write(public_key)
	file_out.close()
	# change working directory back to parent directory
	os.chdir("..")
	return

# Purpose: generate all keys needed for the server
def keyGenServer():
	# generate 2048 bit keys
	key = RSA.generate(2048)
	private_key = key.export_key()
	public_key = key.public_key().export_key()
	# export private key to server
	os.chdir("server")
	private_file = open("server_private.pem", "wb")
	private_file.write(private_key)
	private_file.close()
	# export public key to server
	public_out = open("server_public.pem", "wb")
	public_out.write(public_key)
	public_out.close()
	# change directory to client and write public key
	os.chdir("..")
	os.chdir("client")
	public_out = open("server_public.pem", "wb")
	public_out.write(public_key)
	public_out.close()
	os.chdir("..")
	return

def key_generator():
	# Generate keys for each client
	clients = ["client1", "client2", "client3", "client4", "client5"]
	for i in clients:
		private_name = f'{i}_private.pem'
		public_name = f'{i}_public.pem'
		keyGenClient(public_name, private_name)
	keyGenServer()
	return

key_generator()