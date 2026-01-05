# Description
# Project Overview

The project aims to implement a simplified version of RSA encryption to secure the connection between a client and a server, and then to encrypt and decrypt messages between the client and server using a symmetric encryption implementation. Providing an understanding of how RSA and AES encryption algorithms work hand-in-hand to secure messages sent between a client and server.

# How it works

The logic begins when the command python3 crypto_server.py 5001 (or any port number between 1024–49151) is executed in the terminal. The server starts up and prompts the user to enter two prime numbers within the required constraints. After these values are entered, the server uses them to generate the RSA keys, then begins listening for a client connection.
A connection is established when the client is started with the command: python3 crypto_client.py localhost 5001 Once this command is executed, the client connects to the server through the socket.
With the connection established, the server and client enter the communication loop that implements the cryptographic protocol. The client first sends a list of the encryption algorithms it supports. The server responds by selecting the symmetric and asymmetric algorithms it will use(AES for symmetric encryption and RSA for asymmetric encryption), and sends this information back to the client along with its RSA public key and a nonce.
From here, the client uses the RSA algorithm to securely exchange and verify sensitive data such as the session key and the encrypted nonce. Once both sides have successfully shared and confirmed the AES session key, the system switches to using the AES algorithm to encrypt the integers exchanged between the client and server. The server then computes the sum of the integers and returns it to the client, still using AES encryption.
