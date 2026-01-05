# Client to implement simplified RSA algorithm and then subsequently send
# encrypted prime numbers to a server. The client says hello to the server
# and indicates
# which cryptographic algorithms it can support. The server picks one
# asymmetric key and one symmetric key algorithm and then responds to the
# client with its public key and a nonce. The client generates a symmetric
# key to send to the server, encrypts the symmetric key with the public key,
# and then encrypts the nonce with the symmetric key.
# If the nonce is verified, then the server will send the "104 Nonce Verified"
# message.

import socket
import math
import random
import sys
import simplified_DES
import simplified_AES
from NumTheory import NumTheory

# Author: 
# Last modified: 2025-11-17
# Version: 0.1
#!/usr/bin/python3

class RSAClient:
    def __init__(self, address, port):
        self.address = address
        self.port = int(port)
        self.socket = socket.socket()
        self.lastRcvdMsg = None
        self.sessionKey = None		#For storing the symmetric key
        self.modulus = None		    #For storing the server's n in the public key
        self.serverExponent = None	#For storing the server's e in the public key

    def connect(self):
        self.socket.connect((self.address, self.port))
        


    def send(self, message):
        self.socket.send(bytes(message,'utf-8'))

    def read(self):
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Server is unavailable")

    def close(self):
        print("closing connection to", self.address)
        try:
            self.socket.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f"{self.address}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None

    def RSAencrypt(self, msg):
        """"This function will return (msg^exponent mod modulus) and you"""
        """ *must* use the expMod() function. You should also ensure that"""
        """  msg < n before encrypting"""
        """You will need to complete this function."""
        if msg<self.modulus:
            return NumTheory.expMod(msg, self.serverExponent, self.modulus)

    def computeSessionKey(self):
        """Computes this node's session key"""
        """Update this method such that you are guaranteed correct results"""
        self.sessionKey = random.randint(16384, 65535)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext

    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def serverHello(self):
        status = "101 Hello 3DES, AES, RSA16, DH16"
        return status

    def sessionKeyMsg(self,nonce):
        """Function to generate response string to server's hello"""
        encryptedSessionKey= self.RSAencrypt(self.sessionKey)
        encryptedNonce= self.AESencrypt(nonce)
        status = "103 SessionKey " + ", " + str(encryptedSessionKey) + ", " + str(encryptedNonce)
        return status

    def encryptedintmsg(self): 
        status = "113 IntegersEncrypted" + ", " + str({self.AESencrypt(int1)}) + ", " + str(encryptedNonce)
        return status




    def start(self):
        """Main sending and receiving loop for the client"""
        self.connect()
        self.send(self.serverHello())
        self.read()
        print(self.lastRcvdMsg)

        #extraact and store data from last msg
        msg= self.lastRcvdMsg
        parts= msg.split(",")
        self.modulus = int(parts[2])
        self.serverExponent  = int(parts[3])
        nonce = int(parts[4])
        
        self.computeSessionKey()
        #print("sessionkey:",self.sessionKey)
        self.send(self.sessionKeyMsg(nonce))
        self.read()
        msg2 = self.lastRcvdMsg
        print(msg2)

        int1 = int(input('Client : Enter integer 1: '))
        int2 = int(input('Client : Enter integer 2: '))
        localsum = int1 + int2
        #print("localsum:",localsum)

        self.send(f"113 IntegersEncrypted {self.AESencrypt(int1)} {self.AESencrypt(int2)}")
        self.read()
        msg3 =self.lastRcvdMsg
        print(msg3)

        parts = self.lastRcvdMsg.split(sep=" ")
        Servers_sum = (parts[2])
        #print("servers_sum:", Servers_sum)
            
        if str(Servers_sum) == str(self.AESencrypt(int1 + int2)):
                self.send("200 OK")
                #print("Client : 200 OK")
                  
                

        else:
                  
            self.send("400 Error")
            print("Client : 400 Error")
    
    
        


        self.close()
        


def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 3:
        print ("Please supply a server address and port.")
        sys.exit()
    print("Client of Antonette Robinson")
    serverHost = str(args[1])       # The remote host
    serverPort = int(args[2])       # The same port as used by the server

    client = RSAClient(serverHost, serverPort)
    try:
        client.start()
    except (KeyboardInterrupt, SystemExit):
        exit()

if __name__ == "__main__":
    main()
