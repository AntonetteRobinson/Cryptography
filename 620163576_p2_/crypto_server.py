# Server to implement the simplified RSA algorithm and receive encrypted
# integers from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.

# Author: 
# Last modified: 2025-11-17
# Version: 0.1.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_DES
import simplified_AES
from NumTheory import NumTheory


class RSAServer(object):
    
    def __init__(self, port, p, q):
        self.socket = socket.socket()
        # The option below is to permit reuse of a socket in less than an MSL
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", int(port)))
        self.socket.listen(5)
        self.lastRcvdMsg = None
        self.sessionKey = None		#For storing the symmetric key
        self.modulus = None		#For storing the server's n in the public/private key
        self.pubExponent = None	#For storing the server's e in the public key
        self.privExponent = None	#For storing the server's d in the private key
        self.nonce = None
        # Call the methods to compute the public private/key pairs
        

    def send(self, conn, message):
        conn.send(bytes(message,'utf-8'))

    def read(self):
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Client is unavailable")

    def close(self, conn):
        print("closing server side of connection")
        try:
            conn.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f" {repr(e)}",
            )
        finally:
            # Delete reference to socket object
            conn = None    

    def RSAencrypt(self, msg):
        """Encryption side of RSA"""
        """"This function will return (msg^exponent mod modulus) and you *must*"""
        """ use the expMod() function. You should also ensure that msg < n before encrypting"""
        """You will need to complete this function."""
        if msg< self.modulus:
            return NumTheory.expMod(msg, self.pubExponent, self.modulus)

    def RSAdecrypt(self, cText):
        """Decryption side of RSA"""
        """"This function will return (cText^exponent mod modulus) and you *must*"""
        """ use the expMod() function"""
        """You will need to complete this function."""

        return NumTheory.expMod(cText, self.privExponent, self.modulus)


    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext

    def generateNonce16(self):
        """This method returns a 16-bit random integer derived from hashing the
            current time. This is used to test for liveness"""
        hash = hashlib.sha1()
        hash.update(str(time.time()).encode('utf-8'))
        self.nonce = int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)
        
    def findE(self, phi):
        """Method to randomly choose a good e given phi"""
        """You will need to complete this function."""
        """Consider choosing a valid random e from one of 3, 17, or 257"""
        for i in range (3,phi):
            if NumTheory.gcd_iter(i, phi) ==1:
                return i

    def genKeys(self, p, q):
        """Generates n, phi(n), e, and d"""
        """You will need to complete this function."""
        print(p,q)
        self.modulus = p*q
        phi = (p-1)*(q-1)
        self.pubExponent= self.findE(phi)
        self.privExponent = NumTheory.ext_Euclid(phi,self.pubExponent)

        print(f"n= {self.modulus}, phi= {phi}, e= {self.pubExponent}, d= {self.privExponent}")

    def clientHelloResp(self):
        """Generates response string to client's hello message"""
        self.generateNonce16()
        status = "102 Hello AES, RSA16, " + str(self.modulus) + ", " + \
         str(self.pubExponent) + ", " + str(self.nonce)
        return status

    def nonceVerification(self, decryptedNonce):
        """Verifies that the transmitted nonce matches that received
        from the client."""
        """You will need to complete this function."""
        return self.nonce == decryptedNonce


    def start(self):
        """Main sending and receiving loop"""
        """You will need to complete this function"""
        while True:
            connSocket, addr = self.socket.accept()
            #self.socket.connect((self.address, self.port))
            msg = connSocket.recv(1024).decode('utf-8')
            print (msg)
            
            self.send(connSocket, self.clientHelloResp())
            msg2 = connSocket.recv(1024).decode('utf-8')
            print(msg2)

            #decrypt sessionkey and nonce
            parts = msg2.split(",")
            encryptedsessionkey= int(parts[1])
            encryptednonce = int(parts[2])

            self.sessionKey = self.RSAdecrypt(encryptedsessionkey)
            #print("decryptedsessionkey:",self.sessionKey)

            decryptedNonce= self.AESdecrypt(encryptednonce)
            #print("decryptednonce:",decryptedNonce)

            if self.nonceVerification(decryptedNonce) == True:
                    self.send(connSocket, "104 Nonce Verified")
                    print("104 Nonce Verified")
            else:
                    self.send(connSocket, "400 Error")
                    self.close(connSocket)
                    #print("Server : 400 Error")
            
            msg3 = connSocket.recv(1024).decode('utf-8')
            print(msg3)

            parts = msg3.split(sep=" ")

            int1 = self.AESdecrypt(int(parts[2]))
            int2 = self.AESdecrypt(int(parts[3]))

            #print("decrypted int 1:", int1)
            #print("decrypted int 2:", int2)

                    
            sum = int1+ int2
            #print("sum:",sum)

            self.send(connSocket,f"114 CompositeEncrypted {self.AESencrypt(sum)} ")
            print(f"114 CompositeEncrypted {self.AESencrypt(sum)} ")


            msg4 = connSocket.recv(1024).decode('utf-8')
            print(msg4) 
 

            

            self.close(connSocket)
            break

def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 2:
        print ("Please supply a server port.")
        sys.exit()
        
    HOST = ''		# Symbolic name meaning all available interfaces
    PORT = int(args[1])     # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()
    print("Server of Antonette Robinson")
    print ("""Enter prime numbers. One should be between 211 and 281,
    and the other between 229 and 307. The product of your numbers should
    be less than 65536""")

    prime = False

    while prime != True:
        p = int(input('Enter P: '))
        q = int(input('Enter Q: '))
    
        if NumTheory.IsPrime(p) and NumTheory.IsPrime(q):
            if 281 > p and p > 211 and 307 > q and q > 229:
                if p*q < 65536:
                    prime = True
                else:
                    print("p*q != 65536\n")
            else:
                print("Number not in range\n")
        else:
            print("Number not prime\n")


    
    server = RSAServer(PORT, p, q)
    server.genKeys(p,q)
    server.start()

if __name__ == "__main__":
    main()
