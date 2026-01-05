# Server to implement the simplified RSA algorithm and receive encrypted
# integers from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.



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

        #given a  msg to encrypt we use the formula c = m^e modn , and should ensure that the msg is < n . expmod returns (b^n mod m)
        if msg < self.modulus:
            #encrypt msg
           return NumTheory.expMod(msg,self.pubExponent,self.modulus)
        

    def RSAdecrypt(self, cText):
        """Decryption side of RSA"""
        """"This function will return (cText^exponent mod modulus) and you *must*"""
        """ use the expMod() function"""
        """You will need to complete this function."""

        # given a the encrpyted msg, return the plaintext of the message.expmod returns (b^n mod m). formula for decrypt m = c^d modn
        print("d:", self.privExponent)
        print("n:", self.modulus)
        print("ctext:", cText)
        return NumTheory.expMod(cText,self.privExponent,self.modulus)
    

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
        # given a list of possible value of e, iterate through the list and find the suitable e that matches the condtion
        for i in range(3,phi):
            if  NumTheory.gcd_iter(i, phi) == 1:
                #print("The e calculated from findE:")
                return i
            
    def genKeys(self, p, q):
        """Generates n, phi(n), e, and d"""
        """You will need to complete this function."""
        print(p,q)
        self.modulus= p*q    #store the calculation of n in the attribute modulus
        phi = (p-1)*(q-1)
        self.pubExponent= self.findE(phi)  #store the calculation of e in the attribute pubExponent
        self.privExponent= NumTheory.ext_Euclid(phi, self.pubExponent) #store the calculation of d in the attribute privExponent
         

        #print n,phi,e,d to the standard output
        print(f"n ={self.modulus}, phi = {phi}, e ={self.pubExponent}, d ={self.privExponent}")

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
        

            if "103" in msg:
                    data = msg.split(",")
                    self.sessionKey = self.RSAdecrypt(int(data[1]))
                    decryptedNonce = self.AESdecrypt(int(data[2]))
                    if self.nonceVerification(decryptedNonce) == True:
                        self.send(connSocket, "104 Nonce Verified")
                        print("Server : 104 Nonce Verified")
                    else:
                        self.send(connSocket, "400 Error")
                        print("Server : 400 Error")
                        break

            # if "113" in msg:
            #         data = msg.split(sep=" ")
            #         int1 = self.AESdecrypt(int(data[2]))
            #         int2 = self.AESdecrypt(int(data[3]))
                    
            #         sum = int1+ int2

            #         self.send(connSocket,f"114 CompositeEncrypted {self.AESencrypt(sum)} ")
            #         print(f"Server : 114 CompositeEncrypted {self.AESencrypt(sum)} ")
                
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
    p = int(input('Enter P: '))
    q = int(input('Enter Q: '))
    
    server = RSAServer(PORT, p, q)
    server.genKeys(p,q) #with the given p and q generate keys
    server.start()

    

    



if __name__ == "__main__":
    main()
