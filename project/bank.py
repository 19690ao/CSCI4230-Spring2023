import json
import hash
import socket
import select
import secrets
from PublicKey import rsa
from PublicKey import elgamal
from PrivateKey import aes

class Bank:
    def __init__(self):
        # Initialize cryptographic module and server
        self.setupCrypt()
        self.setupServer()

    def setupCrypt(self):
        # Load user information from files
        # 'usertohashpass.txt' stores user hashes and passwords
        # 'usertomoney.txt' stores user account balances
        self.usertopass = json.loads(open("atm_secret/usertohashpass.txt", "r").read()) 
        self.usertomoney = json.loads(open("atm_secret/usertomoney.txt", "r").read())

        # Setup counters for failed login attempts
        self.failedlogins = {username: 0 for username in self.usertopass.keys()}

        # Set up public key encryption methods
        self.methods = ['rsa', 'elgamal'] 
        print("Public key methods in use by bank --> ", self.methods)

        # Initialize AES and MAC keys
        self.aeskey = None
        self.mackey = None

        # Initialize counter for message sequence numbers
        self.counter = 0

        # Set large prime number
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

    def setupServer(self):
        # Set up TCP server to listen for client connections
        self.s = socket.socket()
        self.s.bind(('127.0.0.1',9999))
        self.s.listen(5)

        # Initialize client connection variables
        self.client = None
        self.clientaddr = None

    def countercheck(self, msg):
        # Extract message sequence number from first element of message
        seq_num = int(msg[0])

        # Check that sequence number is greater than current counter value
        if seq_num <= self.counter:
            # Raise exception if sequence number is out of order or message has been tampered with
            raise Exception("Message out of order or tampered with")

        # Update counter with new sequence number
        self.counter = seq_num + 1

    def withdraw(self, usr, amt):
        # Start building response message with user ID
        sendback = usr + "-"

        # Check if the user has enough money to withdraw
        if int(self.usertomoney[usr]) - amt < 0:
            # If not, construct message indicating insufficient funds
            sendback += self.usertomoney[usr] + '-' + "cannot overdraw this account"
        else:
            # Otherwise, update user's balance and construct message indicating successful withdrawal
            self.usertomoney[usr] = str(int(self.usertomoney[usr]) - amt)
            open("atm_secret/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
            sendback += self.usertomoney[usr] + '-' + "withdraw successful"

        # Add message sequence number and encrypt message
        sendback = str(self.counter) + '-' + sendback
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)

        # Send encrypted message to client
        self.client.send(sendback.encode('utf-8'))

    def deposit(self, usr, amt):
        # Start building response message with user ID
        sendback = usr + "-"

        # Update user's balance and construct message indicating successful deposit
        self.usertomoney[usr] = str(int(self.usertomoney[usr]) + amt)
        open("atm_secret/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
        sendback += self.usertomoney[usr] + '-' + "deposit successful"

        # Add message sequence number and encrypt message
        sendback = str(self.counter) + '-' + sendback
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)

        # Send encrypted message to client
        self.client.send(sendback.encode('utf-8'))

    def check(self, usr):
        # Start building response message with user ID and balance
        sendback = usr + "-"
        sendback += self.usertomoney[usr] + '-' + "check successful"

        # Add message sequence number and encrypt message
        sendback = str(self.counter) + '-' + sendback
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)

        # Send encrypted message to client
        self.client.send(sendback.encode('utf-8'))

    def handleLogin(self):
        # Continue with user login and bank operations
        loggedin = False
        loginname = ""

        # Loop to handle user login
        while not loggedin:
            # Receive a message from the client and decrypt it using the shared AES key
            cmd = self.client.recv(4096).decode('utf-8')
            if len(cmd) == 0:
                # Socket is closed
                self.s.close()
                return

            # Decrypt the received message and split it into its components
            cmd = aes.decrypt(cmd, self.aeskey)
            cmd = cmd.split('-')

            try:
                self.countercheck(cmd)  # Check if the counter in the message is valid
            except Exception as e:
                print(str(e))
                break           

            # Extract the username, password and hash from the received message
            chkhash = cmd[-1]
            cmd.remove(chkhash)
            againsthash = '-'.join(cmd)

            # Verify the integrity of the received message
            if chkhash != hash.hmac(againsthash, self.mackey):
                sendback = 'notverifieduser-0-message tampered'
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            # Check if the user is registered in the bank
            cmd = cmd[1:]
            username = cmd[0]
            if username not in self.usertopass:
                sendback = "notverifieduser-0-username not known in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue
            
            # Check if the account is locked
            if self.failedlogins[username] >= 5:
                sendback = "notverifieduser-0-account locked (too many login attempts)"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            # Check if the password is correct
            password = cmd[1]
            if password != self.usertopass[username]:
                sendback = username + "-0-password not matching in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                self.failedlogins[username] += 1
                continue

            # Login successful
            loggedin = True
            loginname = username
            sendback = loginname + "-"
            sendback += self.usertomoney[loginname] + '-' + "login successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        
        return loggedin, loginname
    
    def handleBanking(self, loggedin, loginname):
        # Loop to handle incoming commands from the client and execute them
        while True:
            # Receive a message from the client and decrypt it using the shared AES key
            cmd = self.client.recv(4096).decode('utf-8')
            if len(cmd) == 0:
                break

            # Decrypt the received message and split it into its components
            cmd = aes.decrypt(cmd,self.aeskey)
            cmd = cmd.split('-')

            try:
                self.countercheck(cmd)  # Check if the counter in the message is valid
            except Exception as e:
                print(str(e))
                break           

            # Verify the integrity of the received message
            chkhash = cmd[-1]
            cmd.remove(chkhash)
            againsthash = '-'.join(cmd)
            cmd = cmd[1:]

            if hash.hmac(againsthash,self.mackey) != chkhash:
                sendback = "notverifieduser-0-msg integrity compromised"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            # Check if the user is registered in the bank
            if cmd[0] not in list(self.usertopass.keys()):
                sendback = "notverifieduser-0-username not known in bank(tampered name error)"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            # Execute the requested banking command if the user is logged in
            if cmd[1] == 'withdraw' and loggedin:
                self.withdraw(cmd[0], int(cmd[2]))
            elif cmd[1] == 'deposit' and loggedin:
                self.deposit(cmd[0], int(cmd[2]))
            elif cmd[1] == 'check' and loggedin:
                self.check(cmd[0])
            else:
                sendback = loginname + "-"
                sendback += self.usertomoney[loginname] + '-' + "invalid command"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))

    def post_handshake(self):
        # Receive a message from the client and decrypt it using the shared AES key
        count = self.client.recv(4096).decode('utf-8')
        count = aes.decrypt(count, self.aeskey)
        count = count.split('-')

        # Extract the random number and its hash
        chkhash = count[-1]
        count.remove(chkhash)
        againsthash = '-'.join(count)

        # Verify the integrity of the received message
        if hash.hmac(againsthash, self.mackey) != chkhash:
            sendback = "notverifieduser-0-msg integrity compromised"
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))
            return

        # Update the counter with the received value
        self.counter = int(count[0]) + 1

        # Send a message back to the client with the updated counter
        sendback = str(self.counter) + '-' + "counter exchange successful"
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
        self.client.send(sendback.encode('utf-8'))

        loggedin, loginname = self.handleLogin()
        
        self.handleBanking(loggedin, loginname)

        self.s.close()

    def starthandshake(self): 
        # Hang until a client has connected
        # accept incoming client connection
        self.client, self.clientaddr = self.s.accept()
        # receive client hello message containing the client's preferences for encryption schemes
        clienthello = self.client.recv(1024)
        # split the message by '-' and parse the JSON message
        clienthello = clienthello.decode('utf-8').split('-')
        atmprefs = json.loads(clienthello[0])
        # print message indicating ATM is initiating handshake with BANK server
        print("ATM has initiated handshake, hello to BANK server!")

        #choose a common PKC and make sure the client knows. currently support rsa and elgamal
        atmprefs = [x.lower() for x in atmprefs]
        common = list(set(self.methods) & set(atmprefs))
        scheme = None
        if len(common) == 0:
            self.client.close()
            raise Exception("no common methods between atm/bank")
        else:
            scheme = common[0]
        print(f"Handshake info --> common encryption scheme set to use {scheme}")

        #*PKC* 1.get some public and private keys based on the chosen PKC
        keypairs = None
        if scheme == "rsa":
            keypairs = rsa.load_keys("atm_secret/bank-rsa.txt", 4096)
        else:
            keypairs = elgamal.load_keys("atm_secret/bank-elgamal.txt", 4096)
        pubkey = keypairs[0]
        privkey = keypairs[1]
        self.client.send(scheme.encode('utf-8'))

        #*DH* get client's private keys (used for calculating aes and mac key)
        print("Handshake info --> recieving client random")
        clirand = self.client.recv(4096).decode('utf-8')

        #*DH* generate our own private keys (used for calculating aes and mac key)
        print("Handshake info --> signing client random, server random, and DH parameters")
        dhprivateaes = secrets.randbelow(((self.p - 1) // 2) + 1)
        dhprivatemac = secrets.randbelow(((self.p - 1) // 2) + 1)

        #*digital signature* use chosen PKC and PKC-private key (see 1.) to sign both sets of DH-private keys
        clisign = str(clirand) + '-' + str(pow(2, dhprivateaes, self.p)) + '-' + str(pow(2, dhprivatemac, self.p))
        clie = None
        if scheme == 'rsa':
            clie = rsa.sign(clisign, privkey)
        else:
            clie = elgamal.sign(clisign, privkey, pubkey)

        #send over the client's signed and plaintext private keys
        self.client.send(str(clisign).encode('utf-8'))
        print(f"Handshake info --> client says {self.client.recv(4096).decode('utf-8')}")
        self.client.send(str(clie).encode('utf-8'))
        print(f"Handshake info --> client says {self.client.recv(4096).decode('utf-8')}")

        self.client.send("breaker".encode('utf-8'))#formatting

        cliplain = clirand.split('-')
        #*DH* compute actual aes and mac keys, based off of the private keys of the client and ours
        self.aeskey = pow(int(cliplain[0]), dhprivateaes, self.p) % pow(2,256)  #do the extra mod 2^256 b/c we need length of 256 for AES-256 and SHA-256
        self.mackey = pow(int(cliplain[1]), dhprivatemac, self.p) % pow(2,256)  
        self.aeskey = format(self.aeskey, '064x')
        self.mackey = format(self.mackey, '064x')
        print("Handshake info --> bank calculated aes/mac keys from DH exchange")
        print(f"Handshake info --> Bank ready to go, atm replied {aes.decrypt(self.client.recv(1024).decode('utf-8'),self.aeskey)}")

        #*symmetric key crypto* every message we send to the client can now be encrypted and decrypted via actual aes key
        self.client.send((aes.encrypt("finished", self.aeskey)).encode('utf-8'))

        #issue client a challenge to pass (using their own PKC-public key), based on the chosen PKC
        client_keyname = aes.decrypt(self.client.recv(1024).decode('utf-8'), self.aeskey)
        challenge = secrets.randbelow(pow(6,40))
        try:
            if scheme == 'rsa':
                client_pubkey = rsa.load_public_key(f"atm_secret/{client_keyname}-rsa.pub")
                challenge_encrypted = rsa.encrypt(str(challenge), client_pubkey)
                #print(f"TEMP b2: {challenge}")
            else:
                #print(f"TEMP b4")
                client_pubkey = elgamal.load_public_key(f"atm_secret/{client_keyname}-elgamal.pub")
                #print(f"TEMP b3")
                challenge_encrypted = elgamal.encrypt(str(challenge), client_pubkey)
                #print(f"TEMP b2: {challenge}")
        except:
            self.client.close()
            raise Exception('client identifier is invalid')
        #print(f"TEMP b1: {aes.encrypt(str(challenge_encrypted), self.aeskey).encode('utf-8')}")
        self.client.send(aes.encrypt(str(challenge_encrypted), self.aeskey).encode('utf-8'))  

        #if client response is good, accept them
        client_response = aes.decrypt(self.client.recv(1024).decode('utf-8'), self.aeskey)
        if client_response != hash.sha1(str(challenge) + self.aeskey):
            self.client.close()
            raise Exception("client is not an atm")

        self.post_handshake()

if __name__ == "__main__":
    testbank = Bank()
    testbank.starthandshake()
