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
        #get all the users and their associated hashes and their money
        self.usertopass = json.loads(open("atm_secret/usertohashpass.txt", "r").read()) 
        self.usertomoney = json.loads(open("atm_secret/usertomoney.txt", "r").read())
        self.methods = ['elgamal'] 
        print("Public key methods in use by bank --> ", self.methods)
        self.aeskey = None
        self.mackey = None
        self.counter = 0
        #random large prime
        self.p= 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        self.s = socket.socket()
        self.s.bind(('127.0.0.1',9999))
        self.s.listen(5)
        self.client = None
        self.clientaddr = None

    def countercheck(self, msg):
        if(int(msg[0]) <= self.counter):
            raise Exception("counter check failed or msg tampered with")
        self.counter = int(msg[0]) + 1

    def withdraw(self, usr, amt): 
        sendback = usr + "-"
        if int(self.usertomoney[usr]) - amt < 0:
            sendback += self.usertomoney[usr] + '-' + "cannot overdraw this account"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        else:
            self.usertomoney[usr] = str(int(self.usertomoney[usr]) - amt)
            open("atm_secret/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
            sendback += self.usertomoney[usr] + '-' + "withdraw successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))

    def deposit(self, usr, amt):
        sendback = usr + "-"
        self.usertomoney[usr] = str(int(self.usertomoney[usr]) + amt)
        open("atm_secret/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
        sendback += self.usertomoney[usr] + '-' + "deposit successful"
        sendback = str(self.counter) + '-' + sendback
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
        self.client.send(sendback.encode('utf-8'))

    def check(self, usr):
        sendback = usr + "-"
        sendback += self.usertomoney[usr] + '-' + "check successful"
        sendback = str(self.counter) + '-' + sendback
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
        self.client.send(sendback.encode('utf-8'))
            
    def post_handshake(self):
        count = self.client.recv(4096).decode('utf-8')
        count = aes.decrypt(count,self.aeskey)
        count = count.split('-')
        
        #extract the random number and its hash
        chkhash = count[-1]
        count.remove(chkhash)
        againsthash = '-'.join(count)

        #try to compute our own hash of the random num and see if it matches the expected hash...helps integrity
        if hash.hmac(againsthash, self.mackey) != chkhash:
            sendback = "notverifieduser-0-msg integrity compromised"
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))

        self.counter = int(count[0]) + 1
        sendback = str(self.counter) + '-' + "counter exchange successful"
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
        self.client.send(sendback.encode('utf-8'))

        #now handle user log in and actual bank operations
        loggedin = False
        loginname = ""
        while True:
            cmd = self.client.recv(4096).decode('utf-8')
            if len(cmd) == 0:
                # Socket is closed
                self.s.close() 
                return

            cmd = aes.decrypt(cmd, self.aeskey)
            cmd = cmd.split('-')
            try:
                self.countercheck(cmd)
            except Exception as e:
                print(str(e))
                break           

            chkhash = cmd[-1]
            cmd.remove(chkhash)
            againsthash = '-'.join(cmd)

            if chkhash != hash.hmac(againsthash, self.mackey):
                sendback = 'notverifieduser-0-message tampered'
                sendback = str(self.counter) + '-' + sendback
                senback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            cmd = cmd[1:]
            if cmd[0] not in list(self.usertopass.keys()):
                sendback = "notverifieduser-0-username not known in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            if cmd[1] != self.usertopass[cmd[0]]:
                sendback = cmd[0] + "-0-password not matching in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            loggedin = True
            loginname = cmd[0]
            sendback = loginname + "-"
            sendback += self.usertomoney[loginname] + '-' + "login successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))
            break
        

        while True:
            cmd = self.client.recv(4096).decode('utf-8')
            if len(cmd) == 0:
                break

            cmd = aes.decrypt(cmd,self.aeskey)
            cmd = cmd.split('-')
            try:
                self.countercheck(cmd)
            except Exception as e:
                print(str(e))
                break           

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

            if cmd[0] not in list(self.usertopass.keys()):
                sendback = "notverifieduser-0-username not known in bank(tampered name error)"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

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
            
        self.s.close()

    def starthandshake(self): 
        #a client has connected, get their preferences
        self.client, self.clientaddr = self.s.accept()
        clienthello = self.client.recv(1024)
        clienthello = clienthello.decode('utf-8').split('-')
        atmprefs = json.loads(clienthello[0])
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
            keypairs = elgamal.load_keys("atm_secret/bank-elgamal.txt", 1024)
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
        self.aeskey = pow(int(cliplain[0]), dhprivateaes, self.p) % pow(2,256)
        self.mackey = pow(int(cliplain[1]), dhprivatemac, self.p) % pow(2,256)
        self.aeskey = format(self.aeskey, '064x')
        self.mackey = format(self.mackey, '064x')
        print("Handshake info --> bank calculated aes/mac keys from DH exchange")
        print(f"Handshake info --> Bank ready to go, atm replied {aes.decrypt(self.client.recv(1024).decode('utf-8'),self.aeskey)}")

        #*symmetric key crypto* every message we send to the client can now be encrypted and decrypted via actual aes key
        self.client.send((aes.encrypt("finished", self.aeskey)).encode('utf-8'))

        #issue client a challenge to pass (using their own PKC-public key), based on the chosen PKC
        client_keyname = aes.decrypt(self.client.recv(1024).decode('utf-8'), self.aeskey)
        challenge = format(secrets.randbits(20*8), '040x')
        try:
            if scheme == 'rsa':
                client_pubkey = rsa.load_public_key(f"atm_secret/{client_keyname}-rsa.pub")
                challenge_encrypted = rsa.encrypt(challenge, client_pubkey)
            else:
                client_pubkey = elgamal.load_public_key(f"atm_secret/{client_keyname}-elgamal.pub")
                challenge_encrypted = elgamal.encrypt(challenge, client_pubkey)
        except:
            self.client.close()
            raise Exception('client identifier is invalid')

        self.client.send(aes.encrypt(str(challenge_encrypted), self.aeskey).encode('utf-8')) 

        #if client response is good, accept them
        client_response = aes.decrypt(self.client.recv(1024).decode('utf-8'), self.aeskey)
        if client_response != hash.sha1(challenge + self.aeskey):
            self.client.close()
            raise Exception("client is not an atm")

        self.post_handshake()

if __name__ == "__main__":
    testbank = Bank()
    testbank.starthandshake()
