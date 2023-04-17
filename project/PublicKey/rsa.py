import PublicKey.utils as utils
import hash
from math import gcd, ceil
from random import randint
import hashlib
from typing import Callable
from sys import byteorder
from os import urandom


def load_keys(filename: str, bitsize: int) -> tuple:
    try:
        f = open(filename, 'r')
        lines = f.readlines()
        
        n = int(lines[0])
        e = int(lines[1])
        d = int(lines[2])

        f.close()
        return ((n, e), (n, d))
    except:
        pub_key, priv_key = generate_keys(bitsize)
        f = open(filename, 'w')
        lines = [pub_key[0], pub_key[1], priv_key[1]]
        f.writelines([str(l) + '\n' for l in lines])
        
        f.close()
        return (pub_key, priv_key)


def load_public_key(filename: str) -> tuple:
    f = open(filename, 'r')
    lines = f.readlines()

    n = int(lines[0])
    e = int(lines[1])

    f.close()
    return (n, e)


def generate_keys(bitsize: int) -> tuple:
    e = 65537
    n = 1

   
    while n < 2**(bitsize-1) or n >= 2**bitsize:
        p = e+1
        while gcd(p-1, e) != 1 or gcd(p, e) != 1:
            p = utils.generate_prime(bitsize//2)
        q = p
        while q == p or gcd(e, q-1) != 1 or gcd(e, q) != 1: 
            q = utils.generate_prime(bitsize//2)

        phi = (p-1) * (q-1)
        d = pow(e, -1, phi)
        n = p * q


        if d >= n or (3*d)**4 < n:
            n = 1 

    pub_key = (n, e)
    priv_key = (n, d)
    return (pub_key, priv_key)

#create random binary string with p octets, turned into bytes type
def rand_key(p: int) -> bytes:
    key1 = ""
    for i in range(p):
        temp = str(randint(0, 1))
        key1 += temp
         
    return bytes(key1, 'utf-8')

def i2osp(x: int, xlen: int) -> bytes:
    '''Converts a nonnegative integer to an octet string of a specified length'''
    return x.to_bytes(xlen, byteorder='big')

def sha1(m: bytes) -> bytes:
    '''SHA-1 hash function'''
    hasher = hashlib.sha1()
    hasher.update(m)
    return hasher.digest()

def xor(data: bytes, mask: bytes) -> bytes:
    '''Byte-by-byte XOR of two byte arrays'''
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked

#a mask generation function as described in RCF 8017
def MGF1(seed: bytes, mlen: int, f_hash: Callable = sha1) -> str:
    t = b''
    hlen = len(f_hash(b''))
    for c in range(0, ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += f_hash(seed + _c)
    return t[:mlen]

#encode a message using OAEP as described in RFC 8017 PKCS #1 v2.2
def oaep_encode(m: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = MGF1) -> bytes:
    '''EME-OAEP encoding'''
    mlen = len(m)
    lhash = f_hash(label)
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = urandom(hlen)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    masked_db = xor(db, db_mask)
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    masked_seed = xor(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db

def encrypt(msg: str, pub_key: tuple) -> int:
    k = 0
    rsa_mod_bin = bin(pub_key[0])
    for i in range( 1,len(rsa_mod_bin)+1 ):
        if i % 8 == 0: #multiple of 8, found an octet
            k += 1
    
    msg_encoded = oaep_encode(bytes(msg, 'utf-8'), k)
    msg_encoded_int = int.from_bytes(msg_encoded, "big")
    return pow(msg_encoded_int, pub_key[1], pub_key[0])

def oaep_decode(c: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = MGF1) -> bytes:
    '''EME-OAEP decoding'''
    clen = len(c)
    lhash = f_hash(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    seed = xor(masked_seed, seed_mask)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    db = xor(masked_db, db_mask)
    _lhash = db[:hlen]

    if lhash != _lhash:
        print("\n\nWARNING ?\n")
    
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else: 
            raise Exception()
    m = db[i:]
    return m

def decrypt(msg: str, priv_key: tuple) -> str:
    decrypted = pow(int(msg), priv_key[1], priv_key[0])

    length = 0
    rsa_mod_bin = bin(priv_key[0])
    for i in range( 1,len(rsa_mod_bin)+1 ):
        if i % 8 == 0: #multiple of 8, found an octet
            length += 1
    decrypted = decrypted.to_bytes(length, "big")
    ret = oaep_decode(decrypted, length)
    return str(ret, 'utf-8')

def sign(msg: str, priv_key: tuple) -> int:
    hashed = int(hash.sha1(msg), 16)

    return pow(hashed, priv_key[1], priv_key[0])


def verify_signature(signature: int, msg: str, pub_key: tuple) -> bool:
    hashed = int(hash.sha1(msg), 16)

    return hashed == pow(signature, pub_key[1], pub_key[0])
