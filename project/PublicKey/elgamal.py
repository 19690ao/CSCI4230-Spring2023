import PublicKey.utils as utils
import hash
import random
import secrets
import string
from math import gcd


def load_keys(filename: str, bitsize: int) -> tuple:
    try:
        pub_count = 3
        f = open(filename, 'r')
        lines = f.readlines()

        p = int(lines[0])

        pub_key = tuple([int(l) for l in lines[:pub_count]])
        priv_key = tuple([p] + [int(l) for l in lines[pub_count:]])
        f.close()
        return (pub_key, priv_key)
    except:
        pub_key, priv_key = generate_keys(bitsize)
        f = open(filename, 'w')
        lines = list(pub_key)+list(priv_key)
        f.writelines([str(l) + '\n' for l in lines])
        
        f.close()
        return (pub_key, priv_key)


def load_public_key(filename: str) -> tuple:
    f = open(filename, 'r')
    lines = f.readlines()

    p = int(lines[0])
    alpha = int(lines[1])
    beta = int(lines[2])

    f.close()
    return (p, alpha, beta)

def modinv(a: int, p: int) -> int:
    """
    Returns the modular inverse of a modulo p, if it exists.
    """
    # Compute gcd(a, p) and check if a is invertible
    gcd, x, _ = xgcd(a, p)
    if gcd != 1:
        raise ValueError(f"{a} is not invertible modulo {p}")
    else:
        return x % p

def xgcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean algorithm. Returns gcd(a, b), x, and y
    such that ax + by = gcd(a, b).
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def generate_keys(bitsize: int) -> tuple:
    p = 4
    while not utils.is_prime(p) or p >= 2**bitsize or p < 2**(bitsize-1):
        p = 2 * utils.generate_prime(bitsize-1) + 1 

    phi = p-1
    phi_factors = [2, phi//2]
    alpha = 2
    for i in range(2, p):
        if pow(i, phi//phi_factors[0], p) != 1 and pow(i, phi//phi_factors[1], p) != 1:
            alpha = i
            break

    a = 0
    while a < 1: 
        a = secrets.randbelow(p-1)
    beta = pow(alpha, a, p)
    
    pub_key = (p, alpha, beta)
    priv_key = (p, a)
    return (pub_key, priv_key)

def encrypt(msg: str, pub_key: tuple) -> tuple:
    hash_val = utils.str_to_num(hash.sha1(msg))
    # Add random padding to the plaintext message
    padding = ''.join(random.choices(string.digits, k=len(msg)))
    padded_msg = padding + msg
    # Convert padded message to a number
    padded_num = utils.str_to_num(padded_msg)
    
    p, alpha, beta = pub_key

    k = secrets.randbelow(p-1)
    y1 = pow(alpha, k, p)
    y2 = (padded_num * pow(beta, k, p)) % p
    return (y1, y2, hash_val)

def decrypt(msg: tuple, priv_key: tuple) -> str:
    y1, y2, hash_val = msg
    p, a = priv_key

    # Compute (y1 ** a) % p
    shared_secret = pow(y1, a, p)

    # Compute the modular inverse of shared_secret
    shared_secret_inv = modinv(shared_secret, p)

    # Decrypt the message by multiplying y2 with the modular inverse of shared_secret
    decrypted = (y2 * shared_secret_inv) % p

    # Convert the decrypted integer to a string representation of the original message
    padded_msg = utils.num_to_str(decrypted, p.bit_length())
    
    # Remove the padding from the decrypted message
    padding = padded_msg[:len(padded_msg)//2]
    plaintext = padded_msg[len(padding):]

    # Check hash for tampering
    if (utils.str_to_num(hash.sha1(plaintext)) != hash_val): return ""
    
    return plaintext


def sign(msg: str, priv_key: tuple, pub_key: tuple) -> tuple:
    p, a = priv_key
    alpha = pub_key[1]

    hashed = int(hash.sha1(msg), 16)

    s = 0
    r = 0
    while s == 0:
        k = 1
        while k < 2 or gcd(k, p-1) != 1:
            k = secrets.randbelow(p-1)

        r = pow(alpha, k, p)
        k_inv = modinv(k, p-1)
        s = ((hashed - a*r) * k_inv) % (p-1)

    return (r, s)


def verify_signature(signature: tuple, msg: str, pub_key: tuple) -> bool:
    p, alpha, beta = pub_key

    hashed = int(hash.sha1(msg), 16)

    r, s = signature
    if 0 >= r or r >= p or 0 >= s or s >= p-1:
        return False

    return pow(alpha, hashed, p) == (pow(beta, r, p) * pow(r, s, p)) % p
