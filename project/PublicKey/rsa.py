import PublicKey.utils as utils
import hash
from math import gcd


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



def encrypt(msg: str, pub_key: tuple) -> int:
    msg = utils.str_to_num(msg)

    return pow(msg, pub_key[1], pub_key[0])


def decrypt(msg: int, priv_key: tuple) -> str:
    decrypted = pow(msg, priv_key[1], priv_key[0])

    return utils.num_to_str(decrypted, priv_key[0].bit_length())


def sign(msg: str, priv_key: tuple) -> int:
    hashed = int(hash.sha1(msg), 16)

    return pow(hashed, priv_key[1], priv_key[0])


def verify_signature(signature: int, msg: str, pub_key: tuple) -> bool:
    hashed = int(hash.sha1(msg), 16)

    return hashed == pow(signature, pub_key[1], pub_key[0])
