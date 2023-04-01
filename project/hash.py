import secrets

K_vals = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]

def functions(x: int, y: int, z: int, t: int) -> int:
    t = t // 20

    if t == 0:
        return (x & y) ^ ((~x) & z)
    elif t == 1 or t == 3:
        return x ^ y ^ z
    else:
        return (x & y) ^ (x & z) ^ (y & z)

def pad(msg: str) -> str:
    msg = ''.join([format(ord(c), '08b') for c in msg])

    padding = '1'
    l = len(msg)
    
    k = (448 - 1 - l) % 512
    padding += '0'*k

    padding += format(l, '064b')

    return msg + padding


def rotl(n: int, bitlength: int, num_bits: int) -> int:
    return ((n << num_bits) | (n >> (bitlength - num_bits))) & (2**bitlength - 1)


def sha1(msg: str) -> str:
    H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    msg = pad(msg)
    msg = [int(msg[i:i+512], 2) for i in range(0, len(msg), 512)] 

    modulus = 2**32

    for block in msg:
        W = []
        for t in range(16):
            shift_size = (15-t) * 32
            W.append((block >> shift_size) & 0xffffffff) 
        for t in range(16, 80):
            tmp = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
            W.append(rotl(tmp, 32, 1))

        a, b, c, d, e = H

        for t in range(80):
            T = (rotl(a, 32, 5) + functions(b, c, d, t) + e + K_vals[t//20] + W[t]) % modulus
            e = d
            d = c
            c = rotl(b, 32, 30)
            b = a
            a = T

        H[0] = (a + H[0]) % modulus
        H[1] = (b + H[1]) % modulus
        H[2] = (c + H[2]) % modulus
        H[3] = (d + H[3]) % modulus
        H[4] = (e + H[4]) % modulus

    return ''.join([format(i, '08x') for i in H])

hmac_keys = {}

def hmac(msg: str, key: str) -> str:
    B = 64

    if len(key) > 2*B: 
        key = sha1(key)
    while len(key) < 2*B:
        key += '00'
    
    if key in hmac_keys:
        x_ipad, x_opad = hmac_keys[key]
    else:
        key_bytes = [int(key[i:i+2], 16) for i in range(0, len(key), 2)]
        x_ipad = ''.join([format(a ^ 0x36, '02x') for a in key_bytes])
        x_opad = ''.join([format(a ^ 0x5c, '02x') for a in key_bytes])

        hmac_keys[key] = (x_ipad, x_opad)

    return sha1(x_opad + sha1(x_ipad + msg))

def generate_mac_key():
    return format(secrets.randbits(32*8), '064x')
