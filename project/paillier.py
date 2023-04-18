import random

def gcdExtended(a, b):
    #credit: https://www.geeksforgeeks.org/python-program-for-basic-and-extended-euclidean-algorithms-2/
    if a == 0 :
        return b,0,1
    gcd,x1,y1 = gcdExtended(b%a, a)
    x = y1 - (b//a) * x1
    y = x1  
    return gcd,x,y

def carmichael(n):
    coprimes = []

    for i in range(1,n):
        if gcdExtended(i, n)[0] == 1:
            coprimes.append(i)
    k = 1
    i = 0
    res = True
    check = 0
    while check != 1:
        res = True
        for i in range(len(coprimes)):
            check = exponentMod(coprimes[i], k, n)
            if check != 1:
                res = False
                break
        if res == False:
            k += 1
    return k

def L(x, n):
    return (x-1)//n

def getInverse(a, b):
    return gcdExtended(a, b)[1]

def encryptor(plaintext: str, r: int = 35145, g: int = 6497955158, n: int = 293*433) -> int:
    x = pow(g, int(plaintext), n*n)
    y = pow(r, n, n*n)
    return exponentMod(x*y, 1, n*n)

def add(p1: str, p2: str, r: int = 35145, g: int = 6497955158, n: int = 293*433) -> int:  
    #adds 2 plaintexts according to the formula then decrypts the result (showing the plaintext sum)
    encrypted_p1 = encryptor(p1, r, g, n)
    encrypted_p2 = encryptor(p2, r, g, n)
    product = encrypted_p1*encrypted_p2
    return pow( decryptor(product, g, n), 1, n*n )

def decryptor(ciphertext: int , g: int = 6497955158, n: int = 293*433) -> int:
    u = 53022
    thing2 = pow(ciphertext, carmichael(n), n*n)
    thing2 = L(thing2, n)

    #return exponentMod(thing2*u, 1, n)
    return pow(thing2*u, 1, n)