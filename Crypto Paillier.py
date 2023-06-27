#%%
from sympy import *
import random

##############################################################################

# Tools and fonctions used for the algorithms

##############################################################################

def getprime(k):
    # Returns a random prime number between 2^(k-1) and 2^k
    p = randprime(2**(k-1), 2**k)
    return p

def oplus(X, Y, pk):
    # Returns the encryption of X + Y with X and Y encrypted
    Z = (X * Y) % (pk * pk)
    return Z

def constantProduct(X, y, pk):
    # Returns the encryption of y * X with X encrypted
    Z = pow(X, y, pk * pk)
    return Z

def opposite(X, pk):
    # Returns the encryption of -1 * X with X encrypted
    Z = constantProduct(X, -1, pk)
    return Z

def genkeys(k):
    # Returns a couple made of a public and secret key
    p = getprime(k)
    q = getprime(k)
    while (p == q):
        q = getprime(k)

    N = int(p * q)
    Phi = (p - 1) * (q - 1)
    return [N, mod_inverse(N, Phi)]

def encrypt(m, pk):
    # Returns an encryption of the message m using the public key pk through Paillier
    r = random.randint(1, pk)
    N2 = pk * pk
    c = ((1 + m * pk) * pow(r, pk, N2)) % N2
    return int(c)

def decrypt(c, pk, sk):
    # Returns the decryption of c using the public and secret keys through Paillier
    N2 = pk * pk
    r = pow(c, sk, pk)
    m = ((c * pow(r, -pk, N2)) % N2 -1) // pk
    return int(m)




##############################################################################

# Implementation of the BobDistance protocol : 
# 1. Alice sends [xA] and [yA] to Bob
# 2. Bob sends [x2B + y2B − 2(xAxB + yAyB)] to Alice
# 3. Alice returns dAB

##############################################################################

def AliceEncryption(xA, yA, pk):
    # Alice encrypts her coordinates
    encrypt_xA = encrypt(xA, pk)    
    encrypt_yA = encrypt(yA, pk)
    return encrypt_xA, encrypt_yA

def BobComputing(encrypt_xA, encrypt_yA, xB, yB, pk):
    encrypt_xByB2 = encrypt(pow(xB, 2) + pow(yB, 2), pk)            # Bob computes and encrypts xB^2 + yB^2
    xAxB = constantProduct(encrypt_xA, xB, pk)                      # Bob uses Paillier's homomorphy to encrypt xA * xB
    yAyB = constantProduct(encrypt_yA, yB, pk)                      # and yA * yB
    sumOf = oplus(xAxB, yAyB, pk)   
    toThePower = constantProduct(sumOf, -2, pk)                     # Bob computes and encrypts -2 * (xAxB + yAyB)
    finalSum = oplus(toThePower, encrypt_xByB2, pk)                 # Bob computes and encrypts the final sum
    return finalSum

def AliceDecryption(msg, xA, yA, pk, sk):
    aliceDecrypt = decrypt(msg, pk, sk)             # Alice decrypts Bob's computing 
    xA2 = pow(xA, 2)                                # And adds her own coords xA^2 and yA^2
    yA2 = pow(yA, 2)
    decryption = (aliceDecrypt + xA2 + yA2) % pk
    return sqrt(decryption)
    
def BobDistance(xA, yA, xB, yB):
    pk, sk = genkeys(128)             # Alice generates her keys and shares her public key
    
    encrypt_xA, encrypt_yA = AliceEncryption(xA, yA, pk)          # Alice sends her crypted coords to Bob 
    msg = BobComputing(encrypt_xA, encrypt_yA, xB, yB, pk)        # Bob returns the results of his computing
    
    result = AliceDecryption(msg, xA, yA, pk, sk)
    return("Distance between Alice and Bob : {}".format(float(result)))

#print(BobDistance(10, 10, 21, 13))
#print(BobDistance(1, 1, 1, 1))




##############################################################################

# Implementation of the BobDistance100 protocol : 
# 1. Alice sends [xA], [xA2], [yA] and [yA2] to Bob
# 2. Bob computes dAB2
# 3. Bob creates an array, fills it with ([dAB] + [i]^-1) * r (with i being the index of the array and r a random number between 1 and pk)
# 4. Bob sends the array to Alice
# 5. Alice decrypts each element of the list, if one of them == 0 then Bob is near otherwise he isn't

##############################################################################

def BobComputing100(encrypt_xA, encrypt_yA, encrypt_xA2, encrypt_yA2, xB, yB, pk):
    encrypt_xByB2 = encrypt(pow(xB, 2) + pow(yB, 2), pk)            # Bob computes and encrypts xB^2 + yB^2
    xAxB = constantProduct(encrypt_xA, xB, pk)                      # Bob uses Paillier's homomorphy to encrypt xA * xB
    yAyB = constantProduct(encrypt_yA, yB, pk)                      # and yA * yB
    sumA = oplus(encrypt_xA2, encrypt_yA2, pk)                      # Bob computes xA^2 + yA^2
    middleSum = oplus(xAxB, yAyB, pk)
    powerMinus2 = constantProduct(middleSum, -2, pk)           
    sumB = oplus(powerMinus2, encrypt_xByB2, pk)                    # Bob computes and encrypts -2(xAxB + yAyB)
    finalSum = oplus(sumB, sumA, pk)                                # Bob computes and encrypts the final sum
    return finalSum

def BobDistance100(xA, yA, xB, yB, distance):
    pk, sk = genkeys(128)                                           # Alice generates her keys and shares her public key
    
    encrypt_xA, encrypt_yA = AliceEncryption(xA, yA, pk)            # Bob receives [xA] [yA] [xA2] [yA2] and computes distAB squared
    encrypt_xA2, encrypt_yA2 = AliceEncryption(xA * xA, yA * yA, pk)
    distAB = BobComputing100(encrypt_xA, encrypt_yA, encrypt_xA2, encrypt_yA2, xB, yB, pk)

    shuffledArray = []
    for i in range(distance * distance):      # Bob creates and shuffles the array and sends it to Alice
        r = random.randint(1, pk)
        ic = encrypt(i, pk)
        icNegative = constantProduct(ic, -1, pk)
        dist_ic = oplus(distAB, icNegative, pk)
        shuffledArray.append(constantProduct(dist_ic, r, pk))
    random.shuffle(shuffledArray)
    
    
    for i in shuffledArray:                 # Alice goes through the array and checks for a 0
        if decrypt(i, pk, sk) == 0:
            return "Warning Bob is near !"
    return "Everything's fine Bob's far away !"
              
#print(BobDistance100(10, 10, 80, 80, 100))
#print(BobDistance100(10, 10, 150, 150, 100))




##############################################################################

# Implementation of the BobLocation100 protocol : 
# 1. Alice sends [xA], [x2A] and [xB], [x2B] to Bob
# 2. Bob generates the arrays X = ([(dAB − i)^ri + xB]) for i = 1 -> 10000 and Y = ([(dAB − i)^r′i + yB]) for i = 1 -> 10000 and a random swap σ of {1; 10000}
# 3. He sends σ(X) and σ(Y ) to Alice
# 4. Alice decrypts all encryptions from X and Y 
# 5. If Alice finds |xi| ≤ 100 once, then she returns (xB, yB) = (xi, yi) otherwise she returns dAB > 100

##############################################################################


def DistanceIfUnderN(xA, yA, N):
    pk, sk = genkeys(128)                # Alice generates her keys and shares her public key
    N2 = N * N
    encrypt_xA = encrypt(xA, pk)         # Alice encrypts xA yA xA^2 and yA^2 
    encrypt_xA2 = encrypt(xA * xA, pk) 
    encrypt_yA = encrypt(yA, pk)  
    encrypt_yA2 = encrypt(yA*yA, pk)    
    
    x_table, y_table = BobLocation100(encrypt_xA, encrypt_xA2, encrypt_yA, encrypt_yA2, pk, N2)
    # Alice sends her encryptions to Bob and waits for his tables
    
    xB, yB = -1, -1  # Initialization
    
    for i in range(N2):                     # Alice recovers Bob's tables and goes through them
        xi = decrypt(x_table[i], pk, sk)
        yi = decrypt(y_table[i], pk, sk)
        
        if abs(xi - xA) <= N:               # Alice checks if |xi - xA| <= 100 
            xB = xi
        
        if abs(yi - yA) <= N:               # Alice checks if |yi - yA| <= 100
            yB = yi 
            
        if xB != -1 and yB != -1:           # If she finds a couple that works she immediately returns it
            return(xB, yB) 
    
    return "Everything's fine Bob's far away !"    # Otherwise Bob is too far

def BobLocation100(encrypt_xA, encrypt_xA2, encrypt_yA, encrypt_yA2, pk, N2):
    encrypt_xAxB = constantProduct(encrypt_xA, xBob, pk)                # Bob uses o+ and the constant product
    encrypt_yAyB = constantProduct(encrypt_yA, yBob, pk)
    encrypt_xAxByAyB = oplus(encrypt_xAxB, encrypt_yAyB, pk)            # To compute [-2 * (xA * xB + yA * yB)]
    encrypt_xAxByAyB = constantProduct(encrypt_xAxByAyB, -2, pk)
    
    encrypt_xB = encrypt(xBob, pk)                                      # Bob encrypts his coordinates xB yB xB^2 et yB^2
    encrypt_xB2 = encrypt(xBob * xBob, pk)
    encrypt_yB = encrypt(yBob, pk)                  
    encrypt_yB2 = encrypt(yBob * yBob, pk)
    
    distAB = oplus(encrypt_xAxByAyB, encrypt_xB2, pk)
    distAB2 = oplus(distAB, encrypt_yB2, pk)                            # Bob adds his own encryptions in order to find      
    distAB3 = oplus(distAB2, encrypt_xA2, pk)                           # [xB^2 + yB^2 + xA^2 + yA^2 - 2 * (xA * xB + yA * yB)] = [distAB]
    distAB4 = oplus(distAB3, encrypt_yA2, pk)
    
    x_table, y_table = [], []                                           # Table initialization
    
    for i in range(N2):
        r = random.randint(1, pk)
        protocol = encrypt(i, pk)                                       # For i going from 1 to N^2
        protocol2 = opposite(protocol, pk)
        protocol3 = oplus(protocol2, distAB4, pk)
        protocol4 = constantProduct(protocol3, r, pk)                   # Bob computes and encrypts [(distAB² − 𝑖) ∗ 𝑟 + xB] (or + yB)

        x_table.append(oplus(protocol4, encrypt_xB, pk))                # [𝑥𝑖] = [(distAB² − 𝑖) ∗ 𝑟 + xB]
        y_table.append(oplus(protocol4, encrypt_yB, pk))                # [𝑦𝑖] = [(distAB² − 𝑖) ∗ 𝑟 + yB]

    
    random.shuffle(x_table)                                             # Random shuffle of the tables
    random.shuffle(y_table)
    
    return x_table, y_table

xBob = 10
yBob = 10
#DistanceIfUnderN(15, 15, 50) 
#DistanceIfUnderN(60, 60, 50) 
# n = 50 for fast execution time
#%%