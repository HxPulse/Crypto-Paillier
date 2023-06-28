# Crypto-Paillier
Python implementation of the Paillier cryptosystem.
Each function has a commented explanation for better understanding.

# What's Paillier cryptosystem

I'm not gonna copy paste what's written on Wikipedia so I might aswell paste the link here : https://en.wikipedia.org/wiki/Paillier_cryptosystem

# Repository theme

We are in a orthonormal datum using cartesian coordinates
We want to implement a system where two individuals (Alice and Bob) can know the distance separating each other.
We want to introduce cryptography as a way to make sure each individual only knows their own coordinates, we will be using the Paillier cryptosystem in that regard.

Each character knows their coords (xA, yA) and (xB, yB) ∈ Z2. 

At first, Alice generates a set of keys (pk, sk) ←− Paillier.KeyGen(λ) and Bob knows pk. 
Let's give a way for  Alice to know the distance dAB = sqrt((xB - xA)^2 + (yB - yA)^2) 

The protocol used are detailed in the given python file.
