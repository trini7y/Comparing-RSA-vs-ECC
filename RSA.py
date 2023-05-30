import random

# Check if a number is a prime number 
def isPrime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# A function to help Generates random prime numbers
def generatePrime():
    # Generate a random number
    prime = random.randint(2**8, 2**16)  
    # Check if the generated number is a prime
    while not isPrime(prime):  
        # If it's not prime, generate another random number
        prime = random.randint(2**8, 2**16)  
    return prime

# A function to help calculate the greates common divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# A function to help calculate the modular inverse
def modularInverse(a, m):
    if gcd(a, m) != 1:
        # Checks if modular inverse exist
        return None 
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

# A function to generate rsa keys 
def generate_rsa_keys():
    # Generate a random prime number p
    p = generatePrime()  
    # Generate another random prime number q
    q = generatePrime() 
    # Calculate the modulus n
    n = p * q 
    # Calculate Euler's totient function phi(n)
    phi_n = (p - 1) * (q - 1) 
    # Choose a random number e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    e = random.randint(2, phi_n)  
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n)
    # Calculate the modular inverse of e modulo phi(n)
    d = modularInverse(e, phi_n)  
    # Public key: (e, n), Private key: (d, n)
    return (e, n), (d, n)  

# A function to help encrypt the message 
def encrypt(message, publicKey):
    e, n = publicKey
    ciphertext = [pow(ord(char), e, n) for char in message]
    return ciphertext

# A function to help decrypt the message 
def decrypt(ciphertext, privateKey):
    d, n = privateKey
    message = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return message

# Example usage
message = "This is a test message"
publicKey, privateKey = generate_rsa_keys()
encrypted_message = encrypt(message, publicKey)
decrypted_message = decrypt(encrypted_message, privateKey)

print("Original message:", message)
print("Encrypted message:", encrypted_message)
print("Decrypted message:", decrypted_message)
