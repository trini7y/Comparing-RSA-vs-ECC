# -*- coding: utf-8 -*-
"""
Created on Thu May 18 15:32:14 2023

@author: desmy
"""

from ecdsa import SigningKey, NIST256p

# Generate ECC key pair
private_key = SigningKey.generate(curve=NIST256p)
public_key = private_key.verifying_key

# Get the public key coordinates
public_key_x = public_key.to_string().hex()[:64]
public_key_y = public_key.to_string().hex()[64:]

# Sign a message using the private key
message = b"Test message!"
signature = private_key.sign(message)

# Verify the signature using the public key
is_valid = public_key.verify(signature, message)

# Print the results
print("ECC Key Pair Generation:")
print("Private Key (hex):", private_key.to_string().hex())
print("Public Key (x, y):", public_key_x, public_key_y)
print()

print("Signing and Verification:")
print("Message:", message)
print("Signature:", signature.hex())
print("Verification Result:", is_valid)
