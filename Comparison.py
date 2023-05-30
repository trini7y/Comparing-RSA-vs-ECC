# -*- coding: utf-8 -*-
"""
Created on Mon May 22 18:17:39 2023

@author: desmy
"""

import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Function to measure the execution time of a function
def measure_execution_time(function):
    start_time = time.time()
    function()
    end_time = time.time()
    execution_time = end_time - start_time
    return execution_time

# Function to compare RSA and ECC in terms of key length, computational complexity, and security
def compare_rsa_ecc():
    print("RSA vs ECC Comparison\n")

    # Generate RSA key pair
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    rsa_public_key = rsa_private_key.public_key()

    # Generate ECC key pair
    ecc_private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    ecc_public_key = ecc_private_key.public_key()

    # Compare key lengths
    rsa_key_length = rsa_public_key.key_size
    ecc_key_length = ecc_public_key.curve.key_size
    print("Key Length:")
    print("RSA: {} bits".format(rsa_key_length))
    print("ECC: {} bits".format(ecc_key_length))

    # Compare computational complexity
    rsa_encryption_time = measure_execution_time(lambda: rsa_public_key.encrypt(
        b"message", 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    ecc_encryption_time = measure_execution_time(lambda: ecc_private_key.exchange(ec.ECDH(), ecc_public_key))
    print("\nComputational Complexity (Encryption Time):")
    print("RSA: {:.6f} seconds".format(rsa_encryption_time))
    print("ECC: {:.6f} seconds".format(ecc_encryption_time))

    # Compare security
    rsa_strength = "High" if rsa_key_length >= 2048 else "Low"
    ecc_strength = "High" if ecc_key_length >= 256 else "Low"
    print("\nSecurity Strength:")
    print("RSA: {}".format(rsa_strength))
    print("ECC: {}".format(ecc_strength))

# Run the comparison
compare_rsa_ecc()

