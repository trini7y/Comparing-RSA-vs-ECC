# -*- coding: utf-8 -*-
"""
Created on Mon May 01 07:11:55 2023

@author: Desmond Okeke
"""

import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# A function to simulate the secure transmission of e-voting results


def simulate_E_Voting_System():
    print("Simulation of Secure E-Voting System\n")

    # Generate RSA key pair for secure transmission
    rsaPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=15360,  # Security bit level
        backend=default_backend()
    )
    rsaPublicKey = rsaPrivateKey.public_key()

    # Generate ECC key pair for digital signatures
    eccPrivateKey = ec.generate_private_key(
        ec.SECT571R1(),
        default_backend()
    )
    eccPublicKey = eccPrivateKey.public_key()

    # Generate voting results of 100 votes for simulation
    votingResults = ["Candidate A"] * 40 + \
        ["Candidate B"] * 35 + ["Candidate C"] * 25

    # Encrypt voting results using RSA and measure encryption time
    rsaEncryptionStartTime = time.time()
    rsaEncryptedResults = [rsaPublicKey.encrypt(
        result.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ) for result in votingResults]
    rsaEncryptionEndTime = time.time()
    rsaEncryptionTime = rsaEncryptionEndTime - rsaEncryptionStartTime

    # Decrypt RSA-encrypted voting results and measure decryption time
    rsaDecryptionStartTime = time.time()
    rsa_decrypted_results = [rsaPrivateKey.decrypt(
        result,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode() for result in rsaEncryptedResults]
    rsaDecryptionEndTime = time.time()
    rsaDecryptionTime = rsaDecryptionEndTime - rsaDecryptionStartTime

    # Sign voting results using ECC and measure signature time
    eccSignatureStartTime = time.time()
    eccSignedResults = [eccPrivateKey.sign(
        result.encode(),
        ec.ECDSA(hashes.SHA256())
    ) for result in votingResults]
    eccSignatureEndTime = time.time()
    eccSignatureTime = eccSignatureEndTime - eccSignatureStartTime

    # Verify ECC signatures by using the public key and measure verification time
    eccVerificationStartTime = time.time()
    ecc_verification_results = [eccPublicKey.verify(
        signature,
        result.encode(),
        ec.ECDSA(hashes.SHA256())
    ) for result, signature in zip(voting_results, eccSignedResults)]
    eccVerificationEndTime = time.time()
    eccVerificationTime = eccVerificationEndTime - eccVerificationStartTime

    # Compare key lengths
    rsaKeyLength = rsaPublicKey.key_size
    eccKeyLength = eccPublicKey.curve.key_size
    print("Key Length:")
    print("RSA: {} bits".format(rsaKeyLength))
    print("ECC: {} bits".format(eccKeyLength))

    # Print encryption and decryption times
    print("\nEncryption and Decryption Times:")
    print("RSA Encryption Time: {:.6f} seconds".format(rsaEncryptionTime))
    print("RSA Decryption Time: {:.6f} seconds".format(rsaDecryptionTime))

    # Print signature and verification times
    print("\nSignature and Verification Times:")
    print("ECC Signature Time: {:.6f} seconds".format(eccSignatureTime))
    print("ECC Verification Time: {:.6f} seconds".format(
        eccVerificationTime))

    # Print total time for encryption and decryption
    totalEncryptionTime = rsaEncryptionTime
    totalDecryptionTime = rsaDecryptionTime
    print("\nTotal Time:")
    print("RSA Encryption Total Time: {:.6f} seconds".format(
        totalEncryptionTime))
    print("RSA Decryption Total Time: {:.6f} seconds".format(
        totalDecryptionTime))

    # Print encrypted and decrypted voting results
    print("\nEncrypted Voting Results:")
    print("RSA: {}".format(rsaEncryptedResults))
    print("Decrypted Voting Results:")
    print("RSA: {}".format(rsa_decrypted_results))
    print("ECC Signatures:")
    for result, signature in zip(votingResults, eccSignedResults):
        print("Result: {}, Signature: {}".format(result, signature.hex()))


# Run the e-voting simulation
simulate_E_Voting_System()
