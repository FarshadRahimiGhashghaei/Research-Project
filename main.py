# Import required modules
from qiskit import QuantumCircuit, Aer
from numpy.random import randint
import numpy as np
from Crypto.Cipher import AES
from Kyber.kyber import Kyber1024, Kyber768, Kyber512
from dilithium.dilithium import Dilithium2, Dilithium3, Dilithium5
from falcon import falcon
import time


# Function to encrypt data using AES
def aes_encrypt(aes_message):
    # Create AES cipher in EAX mode
    cipher = AES.new(aes_key, AES.MODE_GCM)
    # Get the randomly generated nonce
    nonce = cipher.nonce
    # Encrypt and get the authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(aes_message.encode('ascii'))
    return nonce, ciphertext, tag

# Function to decrypt data using AES
def aes_decrypt(nonce, chipertext, tag):
    # Create AES cipher in EAX mode with the provided nonce
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt(chipertext)
    try:
        # Verify the authentication tag
        cipher.verify(tag)
        # Return the decrypted plaintext
        return plaintext.decode('ascii')
    except:
        # Return False if authentication fails
        return False

def encode_message(bits, bases):
    message = []
    for i in range(n):
        qc = QuantumCircuit(1, 1)
        if bases[i] == 0: # Prepare qubit in Z-basis
            if bits[i] == 0:
                pass
            else:
                qc.x(0)
        else: # Prepare qubit in X-basis
            if bits[i] == 0:
                qc.h(0)
            else:
                qc.x(0)
                qc.h(0)
        message.append(qc)
    return message

def measure_message(message, bases):
    backend = Aer.get_backend('aer_simulator')
    measurements = []
    for q in range(n):
        if bases[q] == 0: 
            # measuring in Z-basis
            message[q].measure(0, 0)
        if bases[q] == 1: 
            # measuring in X-basis
            message[q].h(0)
            message[q].measure(0, 0)
        aer_sim = Aer.get_backend('aer_simulator')
        result = aer_sim.run(message[q], shots=1, memory=True).result()
        measured_bit = int(result.get_memory()[0])
        measurements.append(measured_bit)
    return measurements


def remove_garbage(a_bases, b_bases, bits):
    good_bits = []
    for q in range(n):
        if a_bases[q] == b_bases[q]:
            # If both used the same basis, add
            # this to the list of 'good' bits
            good_bits.append(bits[q])
    return good_bits


def sample_bits(bits, selection):
    sample = []
    bits_copy = list(bits)  # Create a copy of the original list

    for i in selection:
        i = np.mod(i, len(bits_copy))
        sample.append(bits_copy[i])
    return sample

# Step 0
print("========================================Step 0========================================")
# Amount of Qubits
n = int(input("How many qubits?"))
print("")

np.random.seed(seed=0)
# Step 1
# Alice generates bits
alice_bits = randint(2, size=n)

# Step 2
# Create an array to tell us which qubits
# are encoded in which bases
alice_bases = randint(2, size=n)
message = encode_message(alice_bits, alice_bases)

# Step 3
# Decide which basis to measure in:
bob_bases = randint(2, size=n)
bob_results = measure_message(message, bob_bases)

# Step 4
print("========================================Step 4========================================")
# Alice generate the public and secret key using the keygen() function
while True:
    User_Kyber_Choice = input("Which level you choose(Kyber512/Kyber768/Kyber1024)? ")

    if User_Kyber_Choice == "Kyber512":
        Alice_Kyber_pk, Alice_Kyber_sk = Kyber512.keygen()
        print("Keys generated for Kyber512")
        start_time = time.time()
        Kyber_keygen = Kyber512.keygen()
        key_generation_time = (time.time() - start_time) * 1000
        print(key_generation_time)
        break  # Exit the loop after generating keys


    elif User_Kyber_Choice == "Kyber768":
        Alice_Kyber_pk, Alice_Kyber_sk = Kyber768.keygen()
        print("Keys generated for Kyber768")
        start_time = time.time()
        Kyber_keygen = Kyber768.keygen()
        key_generation_time = (time.time() - start_time) * 1000
        print(key_generation_time)
        break  # Exit the loop after generating keys

    elif User_Kyber_Choice == "Kyber1024":
        Alice_Kyber_pk, Alice_Kyber_sk = Kyber1024.keygen()
        print("Keys generated for Kyber1024")
        start_time = time.time()
        Kyber_keygen = Kyber1024.keygen()
        key_generation_time = (time.time() - start_time) * 1000
        print(key_generation_time)
        break  # Exit the loop after generating keys

    else:
        print("You chose a wrong level! Please choose again.")

while True:
    User_Digital_Signature_Choice = input("Which digital signature you choose(Dilithium/Falcon)? ")

    if User_Digital_Signature_Choice == "Dilithium":
        pass
        while True:
            User_Dilithium_Choice = input("Which level you choose(Dilithium2/Dilithium3/Dilithium5)? ")

            if User_Dilithium_Choice == "Dilithium2":
                dilithium2_pk, dilithium2_sk = Dilithium2.keygen()
                print("Keys generated for Dilithium2")
                start_time = time.time()
                Dilithium2_keygen = Dilithium2.keygen()
                Dilithium2_key_generation_time = (time.time() - start_time) * 1000
                print(Dilithium2_key_generation_time)
                break

            elif User_Dilithium_Choice == "Dilithium3":
                dilithium3_pk, dilithium3_sk = Dilithium3.keygen()
                print("Keys generated for Dilithium3")
                start_time = time.time()
                Dilithium3_keygen = Dilithium3.keygen()
                Dilithium3_key_generation_time = (time.time() - start_time) * 1000
                print(Dilithium3_key_generation_time)
                break

            elif User_Dilithium_Choice == "Dilithium5":
                dilithium5_pk, dilithium5_sk = Dilithium5.keygen()
                print("Keys generated for Dilithium5")
                start_time = time.time()
                Dilithium5_keygen = Dilithium5.keygen()
                Dilithium5_key_generation_time = (time.time() - start_time) * 1000
                print(Dilithium5_key_generation_time)
                break
            else:
                print("You chose a wrong level! Please choose again.")
        break

    elif User_Digital_Signature_Choice == "Falcon":
        pass
        while True:
            User_Falcon_Choice = input("Which level you choose(falcon256/falcon512/falcon1024)? ")
            if User_Falcon_Choice == "falcon256":

                print("Keys generated for falcon256")
                start_time = time.time()
                falcon256_sk = falcon.SecretKey(256)
                falcon256_pk = falcon.PublicKey(falcon256_sk)
                falcon256_key_generation_time = (time.time() - start_time) * 1000
                print(falcon256_key_generation_time)
                break

            elif User_Falcon_Choice == "falcon512":
                print("Keys generated for falcon512")
                start_time = time.time()
                falcon512_sk = falcon.SecretKey(512)
                falcon512_pk = falcon.PublicKey(falcon512_sk)
                falcon512_key_generation_time = (time.time() - start_time) * 1000
                print(falcon512_key_generation_time)
                break

            elif User_Falcon_Choice == "falcon1024":
                print("Keys generated for falcon1024")
                start_time = time.time()
                falcon1024_sk = falcon.SecretKey(1024)
                falcon1024_pk = falcon.PublicKey(falcon1024_sk)
                falcon1024_key_generation_time = (time.time() - start_time) * 1000
                print(falcon1024_key_generation_time)
                break
            else:
                print("You chose a wrong level! Please choose again.")
        break
    else:
        print("You chose a wrong digital signature! Please choose again.")


# Step 5
print("========================================Step 5========================================")
# Bob encrypt a message (here represented by 'c') using Alice public key 'pk'
# and store the result in 'Bob_KEM_Key'
if User_Kyber_Choice == "Kyber512":
    if User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon256":
        c, Bob_KEM_Key = Kyber512.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Falcon256 signed")
        enc_start_time = time.time()
        sig = falcon256_sk.sign(c)
        Kyber_enc = Kyber512.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon512":
        c, Bob_KEM_Key = Kyber512.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Falcon512 signed")
        enc_start_time = time.time()
        sig = falcon512_sk.sign(c)
        Kyber_enc = Kyber512.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon1024":
        c, Bob_KEM_Key = Kyber512.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Falcon1024 signed")
        enc_start_time = time.time()
        sig = falcon1024_sk.sign(c)
        Kyber_enc = Kyber512.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium2":
        c, Bob_KEM_Key = Kyber512.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Dilithium2 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium2.sign(dilithium2_sk, msg)
        Kyber_enc = Kyber512.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium3":
        c, Bob_KEM_Key = Kyber512.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Dilithium3 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium3.sign(dilithium3_sk, msg)
        Kyber_enc = Kyber512.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium5":
        c, Bob_KEM_Key = Kyber512.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Dilithium5 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium5.sign(dilithium5_sk, msg)
        Kyber_enc = Kyber512.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    else:
        print("ERROR!")


elif User_Kyber_Choice == "Kyber768":
    if User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon256":
        c, Bob_KEM_Key = Kyber768.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Falcon256 signed")
        enc_start_time = time.time()
        sig = falcon256_sk.sign(c)
        Kyber_enc = Kyber768.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon512":
        c, Bob_KEM_Key = Kyber768.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Falcon512 signed")
        enc_start_time = time.time()
        sig = falcon512_sk.sign(c)
        Kyber_enc = Kyber768.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon1024":
        c, Bob_KEM_Key = Kyber768.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Falcon1024 signed")
        enc_start_time = time.time()
        sig = falcon1024_sk.sign(c)
        Kyber_enc = Kyber768.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium2":
        c, Bob_KEM_Key = Kyber768.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Dilithium2 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium2.sign(dilithium2_sk, msg)
        Kyber_enc = Kyber768.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium3":
        c, Bob_KEM_Key = Kyber768.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Dilithium3 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium3.sign(dilithium3_sk, msg)
        Kyber_enc = Kyber768.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium5":
        c, Bob_KEM_Key = Kyber768.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber512")
        print("Dilithium5 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium5.sign(dilithium5_sk, msg)
        Kyber_enc = Kyber768.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)

    else:
        print("ERROR!")

elif User_Kyber_Choice == "Kyber1024":
    if User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon256":
        c, Bob_KEM_Key = Kyber1024.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber1024")
        print("Falcon256 signed")
        enc_start_time = time.time()
        sig = falcon256_sk.sign(c)
        Kyber_enc = Kyber1024.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon512":
        c, Bob_KEM_Key = Kyber1024.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber1024")
        print("Falcon512 signed")
        enc_start_time = time.time()
        sig = falcon512_sk.sign(c)
        Kyber_enc = Kyber1024.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon1024":
        c, Bob_KEM_Key = Kyber1024.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber1024")
        print("Falcon1024 signed")
        enc_start_time = time.time()
        sig = falcon1024_sk.sign(c)
        Kyber_enc = Kyber1024.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium2":
        c, Bob_KEM_Key = Kyber1024.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber1024")
        print("Dilithium2 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium2.sign(dilithium2_sk, msg)
        Kyber_enc = Kyber1024.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium3":
        c, Bob_KEM_Key = Kyber1024.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber1024")
        print("Dilithium3 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium3.sign(dilithium3_sk, msg)
        Kyber_enc = Kyber1024.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium5":
        c, Bob_KEM_Key = Kyber1024.enc(Alice_Kyber_pk)
        print("Encapsulation by Kyber1024")
        print("Dilithium5 signed")
        enc_start_time = time.time()
        msg = c
        sig = Dilithium5.sign(dilithium5_sk, msg)
        Kyber_enc = Kyber1024.enc(Alice_Kyber_pk)
        key_enc_time = (time.time() - enc_start_time) * 1000
        print(key_enc_time)

    else:
        print("Digital Signature ERROR!")
else:
    print("Kyber ERROR!")
# Step 6
print("========================================Step 6========================================")
# Alice decrypt the encrypted message 'c' using her secret key 'sk'
# and store the result in 'Alice_KEM_Key'
if User_Kyber_Choice == "Kyber512":
    if User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon256":
        Alice_KEM_Key = Kyber512.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber512")
        print("Falcon256 verified")
        dec_start_time = time.time()
        falcon256_pk.verify(c, sig)
        Kyber_dec = Kyber512.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon512":
        Alice_KEM_Key = Kyber512.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber768")
        print("Falcon512 verified")
        dec_start_time = time.time()
        falcon512_pk.verify(c, sig)
        Kyber_dec = Kyber512.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon1024":
        Alice_KEM_Key = Kyber512.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Falcon1024 verified")
        dec_start_time = time.time()
        falcon1024_pk.verify(c, sig)
        Kyber_dec = Kyber512.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium2":
        Alice_KEM_Key = Kyber512.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium2 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium2.verify(dilithium2_pk, msg, sig)
        Kyber_dec = Kyber512.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium3":
        Alice_KEM_Key = Kyber512.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium3 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium3.verify(dilithium3_pk, msg, sig)
        Kyber_dec = Kyber512.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium5":
        Alice_KEM_Key = Kyber512.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium5 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium5.verify(dilithium5_pk, msg, sig)
        Kyber_dec = Kyber512.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    else:
        print("Digital Signature ERROR!")

elif User_Kyber_Choice == "Kyber768":
    if User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon256":
        Alice_KEM_Key = Kyber768.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber512")
        print("Falcon256 verified")
        dec_start_time = time.time()
        falcon256_pk.verify(c, sig)
        Kyber_dec = Kyber768.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon512":
        Alice_KEM_Key = Kyber768.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber768")
        print("Falcon512 verified")
        dec_start_time = time.time()
        falcon512_pk.verify(c, sig)
        Kyber_dec = Kyber768.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon1024":
        Alice_KEM_Key = Kyber768.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Falcon1024 verified")
        dec_start_time = time.time()
        falcon1024_pk.verify(c, sig)
        Kyber_dec = Kyber768.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium2":
        Alice_KEM_Key = Kyber768.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium2 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium2.verify(dilithium2_pk, msg, sig)
        Kyber_dec = Kyber768.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium3":
        Alice_KEM_Key = Kyber768.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium3 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium3.verify(dilithium3_pk, msg, sig)
        Kyber_dec = Kyber768.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium5":
        Alice_KEM_Key = Kyber768.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium5 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium5.verify(dilithium5_pk, msg, sig)
        Kyber_dec = Kyber768.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    else:
        print("Digital Signature ERROR!")

elif User_Kyber_Choice == "Kyber1024":
    if User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon256":
        Alice_KEM_Key = Kyber1024.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber512")
        print("Falcon256 verified")
        dec_start_time = time.time()
        falcon256_pk.verify(c, sig)
        Kyber_dec = Kyber1024.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon512":
        Alice_KEM_Key = Kyber1024.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber768")
        print("Falcon512 verified")
        dec_start_time = time.time()
        falcon512_pk.verify(c, sig)
        Kyber_dec = Kyber1024.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Falcon" and User_Falcon_Choice == "falcon1024":
        Alice_KEM_Key = Kyber1024.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Falcon1024 verified")
        dec_start_time = time.time()
        falcon1024_pk.verify(c, sig)
        Kyber_dec = Kyber1024.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium2":
        Alice_KEM_Key = Kyber1024.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium2 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium2.verify(dilithium2_pk, msg, sig)
        Kyber_dec = Kyber1024.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium3":
        Alice_KEM_Key = Kyber1024.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium3 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium3.verify(dilithium3_pk, msg, sig)
        Kyber_dec = Kyber1024.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    elif User_Digital_Signature_Choice == "Dilithium" and User_Dilithium_Choice == "Dilithium5":
        Alice_KEM_Key = Kyber1024.dec(c, Alice_Kyber_sk)
        print("Decapsulation by Kyber1024")
        print("Dilithium5 verified")
        dec_start_time = time.time()
        msg = c
        Dilithium5.verify(dilithium5_pk, msg, sig)
        Kyber_dec = Kyber1024.dec(c, Alice_Kyber_sk)
        key_dec_time = (time.time() - dec_start_time) * 1000
        print(key_dec_time)
    else:
        print("Digital Signature ERROR!")

else:
    print("Kyber ERROR!")

# Step 7
print("========================================Step 7========================================")
# If the key from Kyber algorithm has successfully shared, use it for AES key
if Alice_KEM_Key == Bob_KEM_Key:
    aes_key = Alice_KEM_Key or Bob_KEM_Key
    print("Alice_KEM_Key == Bob_KEM_Key")

else:
    print("Alice_KEM_Key is not the same as Bob_KEM_Key")

# Step 8
# Bob encrypt the results and send them to Alice using classic channel
nonce, ciphertext, tag = aes_encrypt(str(bob_bases))

# Step 9
print("========================================Step 9========================================")
# Alice decrypt the ciphertext and print the result
plaintext = aes_decrypt(nonce, ciphertext, tag)
print("Bob ciphertext:", ciphertext)
print(plaintext)
print(bob_bases)
# Step 10
alice_key = remove_garbage(alice_bases, bob_bases, alice_bits)
bob_key = remove_garbage(alice_bases, bob_bases, bob_results)

# Step 11
# 20% of
sample_size = int(n * 0.2)
bit_selection = randint(n, size=sample_size)

bob_sample = sample_bits(bob_key, bit_selection)
print("bob_sample = " + str(bob_sample))
alice_sample = sample_bits(alice_key, bit_selection)
print("alice_sample = " + str(alice_sample))

# Step 12
print("========================================Step 12========================================")
if bob_sample == alice_sample:
    print("=====================================================================")
    print("The Shared Key Has Successfully Generated")
    print("=====================================================================")
    print(bob_key)
    print(alice_key)
    print("key length = %i" % len(alice_key))
