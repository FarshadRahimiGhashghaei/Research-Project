# Research Project: Post-Quantum Cryptography for Quantum Key Distribution

This repository hosts the code and materials for our research project, focusing on Post-Quantum Cryptography (PQC) for Quantum Key Distribution (QKD). 

## Overview

Within the core `main.py` file, Three PQC algorithms, Kyber for key encapsulation, Dilithium and Falcon for authentication, have been combined with QKD BB84 quantum simulation. This integration improves code structure and makes it easier to compare these algorithms' assessments across our cryptosystem.

### Components:

- `Kyber.py`: Contains the implementation of the Kyber algorithm, offering functionalities for key encapsulation following the CRYSTALS-Kyber scheme.

- `Dilithium.py`: Hosts the implementation specific to the Dilithium algorithm, managing digital signatures according to the CRYSTALS-Dilithium scheme.

- `Falcon.py`: Houses the code for the Falcon algorithm, which handles digital signatures in alignment with the Falcon scheme.

To implement PQC algorithms, we rely on external libraries sourced from the following open-source projects:

- [GiacomoPope/kyber-py](https://github.com/GiacomoPope/kyber-py)
- [GiacomoPope/dilithium-py](https://github.com/GiacomoPope/dilithium-py)
- [tprest/falcon.py](https://github.com/tprest/falcon.py)


# Results

## Key Generation Times (ms)

This table presents the key generation times (in milliseconds) for different security levels of the PQC algorithms.


| Security Level | Key Generation (ms) |
|----------------|----------------------|
| Kyber512       | 31.2                 |
| Kyber768       | 78.1                 |
| Kyber1024      | 93.72                |
| Dilithium2     | 62.42                |
| Dilithium3     | 93.73                |
| Dilithium5     | 171.87               |
| Falcon256      | 6606.39              |
| Falcon512      | 10016.76             |
| Falcon1024     | 53601.41             |

## Encapsulation and Signing, Decapsulation and Verification Times

This table showcases the encapsulation, signing, decapsulation, and verification times (in milliseconds) for various combinations of PQC algorithms.

| Cipher Combination          | Encapsulation and Signing (ms) | Decapsulation and Verification (ms) |
|-----------------------------|--------------------------------|-------------------------------------|
| Kyber 512 and Falcon 256    | 78.13                          | 78.44                               |
| Kyber 768 and Falcon 256    | 93.72                          | 124.97                              |
| Kyber 1024 and Falcon 256   | 124.97                         | 140.92                              |
| Kyber 512 and Falcon 512    | 124.97                         | 78.07                               |
| Kyber 768 and Falcon 512    | 124.94                         | 140.52                              |
| Kyber 1024 and Falcon 512   | 156.21                         | 156.21                              |
| Kyber 512 and Falcon 1024   | 187.45                         | 109.68                              |
| Kyber 768 and Falcon 1024   | 203.11                         | 156.23                              |
| Kyber 1024 and Falcon 1024  | 250.19                         | 171.86                              |
| Kyber 512 and Dilithium 2   | 187.45                         | 140.52                              |
| Kyber 768 and Dilithium 2   | 422.1                          | 171.84                              |
| Kyber 1024 and Dilithium 2  | 437.77                         | 203.48                              |
| Kyber 512 and Dilithium 3   | 359.29                         | 171.83                              |
| Kyber 768 and Dilithium 3   | 593.94                         | 203.07                              |
| Kyber 1024 and Dilithium 3  | 453.01                         | 234.37                              |
| Kyber 512 and Dilithium 5   | 656.02                         | 249.94                              |
| Kyber 768 and Dilithium 5   | 718.61                         | 296.77                              |
| Kyber 1024 and Dilithium 5  | 1000.07                        | 312.75                              |

## Cipher and Signature Sizes

These tables present the sizes (in bytes) of the ciphertexts and signatures for different PQC algorithms.

### Cipher Sizes

| Cipher    | Cipher Size (bytes) |
|-----------|----------------------|
| Kyber 512 | 768                  |
| Kyber 768 | 1088                 |
| Kyber 1024| 1568                 |

### Signature Sizes for Falcon Algorithm

| Falcon    | Signature Size (bytes) |
|-----------|-------------------------|
| Falcon 256| 356                     |
| Falcon 512| 666                     |
| Falcon 1024| 1280                   |

### Signature Sizes for Dilithium Algorithm

| Dilithium | Signature Size (bytes) |
|-----------|-------------------------|
| Dilithium 2 | 2420                  |
| Dilithium 3 | 3293                  |
| Dilithium 5 | 4595                  |

