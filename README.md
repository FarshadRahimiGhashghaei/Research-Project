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
