# Differential Cryptanalysis of Lightweight Block Ciphers 
This repository contains supplementary codes and SMT models for ciphers: 
- SLIM
- LCB
- LBC-IoT
- SCENERY

### Summary
- ./SLIM-cryptosmt: folder contains scripts used in cryptoSMT tool for SLIM differential attack
  - slim.py: SLIM SMT model
  - slim32.yaml: inputs file for running the model

- ./slim-key-recovery-verification: folder contains scripts used for key recovery attack
  - slim.cpp: SLIM encryption and decryption
  - slim-key.cpp: SLIM key scheduling and master keys randomization algorithm
  - slim-ddt.cpp: generate SLIM Differential Distribution Table 
  - attack.cpp: SLIM key recovery attack

- ./LCB-cryptosmt: folder contains scripts used in cryptoSMT tool for LCB differential attack
  - lcb.py: LCB SMT model

- ./SCENERY: folder contains scripts used for SCENERY differential attack
  - scenery.py: SCENERY SMT model
  - scenery_cipher.py: SCENERY encryption
