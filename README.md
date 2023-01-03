# Differential Cryptanalysis of Lightweight Block Ciphers 
This repository contains supplementary codes and SMT models for ciphers: 
- SLIM
- LCB
- LCB-IoT
- SCENERY

### Summary
- ./SLIM-cryptosmt: folder contains scripts used in cryptoSMT tool for SLIM differential attack
  - slim.py: SLIM structure modelling in SMT model
  - slim32.yaml: inputs file for running the model

- ./slim-key-recovery-verification: folder contains scripts used for key recovery attack
  - slim.cpp: SLIM encryption and decryption 
  - slim-key.cpp: SLIM key scheduling and master keys randomization algorithm
  - slim-ddt.cpp: generate SLIM Differential Distribution Table 
  - attack.cpp: SLIM key recovery attack
### How to run the program
The script is cater for 13-round key recovery attack. Following are steps to run the script:
1. cmake CMakeLists.txt
2. make all
3. ./slim_cipher
Caution: This execution time of this script is around 1 hour.

- ./LCB-cryptosmt: folder contains scripts used in cryptoSMT tool for LCB differential attack
  - lcb.py: LCB structure modelling in SMT model





