This folder contains experimental verification of correctness for the 13R attack on SLIM.

The **13R_all_keys** files provide information about the key counters during the trial decryptions. 
The target round key that is being guessed is listed in the line ``actual key:`` 
while the guessed key bits with the most hits in the key counter is listed under ``Count of possible right key(s):``. 
Note that only keys that affect active nibbles are being guessed, which makes it an equivalent key for the given round.

In 4 out of 5 of the example runs, the correct round key bits was found to have the highest number of hits. 

The **13R_verification** files provide the results of the linear filtering process which discards wrong pairs after encrypting $2^{30}$ pairs. Only surviving pairs are printed in these files.
