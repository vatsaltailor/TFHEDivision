Two words: SECURE COMPUTATION ; We have all heard of Secure Storage using encryption, but did you know you always have to decrypt your data right before computation? Fully Homomorphic Encryption (https://crypto.stanford.edu/craig/craig-thesis.pdf) allows one to perform operations directly on encrypted data. While addition, subtraction and multiplication have already been implemented, division was not. This work implements and allows users to divide in Fully Homomorphic Encyrption domain, thus completing the full tool stack of operations (+  -  *  / ) making it possible for you to implement and perform any operations you can imagine!


The following work has been caried out by me as a part of my bacherlor's thesis at Indian Institute of Technology, Kharagpur under the guidance of Prof. Ayantika Chatterjee (https://sites.google.com/view/ayantikachatterjee/home)

# TFHEDivision
Division operation using the non-restoring division algorithm is implemented in the Fully Homomorphic Encrypted domain. 

TFHE library is used to implement the same : https://tfhe.github.io/tfhe/  ; refer the link for installation and compilation of the code

COMPILATION:

gcc alice.c -o alice -ltfhe-spqlios-fma

gcc cloud.c -o cloud -ltfhe-spqlios-fma

gcc verif.c -o verif -ltfhe-spqlios-fma


Compile programs in the sequence alice.c - cloud.c - verif.c

In file alice.c , plaintext1 represents the numerator(dividend), plaintext2 represents the denominator(divisor)
