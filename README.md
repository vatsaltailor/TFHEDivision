The following work has been caried out by me as a part of my bacherlor's thesis at Indian Institute of Technology, Kharagpur under the guidance of Prof. Ayantika Chatterjee (https://sites.google.com/view/ayantikachatterjee/home)

# TFHEDivision
Division operation using the non-restoring division algorithm is implemented in the Fully Homomorphic Encrypted domain. 

TFHE library is used to implement the same : https://tfhe.github.io/tfhe/  ; refer the link for installation and compilation of the code

COMPILATION:\n
gcc alice.c -o alice -ltfhe-spqlios-fma\n
gcc cloud.c -o cloud -ltfhe-spqlios-fma\n
gcc verif.c -o verif -ltfhe-spqlios-fma\n

Compile programs in the sequence alice.c - cloud.c - verif.c

In file alice.c , plaintext1 represents the numerator(dividend), plaintext2 represents the denominator(divisor)
