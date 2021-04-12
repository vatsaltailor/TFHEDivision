#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>


int main() {

    //reads the cloud key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 16 ciphertexts of the result
    LweSample* quotient = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* remainder = new_gate_bootstrapping_ciphertext_array(16, params);

    //export the 32 ciphertexts to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<16; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &quotient[i], params);
    for (int i=0; i<16; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &remainder[i], params);   
    fclose(answer_data);

    //decrypt and rebuild the answer
    int16_t int_quotient = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&quotient[i], key)>0;
        int_quotient |= (ai<<i);
        //printf("Quotient: %d\n",ai);
    }
    
    int16_t int_remainder = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&remainder[i], key)>0;
        int_remainder |= (ai<<i);
        //printf("Remainder: %d\n",ai);
    }
    

    printf("Quotient: %d\n",int_quotient);
    printf("Remainder: %d\n",int_remainder);
	

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, quotient);
    delete_gate_bootstrapping_ciphertext_array(16, remainder);
    delete_gate_bootstrapping_secret_keyset(key);

}



