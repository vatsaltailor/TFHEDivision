#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#define BLEN 16
#define ROWS 4
#define COLUMNS 3
#define CLASSES 2


//get left shift function

void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp4=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp5=new_gate_bootstrapping_ciphertext_array(1,bk->params);

    bootsXOR(temp1, a, b, bk);  //a xorb
    bootsXOR(result,temp1,lsb_carry,bk);  //a xor b xor ci
    
    bootsNOT(temp4,a,bk);  // complement of a
    bootsAND(temp3,temp4,b,bk); // complement a and b

    bootsNOT(temp5,temp1,bk);  // complement of a XOR b

    bootsAND(temp2,temp5,lsb_carry,bk);// complement of a XOR b AND lasb_carry
  
    bootsOR(tmp,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry,tmp,bk);
}

void subtract(LweSample* result, LweSample* tmps, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    //run the elementary comparator gate n times//
      
    for (int i=0; i<nb_bits; i++){
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
}

void Addition(LweSample* top1, const LweSample* a6, const LweSample* b6, LweSample* lsb_carry1, LweSample* tmp6, const  TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    
    bootsXOR(temp1, a6, b6, bk);  //a xor b  
    bootsXOR(top1,temp1,lsb_carry1,bk);  //a xor b xor ci
    bootsAND(temp2,temp1,lsb_carry1,bk);   //ci and (a xor b)
    bootsAND(temp3,a6,b6,bk);             // a and b 
    bootsOR(tmp6,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry1,tmp6,bk);


}
void Adder(LweSample* top1, const LweSample* a6, const LweSample* b6, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
    LweSample* tmps6 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    bootsCONSTANT(&tmps6[0], 0, bk); //initialize carry to 0

    //run the elementary comparator gate n times//
        
    for (int i=0; i<nb_bits; i++){
        Addition(&top1[i], &a6[i], &b6[i], &tmps6[0], &tmps6[1], bk);
    }
    delete_gate_bootstrapping_ciphertext_array(2, tmps6);    
}

void multiplexer(LweSample* rdbdata,LweSample* a,LweSample* b,LweSample* select_line,const int nb_bit, const TFheGateBootstrappingCloudKeySet* bk){
    int m=0;
    for(int i=0;i<nb_bit;i++){
        bootsMUX(&rdbdata[i],&select_line[m],&b[i],&a[i],bk);
    }
}

void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
        
    LweSample* enc_theta=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    for(int i=0;i<nb_bits;i++){ //initialize theta to all zero bits
        bootsCONSTANT(&enc_theta[i],0,bk);
    }
    for(int i=0;i<2*nb_bits;i++){ //initialize product to all zero bits
        bootsCONSTANT(&product[i],0,bk);
    } 

    for (int i=0; i<nb_bits; i++) {
        LweSample* temp_result=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        LweSample* partial_sum=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        for(int j=0;j<2*nb_bits;j++){ //initialize temp_result to all zero bits
            bootsCONSTANT(&temp_result[j],0,bk);
            bootsCONSTANT(&partial_sum[j],0,bk);
        } 
        LweSample* temp2=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
        multiplexer(temp2,enc_theta,a,&b[i],nb_bits,bk);
        for(int j=0;j<nb_bits;j++){ 
            bootsCOPY(&temp_result[i+j],&temp2[j],bk);
        }

        //Add the valid result to partial_sum//
        Adder(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
            bootsCOPY(&product[j],&partial_sum[j],bk);
        }
    }
}

void is_equal(LweSample* equal, LweSample* a, LweSample* b, const int n_bits, const TFheGateBootstrappingCloudKeySet* bk){
    int i;
    LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    bootsCONSTANT(&equal[0],0,bk);
    bootsCONSTANT(temp2,0,bk);
    for(i=0; i<n_bits; i++){
        bootsXOR(temp1, &a[i], &b[i], bk);
        bootsOR(temp3, temp2, temp1, bk);
        bootsCOPY(temp2, temp3, bk);
        bootsNOT(&equal[0], temp3, bk);
    }
}

//shift left, mutiply by 2 binary , adds zero at the end
void shiftbit(LweSample* result,const int nb_bits,const TFheGateBootstrappingCloudKeySet* bk){
	LweSample*  temp= new_gate_bootstrapping_ciphertext_array(2,bk->params);
	bootsCONSTANT(&temp[0], 0, bk);
  
	for(int i=nb_bits-1;i>0;i--)
	{
		bootsCOPY(&result[i],&result[i-1],bk);
	}
	bootsCOPY(&result[0],temp,bk);

}



void compare_bit_new(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// this function compares two multibit words, and puts the max in result
void maximum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    
    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits; i++) {
        compare_bit_new(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the max and copy it to the result
    for (int i=0; i<nb_bits; i++) {
        bootsMUX(&result[i], &tmps[0], &b[i], &a[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps);    
}

void make_neg(LweSample* result, const LweSample* a, const LweSample* ciphertext_one, const int nb_bits,const TFheGateBootstrappingCloudKeySet* bk)
{
	LweSample* result_temp = new_gate_bootstrapping_ciphertext_array(16, bk->params);
	for (int i=0; i<nb_bits; i++) {
        	bootsNOT(&result_temp[i], &a[i], bk);
	}
	
	Adder(result, result_temp, ciphertext_one, nb_bits, bk);
}

/*void read_neg(LweSample* result, const LweSample* a,const int nb_bits,const TFheGateBootstrappingCloudKeySet* bk)
{
	//pseudo C code
	if(a[nb_bits-1]==1)
	{
		make_neg(result, a,nb_bits,bk);
	}
}*/


void main(){

	

	//reads the cloud key from file
	
	clock_t begin = clock();
	
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
    
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //initialize the 2x16 ciphertexts
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* ciphertext_zero = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* ciphertext_one = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* A = new_gate_bootstrapping_ciphertext_array(16, params);
	
    LweSample* negative_c2 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* mux_result_1 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* mux_result_temp = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* result_min = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* Aminuszero = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* mux1 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* mux2 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* equal_result = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* AplusM = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* tempA = new_gate_bootstrapping_ciphertext_array(16, params);
    /*LweSample* mux_result_2 = new_gate_bootstrapping_ciphertext_array(16, params);*/
    LweSample* result = new_gate_bootstrapping_ciphertext_array(16, params);

    
    //reads the 2x16 ciphertexts from the cloud file
    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext_zero[i], params);
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext_one[i], params);

    fclose(cloud_data);
    //A=0
    for (int i=0; i<16; i++) bootsCOPY(&A[i], &ciphertext_zero[i], bk);
    //getting M*
    make_neg(negative_c2, ciphertext2, ciphertext_one, 16, bk);
    //getting A-0
    
    int cnt = 16;
    
    do
    {
    	
    	subtract(Aminuszero, temp1, A, ciphertext_zero, 16, bk);
    
    	//shift_left(A), such that A[0]= cp1[N-1]
    	shiftbit(A,16,bk);
    	bootsCOPY(&A[0], &ciphertext1[16-1], bk);
    
    	//getting the MSB of Aminuszero, if MSB = 0, A>0 else A<0, so to implement condition A<0
    
    
    
    	for (int i=0; i<16; i++) bootsMUX(&mux1[i], &Aminuszero[16-1] , &ciphertext2[i], &negative_c2[i], bk);
    
    	//additional condition, if A==0, then mux1 will be negative
    	is_equal(equal_result, A, ciphertext_zero, 16, bk);
    
    	for (int i=0; i<16; i++) bootsMUX(&mux1[i], &equal_result[0] , &negative_c2[i], &mux1[i] ,bk);
    
    
    	//A = A +- M
    	Adder(tempA, A, mux1, 16, bk);
    
    	for (int i=0; i<16; i++) bootsCOPY(&A[i], &tempA[i], bk);
    
    
    	//again new condition for A<0
    	subtract(Aminuszero, temp1, A, ciphertext_zero, 16, bk);
    	shiftbit(ciphertext1,16,bk);
    
    	bootsMUX(&ciphertext1[0], &Aminuszero[16-1] , &ciphertext_zero[0], &ciphertext_one[0], bk);
    	cnt --;
    }while(cnt!=0);
    
    //after main loop
    
    subtract(Aminuszero, temp1, A, ciphertext_zero, 16, bk);
    
    Adder(AplusM, A, ciphertext2, 16, bk);
    
    for (int i=0; i<16; i++) bootsMUX(&A[i], &Aminuszero[16-1] , &AplusM[i], &A[i] ,bk);
    
    
 

    
    //export the 32 ciphertexts to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","wb");
    for (int i=0; i<16; i++) export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertext1[i], params);
    for (int i=0; i<16; i++) export_gate_bootstrapping_ciphertext_toFile(answer_data, &A[i], params);
    fclose(answer_data);
    
    //clean up all pointers

    delete_gate_bootstrapping_ciphertext_array(16, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext_zero);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext_one);
    delete_gate_bootstrapping_ciphertext_array(16, A);

    delete_gate_bootstrapping_ciphertext_array(16, negative_c2);
    delete_gate_bootstrapping_ciphertext_array(16, mux_result_1);
    delete_gate_bootstrapping_ciphertext_array(16, mux_result_temp);
    delete_gate_bootstrapping_ciphertext_array(16, result_min);
    delete_gate_bootstrapping_ciphertext_array(16, Aminuszero);
    delete_gate_bootstrapping_ciphertext_array(16, temp1);
    delete_gate_bootstrapping_ciphertext_array(16, mux1);
    delete_gate_bootstrapping_ciphertext_array(16, mux2);
    delete_gate_bootstrapping_ciphertext_array(16, AplusM);
    delete_gate_bootstrapping_ciphertext_array(16, equal_result);
    delete_gate_bootstrapping_ciphertext_array(16, tempA);
    /*delete_gate_bootstrapping_ciphertext_array(16, mux_result_2);*/
    delete_gate_bootstrapping_ciphertext_array(16, result);
    
    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    
    printf("division operator for %d bits took %lf seconds", 16, time_spent);
	


}
