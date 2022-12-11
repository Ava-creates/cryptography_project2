#include <stdio.h>
#include <string>
#include <vector>
#include <stack>
#include <string>
#include <iostream>
#include <fstream>
#include "tfhe.h"
#include "tfhe_io.h"

// using namespace std;

/*
INPUT - encrypted answer + secret key
OUTPUT - int final answer
*/
int16_t decrypt(LweSample* answer, TFheGateBootstrappingSecretKeySet* key) {
    int16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&answer[i], key);
        int_answer |= (ai<<i);
    }
    return int_answer;
}

/*
INPUT - String 
OUTPUT - Array of 16-bit integers, each int represents 1 encoded char
*/
std::vector<int16_t> string_to_bitarray(const std::string& s) {
	int n = s.size();
	std::vector<int16_t> binarystr;
	for (int i = 0; i<n; i++) {
        binarystr.push_back((int16_t)s[i]);
	}
	return binarystr;
}

/*
generate secret & cloud keys with min lambda and put them in appropriate files
*/
void generate_keys(const int minimum_lambda) {
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

}

/*
creates empty ciphertext array using parameters from key
*/
LweSample* init_ciphertext_array(const TFheGateBootstrappingParameterSet* params) {
    LweSample* initCipher = new_gate_bootstrapping_ciphertext_array(16, params);
    return initCipher;
}

/*
INPUT - 16 plaintext bits + ciphertext LweSample to write encrypted data into + secret key
OUTPUT - 16 bits encrypted data as LweSample
*/
LweSample* encrypt16(int16_t plaintext, LweSample* ciphertext, const TFheGateBootstrappingSecretKeySet* key) {
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext[i], (plaintext>>i)&1, key);
    }
    return ciphertext;
}

/*
INPUT - 16 ciphertext bits + parameters from key
Writes encrypted bits to cloud.data file
*/
void export_ciphertext(LweSample* ciphertext, const TFheGateBootstrappingParameterSet* params) {
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<16; i++) {
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[i], params);
    }
    fclose(cloud_data);
}

// it does performs the AND  operations till the result is in a single bit
//input : xnor lwesample array c , cloudkey set - output - one bit lwesample , length of the lwesample array 
LweSample* end ( LweSample* result , const LweSample* c, const TFheGateBootstrappingCloudKeySet* bk)
{

    int l= sizeof(c)/sizeof(c[0]);


    LweSample* resul[ l ]; 
    LweSample* r= new_gate_bootstrapping_ciphertext(bk->params);  //uh not sure how to make it one variable 

    for (int i =0; i<l-1; i+=2)

        {
        
            // # "And" the current bit and the next bit, and add the result
            // # to the resulting string
            bootsAND(r, &c[i], &c[i+1], bk);
            resul[i]=r;
        
        }
        
    while( l>1){
        
        for (int i =0; i<l-1; i+=2)

        {
        
            // # "And" the current bit and the next bit, and add the result
            // # to the resulting string
            bootsAND(r, &c[i], &c[i+1], bk);
            resul[i]=r;
        
        }
        
        l=l/2;
        
    }


    return resul[0];

}

LweSample* compare_strings(const LweSample* a, const LweSample* b, int start, int end ,  const TFheGateBootstrappingCloudKeySet* bk)
{ 
    int len = sizeof(a)/sizeof(a[0]);
    LweSample* t= new_gate_bootstrapping_ciphertext(bk->params);
    bootsCONSTANT(t, 0, bk);
    LweSample* resul[ len ]; 

    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(n, bk->params);   

    // not sure what exactly the above thing gives but hopefully an array of len equal to n 

    for (int i = start ; i< end ; i++)
        {
            bootsXNOR(&tmps[i], &a[i], &b[i], bk); 
            //    # the xnor to check equality   for every bit and storing the result in     tmps  
           
        }

    // LweSample* result = new_gate_bootstrapping_ciphertext_array(n-1, bk->params);   
    return end(result, tmps, bk);

}


int main() {

    /*
    TEST STRING INPUT S & Q
    */
    const std::string s = "This is my test string.";
    const std::string q = "string";

    //generates & stores keys
    const int minimum_lambda = 110;
    generate_keys(minimum_lambda);

    //saves secret key to variable 'key'
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    //saves cloud key to variable 'bk'
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //initializes a LweSample object for each of query string and plaintext, to copy from for each encryption iteration
    const TFheGateBootstrappingParameterSet* params = key->params;
    LweSample* initial_ciphertext = init_ciphertext_array(params);
    LweSample* initial_query = init_ciphertext_array(params);

    //converts plaintext to array of 16-bit integers
    std::vector<int16_t> bitarrayS = string_to_bitarray(s);
    int bufferS = sizeof(bitarrayS);
    //encrypts array one element at a time & stores into cloud.data
    for (int i=0; i<bufferS; i++) {
        export_ciphertext(encrypt16(bitarrayS[i], initial_ciphertext, key), params);
    }

    //converts query string to array of 16-bit integers
    std::vector<int16_t> bitarrayQ = string_to_bitarray(q);
    int bufferQ = sizeof(bitarrayQ);
    //encrypts array one element at a time & stores into query.data
    FILE* query_data = fopen("query.data","wb");
    for (int i=0; i<bufferQ; i++) {
        for (int i=0; i<16; i++) {
        export_gate_bootstrapping_ciphertext_toFile(query_data, encrypt16(bitarrayQ[i], initial_query, key), params);
        }
    }
    fclose(query_data);
    
    /*
    STILL TO INTEGRATE:
        - read encrypted LweSamples from query.data and cloud.data
        - feed LweSamples to comparison algo, receive integer answer
        - make integer output answer into 16 bit fixed width integer
        - encrypt and write into answer.data
    */
	
    //read encrypted LweSamples from query.data and cloud.data
	
   FILE* query = fopen("query.data","rb");
   LweSample* searchword[bufferQ];
   
	
   for (int i=0; i<bufferQ; i++) {   
	searchword[i] = new_gate_bootstrapping_ciphertext_array(16, params);
        for (int j=0; j<16; j++) {
        import_gate_bootstrapping_ciphertext_toFile(query , &searchword[i] , params);
        }
    }
   
   fclose(query);
	
   FILE* cipher = fopen("cloud.data","rb");
   LweSample* ciphertexts[bufferS];  
	
   // import_gate_bootstrapping_ciphertext_fromFile(cipher, ciphertexts ,params);
   
    int len= bufferS*16;
    LweSample* ciphertexts[bufferS]; 
	
    for (int i=0; i<bufferS; i++) {   
	ciphertexts[i] = new_gate_bootstrapping_ciphertext_array(16, params);
        for (int j=0; j<16; j++) {
        import_gate_bootstrapping_ciphertext_toFile(cipher , &ciphertexts[i] , params);
        }
    }
	
    fclose(cipher);
	
	
    //ciphertexts array is an array of lwesamples that are 16 bit long 
    //looping over this array to compare strings
	
    LweSample* result[bufferS- bufferQ];
	
    int count = 0;
	
    LweSample* comp=  new_gate_bootstrapping_ciphertext(params);
	
    bootsCONSTANT(comp , 0, bk);
		
    for ( int i =0; i<(bufferS- bufferQ); i++)
    { 
	    result[i]= compare_strings(  &ciphertexts [i] , &searchword[i] , i , i+ bufferQ  ,  bk);
	    
	    count += result[i];
    
    }    
		    
    LweSample* ans= new_gate_bootstrapping_ciphertext_array(16, params);
    bootsSymEncrypt(ans , count , params);
    
    FILE* answ = fopen("answer.data","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(ans,  key);
    fclose(answ);


    //decrypt answer.data file & save final answer into variable 'final answer'
    LweSample* answer = new_gate_bootstrapping_ciphertext_array(16, params);
    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<16; i++) {
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[i], params);
    }
    fclose(answer_data);
    int final_answer = decrypt(answer, key);
}
